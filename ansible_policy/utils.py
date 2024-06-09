import os
import re
import base64
import json
import yaml
import Levenshtein
import tarfile
import zipfile
import tempfile
import logging
import subprocess


default_target_type = "task"


def init_logger(name: str, level: str):
    log_level_map = {
        "error": logging.ERROR,
        "warning": logging.WARNING,
        "info": logging.INFO,
        "debug": logging.DEBUG,
    }

    level_val = log_level_map.get(level.lower(), None)
    logging.basicConfig(level=level_val)
    logger = logging.getLogger()
    return logger


logger = init_logger(__name__, os.getenv("ANSIBLE_GK_LOG_LEVEL", "info"))


def validate_opa_installation(executable_name: str = "opa"):
    proc = subprocess.run(
        f"which {executable_name}",
        shell=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.stdout and proc.returncode == 0:
        return
    else:
        raise ValueError("`opa` command is required to evaluate OPA policies")


def load_galaxy_data(fpath: str):
    data = {}
    with open(fpath, "r") as file:
        data = json.load(file)
    if not data:
        raise ValueError("loaded galaxy data is empty")

    return data.get("galaxy", {})


def eval_opa_policy(rego_path: str, input_data: str, external_data_path: str, executable_name: str = "opa"):
    rego_pkg_name = get_rego_main_package_name(rego_path=rego_path)
    if not rego_pkg_name:
        raise ValueError("`package` must be defined in the rego policy file")

    util_rego_path = os.path.join(os.path.dirname(__file__), "rego/utils.rego")
    external_data_option = ""
    if external_data_path:
        external_data_option = f"--data {external_data_path}"
    cmd_str = f"{executable_name} eval --data {util_rego_path} --data {rego_path} {external_data_option} --stdin-input 'data.{rego_pkg_name}'"
    proc = subprocess.run(
        cmd_str,
        shell=True,
        input=input_data,
        # stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    logger.debug(f"command: {cmd_str}")
    logger.debug(f"proc.input_data: {input_data}")
    logger.debug(f"proc.stdout: {proc.stdout}")
    logger.debug(f"proc.stderr: {proc.stderr}")

    if proc.returncode != 0:
        error = f"failed to run `opa eval` command; error details:\nSTDOUT: {proc.stdout}\nSTDERR: {proc.stderr}"
        raise ValueError(error)

    result = json.loads(proc.stdout)
    if "result" not in result:
        raise ValueError(f"`result` field does not exist in the output from `opa eval` command; raw output: {proc.stdout}")

    result_arr = result["result"]
    if not result_arr:
        raise ValueError(f"`result` field in the output from `opa eval` command has no contents; raw output: {proc.stdout}")

    first_result = result_arr[0]
    if not first_result and "expressions" not in first_result:
        raise ValueError(f"`expressions` field does not exist in the first result of output from `opa eval` command; first_result: {first_result}")

    expressions = first_result["expressions"]
    if not expressions:
        raise ValueError(f"`expressions` field in the output from `opa eval` command has no contents; first_result: {first_result}")

    expression = expressions[0]
    result_value = expression.get("value", {})
    eval_result = {
        "value": result_value,
        "message": proc.stderr,
    }
    return eval_result


def get_module_name_from_task(task):
    module_name = ""
    if task.module_info and isinstance(task.module_info, dict):
        module_name = task.module_info.get("fqcn", "")
    if task.annotations:
        if not module_name:
            module_name = task.get_annotation("module.correct_fqcn", "")
        if not module_name:
            module_name = task.get_annotation("correct_fqcn", "")

    if not module_name:
        module_name = task.module

    module_short_name = module_name
    if "." in module_short_name:
        module_short_name = module_short_name.split(".")[-1]

    return module_name, module_short_name


def embed_module_info_with_galaxy(task, galaxy):
    if not task.module:
        return

    if not galaxy:
        return

    mappings = galaxy.get("module_name_mappings", {})

    module_fqcn = ""
    if "." in task.module:
        module_fqcn = task.module
    else:
        found = mappings.get(task.module, [])
        if found and found[0] and "." in found[0]:
            module_fqcn = found[0]
            task.module_fqcn = module_fqcn
    if not task.module_info and module_fqcn and "." in module_fqcn:
        collection_name = ".".join(module_fqcn.split(".")[:2])
        short_name = ".".join(module_fqcn.split(".")[2:])
        task.module_info = {
            "collection": collection_name,
            "fqcn": module_fqcn,
            "key": "__unknown__",
            "short_name": short_name,
        }
    return


def get_rego_main_package_name(rego_path: str):
    pkg_name = ""
    with open(rego_path, "r") as file:
        prefix = "package "
        for line in file:
            _line = line.strip()
            if _line.startswith(prefix):
                pkg_name = _line[len(prefix) :]
                break
    return pkg_name


def uncompress_file(fpath: str):
    if fpath.endswith(".tar.gz"):
        tar = tarfile.open(fpath, "r:gz")
        tar.extractall()
        tar.close()
    return


def prepare_project_dir_from_runner_jobdata(jobdata: str, workdir: str):
    if not isinstance(jobdata, str):
        return None
    lines = jobdata.splitlines()
    if not lines:
        return None
    # remove empty line
    lines = [line for line in lines if line]

    base64_zip_body = lines[-1].replace('{"eof": true}', "")
    zip_bytes = decode_base64_string(base64_zip_body)
    file = tempfile.NamedTemporaryFile(dir=workdir, delete=False, suffix=".zip")
    filepath = file.name
    with open(filepath, "wb") as file:
        file.write(zip_bytes)
    with zipfile.ZipFile(filepath) as zfile:
        zfile.extractall(path=workdir)

    return


def decode_base64_string(encoded: str) -> bytes:
    decoded_bytes = base64.b64decode(encoded.encode())
    # decoded bytes may contain some chars that cannot be converted into text string
    # so we just return the bytes data here
    return decoded_bytes


ExternalDataTypeGalaxy = "galaxy"
ExternalDataTypeAutomation = "automation"
supported_external_data_types = [ExternalDataTypeGalaxy, ExternalDataTypeAutomation]


def load_external_data(ftype: str = "", fpath: str = ""):
    if ftype not in supported_external_data_types:
        raise ValueError(f"`{ftype}` is not supported as external data")

    if fpath.endswith(".tar.gz"):
        new_fpath = fpath[:-7]
        if not os.path.exists(new_fpath):
            uncompress_file(fpath)
        fpath = new_fpath

    ext_data = None
    if ftype == ExternalDataTypeGalaxy:
        ext_data = load_galaxy_data(fpath=fpath)
    else:
        raise NotImplementedError
    return ext_data


def match_str_expression(pattern: str, text: str):
    if not pattern:
        return True

    if pattern == "*":
        return True

    if "*" in pattern:
        pattern = pattern.replace("*", ".*")
        return re.match(pattern, text)

    return pattern == text


def detect_target_module_pattern(policy_path: str):
    var_name = "__target_module__"
    pattern = None
    with open(policy_path, "r") as file:
        for line in file:
            if var_name in line:
                parts = [p.strip() for p in line.split("=")]
                if len(parts) != 2:
                    continue
                if parts[0] == var_name:
                    pattern = parts[1].strip('"').strip("'")
                    break
    return pattern


def detect_target_type_pattern(policy_path: str):
    var_name = "__target__"
    pattern = None
    with open(policy_path, "r") as file:
        for line in file:
            if var_name in line:
                parts = [p.strip() for p in line.split("=")]
                if len(parts) != 2:
                    continue
                if parts[0] == var_name:
                    pattern = parts[1].strip('"').strip("'")
                    break
    if not pattern:
        pattern = default_target_type
    return pattern


def install_galaxy_target(target, target_type, output_dir, source_repository="", target_version=""):
    server_option = ""
    if source_repository:
        server_option = "--server {}".format(source_repository)
    target_name = target
    if target_version:
        target_name = f"{target}:{target_version}"
    cmd_str = f"ansible-galaxy {target_type} install {target_name} {server_option} -p {output_dir} --force"
    logger.debug(cmd_str)
    proc = subprocess.run(
        cmd_str,
        shell=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    # print("[DEBUG] stderr:", proc.stderr)
    # logger.debug("STDOUT:", proc.stdout)
    logger.debug(f"STDOUT: {proc.stdout}")
    logger.debug(f"STDERR: {proc.stderr}")
    if proc.returncode != 0:
        raise ValueError(f"failed to install a collection `{target}`; error: {proc.stderr}")
    return proc.stdout, proc.stderr


def install_galaxy_collection(name: str, target_dir: str):
    install_galaxy_target(target=name, target_type="collection", output_dir=target_dir)


def run_playbook(playbook_path: str, extra_vars: dict = None):
    extra_vars_option = ""
    if extra_vars and isinstance(extra_vars, dict):
        for key, value in extra_vars.items():
            value_str = json.dumps(value)
            extra_vars_option += f"--extra-vars='{key}={value_str}' "

    cmd_str = f"ansible-playbook {playbook_path} {extra_vars_option}"
    logger.debug(cmd_str)
    proc = subprocess.run(
        cmd_str,
        shell=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    logger.debug(cmd_str)
    proc = subprocess.run(
        cmd_str,
        shell=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    # print("[DEBUG] stderr:", proc.stderr)
    # logger.debug("STDOUT:", proc.stdout)
    logger.debug(f"STDOUT: {proc.stdout}")
    logger.debug(f"STDERR: {proc.stderr}")
    if proc.returncode != 0:
        raise ValueError(f"failed to run a playbook `{playbook_path}`; error: {proc.stderr}")
    return proc.stdout, proc.stderr


def transpile_yml_policy(src: str, dst: str):
    extra_vars = {
        "filepath": dst,
    }
    run_playbook(playbook_path=src, extra_vars=extra_vars)
    return


def get_tags_from_rego_policy_file(policy_path: str):
    var_name = "__tags__"
    tags = None
    with open(policy_path, "r") as file:
        for line in file:
            if var_name in line:
                parts = [p.strip() for p in line.split("=")]
                if len(parts) != 2:
                    continue
                if parts[0] == var_name:
                    tags = json.loads(parts[1])
                    break
    return tags


def match_target_module(module_fqcn: str, rego_path: str):
    module_pattern = detect_target_module_pattern(policy_path=rego_path)
    return match_str_expression(module_pattern, module_fqcn)


def match_target_type(target_type: str, rego_path: str):
    type_pattern = detect_target_type_pattern(policy_path=rego_path)
    return match_str_expression(type_pattern, target_type)


def find_task_line_number(
    yaml_body: str = "",
    task_name: str = "",
    module_name: str = "",
    module_options: dict = None,
    task_options: dict = None,
    previous_task_line: int = -1,
):
    if not task_name and not module_options:
        return None, None

    lines = []
    if yaml_body:
        lines = yaml_body.splitlines()

    # search candidates that match either of the following conditions
    #   - task name is included in the line
    #   - if module name is included,
    #       - if module option is string, it is included
    #       - if module option is dict, at least one key is included
    candidate_line_nums = []
    for i, line in enumerate(lines):
        # skip lines until `previous_task_line` if provided
        if previous_task_line > 0:
            if i <= previous_task_line - 1:
                continue

        if task_name:
            if task_name in line:
                candidate_line_nums.append(i)
        elif "{}:".format(module_name) in line:
            if isinstance(module_options, str):
                if module_options in line:
                    candidate_line_nums.append(i)
            elif isinstance(module_options, dict):
                option_matched = False
                for key in module_options:
                    if i + 1 < len(lines) and "{}:".format(key) in lines[i + 1]:
                        option_matched = True
                        break
                if option_matched:
                    candidate_line_nums.append(i)
    if not candidate_line_nums:
        return None, None

    # get task yaml_lines for each candidate
    candidate_blocks = []
    for candidate_line_num in candidate_line_nums:
        _yaml_lines, _line_num_in_file = _find_task_block(lines, candidate_line_num)
        if _yaml_lines and _line_num_in_file:
            candidate_blocks.append((_yaml_lines, _line_num_in_file))

    if not candidate_blocks:
        return None, None

    reconstructed_yaml = ""
    best_yaml_lines = ""
    best_line_num_in_file = []
    sorted_candidates = []
    if len(candidate_blocks) == 1:
        best_yaml_lines = candidate_blocks[0][0]
        best_line_num_in_file = candidate_blocks[0][1]
    else:
        # reconstruct yaml from the task data to calculate similarity (edit distance) later
        reconstructed_data = [{}]
        if task_name:
            reconstructed_data[0]["name"] = task_name
        reconstructed_data[0][module_name] = module_options
        if isinstance(task_options, dict):
            for key, val in task_options.items():
                if key not in reconstructed_data[0]:
                    reconstructed_data[0][key] = val

        try:
            reconstructed_yaml = yaml.safe_dump(reconstructed_data)
        except Exception:
            pass

        # find best match by edit distance
        if reconstructed_yaml:

            def remove_comment_lines(s):
                lines = s.splitlines()
                updated = []
                for line in lines:
                    if line.strip().startswith("#"):
                        continue
                    updated.append(line)
                return "\n".join(updated)

            def calc_dist(s1, s2):
                us1 = remove_comment_lines(s1)
                us2 = remove_comment_lines(s2)
                dist = Levenshtein.distance(us1, us2)
                return dist

            r = reconstructed_yaml
            sorted_candidates = sorted(candidate_blocks, key=lambda x: calc_dist(r, x[0]))
            best_yaml_lines = sorted_candidates[0][0]
            best_line_num_in_file = sorted_candidates[0][1]
        else:
            # give up here if yaml reconstruction failed
            # use the first candidate
            best_yaml_lines = candidate_blocks[0][0]
            best_line_num_in_file = candidate_blocks[0][1]

    yaml_lines = best_yaml_lines
    line_num_in_file = best_line_num_in_file
    return yaml_lines, line_num_in_file


def _find_task_block(yaml_lines: list, start_line_num: int):
    if not yaml_lines:
        return None, None

    if start_line_num < 0:
        return None, None

    lines = yaml_lines
    found_line = lines[start_line_num]
    is_top_of_block = found_line.replace(" ", "").startswith("-")
    begin_line_num = start_line_num
    indent_of_block = -1
    if is_top_of_block:
        indent_of_block = len(found_line.split("-")[0])
    else:
        found = False
        found_line = ""
        _indent_of_block = -1
        parts = found_line.split(" ")
        for i, p in enumerate(parts):
            if p != "":
                break
            _indent_of_block = i + 1
        for i in range(len(lines)):
            index = begin_line_num
            _line = lines[index]
            is_top_of_block = _line.replace(" ", "").startswith("-")
            if is_top_of_block:
                _indent = len(_line.split("-")[0])
                if _indent < _indent_of_block:
                    found = True
                    found_line = _line
                    break
            begin_line_num -= 1
            if begin_line_num < 0:
                break
        if not found:
            return None, None
        indent_of_block = len(found_line.split("-")[0])
    index = begin_line_num + 1
    end_found = False
    end_line_num = -1
    for i in range(len(lines)):
        if index >= len(lines):
            break
        _line = lines[index]
        is_top_of_block = _line.replace(" ", "").startswith("-")
        if is_top_of_block:
            _indent = len(_line.split("-")[0])
            if _indent <= indent_of_block:
                end_found = True
                end_line_num = index - 1
                break
        index += 1
        if index >= len(lines):
            end_found = True
            end_line_num = index
            break
    if not end_found:
        return None, None
    if begin_line_num < 0 or end_line_num > len(lines) or begin_line_num > end_line_num:
        return None, None

    yaml_lines = "\n".join(lines[begin_line_num : end_line_num + 1])
    line_num_in_file = [begin_line_num + 1, end_line_num + 1]
    return yaml_lines, line_num_in_file


# TODO: use task names and module names for searching
# NOTE: currently `tasks` in a Play object is composed of pre_tasks, tasks and post_tasks
def find_play_line_number(
    yaml_body: str = "",
    play_name: str = "",
    play_options: dict = None,
    task_names: list = None,
    module_names: list = None,
    previous_play_line: int = -1,
):
    if not play_name and not play_options and not task_names and not module_names:
        return None, None

    lines = []
    if yaml_body:
        lines = yaml_body.splitlines()

    # search candidates that match either of the following conditions
    #   - task name is included in the line
    #   - if module name is included,
    #       - if module option is string, it is included
    #       - if module option is dict, at least one key is included
    candidate_line_nums = []
    for i, line in enumerate(lines):
        # skip lines until `previous_task_line` if provided
        if previous_play_line > 0:
            if i <= previous_play_line - 1:
                continue

        if play_name:
            if play_name in line:
                candidate_line_nums.append(i)
        elif "hosts:":
            candidate_line_nums.append(i)
    if not candidate_line_nums:
        return None, None

    # get play yaml_lines for each candidate
    candidate_blocks = []
    for candidate_line_num in candidate_line_nums:
        _yaml_lines, _line_num_in_file = _find_play_block(lines, candidate_line_num)
        if _yaml_lines and _line_num_in_file:
            candidate_blocks.append((_yaml_lines, _line_num_in_file))

    if not candidate_blocks:
        return None, None

    reconstructed_yaml = ""
    best_yaml_lines = ""
    best_line_num_in_file = []
    sorted_candidates = []
    if len(candidate_blocks) == 1:
        best_yaml_lines = candidate_blocks[0][0]
        best_line_num_in_file = candidate_blocks[0][1]
    else:
        # reconstruct yaml from the play data to calculate similarity (edit distance) later
        reconstructed_data = [{}]
        if play_name:
            reconstructed_data[0]["name"] = play_name
        if isinstance(play_options, dict):
            for key, val in play_options.items():
                if key not in reconstructed_data[0]:
                    reconstructed_data[0][key] = val

        try:
            reconstructed_yaml = yaml.safe_dump(reconstructed_data)
        except Exception:
            pass

        # find best match by edit distance
        if reconstructed_yaml:

            def remove_comment_lines(s):
                lines = s.splitlines()
                updated = []
                for line in lines:
                    if line.strip().startswith("#"):
                        continue
                    updated.append(line)
                return "\n".join(updated)

            def calc_dist(s1, s2):
                us1 = remove_comment_lines(s1)
                us2 = remove_comment_lines(s2)
                dist = Levenshtein.distance(us1, us2)
                return dist

            r = reconstructed_yaml
            sorted_candidates = sorted(candidate_blocks, key=lambda x: calc_dist(r, x[0]))
            best_yaml_lines = sorted_candidates[0][0]
            best_line_num_in_file = sorted_candidates[0][1]
        else:
            # give up here if yaml reconstruction failed
            # use the first candidate
            best_yaml_lines = candidate_blocks[0][0]
            best_line_num_in_file = candidate_blocks[0][1]

    yaml_lines = best_yaml_lines
    line_num_in_file = best_line_num_in_file
    return yaml_lines, line_num_in_file


def _find_play_block(yaml_lines: list, start_line_num: int):
    if not yaml_lines:
        return None, None

    if start_line_num < 0:
        return None, None

    lines = yaml_lines
    found_line = lines[start_line_num]
    is_top_of_block = found_line.replace(" ", "").startswith("-")
    begin_line_num = start_line_num
    indent_of_block = -1
    if is_top_of_block:
        indent_of_block = len(found_line.split("-")[0])
    else:
        found = False
        found_line = ""
        _indent_of_block = -1
        parts = found_line.split(" ")
        for i, p in enumerate(parts):
            if p != "":
                break
            _indent_of_block = i + 1
        for i in range(len(lines)):
            index = begin_line_num
            _line = lines[index]
            is_top_of_block = _line.replace(" ", "").startswith("-")
            is_tasks_block = _line.split("#")[0].strip() in ["tasks:", "pre_tasks:", "post_tasks:"]
            if is_top_of_block and not is_tasks_block:
                _indent = len(_line.split("-")[0])
                if _indent < _indent_of_block:
                    found = True
                    found_line = _line
                    break
            begin_line_num -= 1
            if begin_line_num < 0:
                break
        if not found:
            return None, None
        indent_of_block = len(found_line.split("-")[0])
    index = begin_line_num + 1
    end_found = False
    end_line_num = -1
    for i in range(len(lines)):
        if index >= len(lines):
            break
        _line = lines[index]
        is_top_of_block = _line.replace(" ", "").startswith("-")
        if is_top_of_block:
            _indent = len(_line.split("-")[0])
            if _indent <= indent_of_block:
                end_found = True
                end_line_num = index - 1
                break
        index += 1
        if index >= len(lines):
            end_found = True
            end_line_num = index
            break
    if not end_found:
        return None, None
    if begin_line_num < 0 or end_line_num > len(lines) or begin_line_num > end_line_num:
        return None, None

    yaml_lines = "\n".join(lines[begin_line_num : end_line_num + 1])
    line_num_in_file = [begin_line_num + 1, end_line_num + 1]
    return yaml_lines, line_num_in_file
