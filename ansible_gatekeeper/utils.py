import os
import sys
import re
import base64
import json
import tarfile
import zipfile
import tempfile
import logging
import subprocess


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
    cmd_str = f"{executable_name} eval --data {util_rego_path} --data {rego_path} --data {external_data_path} --stdin-input 'data.{rego_pkg_name}'"
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
    if proc.stderr:
        print(f"{rego_pkg_name}: {proc.stderr}", file=sys.stderr)

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
    return result_value


def get_module_name_from_task(task):
    module_name = ""
    if task.module_info and isinstance(task.module_info, dict):
        module_name = task.module_info.get("fqcn", "")
    if task.annotations:
        if not module_name:
            module_name = task.annotations.get("module.correct_fqcn", "")
        if not module_name:
            module_name = task.annotations.get("correct_fqcn", "")

    if not module_name:
        module_name = task.module

    module_short_name = module_name
    if "." in module_short_name:
        module_short_name = module_short_name.split(".")[-1]

    return module_name, module_short_name


def embed_module_fqcn_with_galaxy(task, galaxy):
    if not galaxy:
        return
    if task.module and "." in task.module:
        return
    if task.module_fqcn and "." in task.module_fqcn:
        return

    module_fqcn = ""
    mappings = galaxy.get("module_name_mappings", {})
    found = mappings.get(task.module, [])
    if found and found[0] and "." in found[0]:
        module_fqcn = found[0]
        task.module_fqcn = module_fqcn
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
