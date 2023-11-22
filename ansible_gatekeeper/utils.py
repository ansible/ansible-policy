import os
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

    logger = logging.getLogger(name)
    level_val = log_level_map.get(level.lower(), None)
    logger.setLevel(level_val)
    return logger


logger = init_logger(__name__, os.getenv("ANSIBLE_GK_LOG_LEVEL", "info"))


def validate_opa_installation(executable_name: str="opa"):
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
        raise ValueError(f"`opa` command is required to evaluate OPA policies")
    

def load_galaxy_data(fpath: str):
    data = {}
    with open(fpath, "r") as file:
        data = json.load(file)
    if not data:
        raise ValueError("loaded galaxy data is empty")
    
    return data.get("galaxy", {})


def eval_opa_policy(rego_path: str, policy_input: str, galaxy_data_path: str, executable_name: str="opa"):
    rego_pkg_name = get_rego_main_package_name(rego_path=rego_path)
    if not rego_pkg_name:
        raise ValueError("`package` must be defined in the rego policy file")
    
    util_rego_path = os.path.join(os.path.dirname(__file__), "rego/utils.rego")
    cmd_str = f"{executable_name} eval --data {util_rego_path} --data {rego_path} --data {galaxy_data_path} --stdin-input 'data.{rego_pkg_name}'"
    proc = subprocess.run(
        cmd_str,
        shell=True,
        input=policy_input,
        # stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    logger.debug(f"command: {cmd_str}")
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
    if not first_result and not "expressions" in first_result:
        raise ValueError(f"`expressions` field does not exist in the first result of output from `opa eval` command; first_result: {first_result}")

    expressions = first_result["expressions"]
    if not expressions:
        raise ValueError(f"`expressions` field in the output from `opa eval` command has no contents; first_result: {first_result}")
    
    expression = expressions[0]
    result_value = expression.get("value", {})
    return result_value


def get_module_name_from_task(task, galaxy: dict=None):
    module_name = ""
    if task.module_info and isinstance(task.module_info, dict):
        module_name = task.module_info.get("fqcn", "")
    if task.annotations:
        if not module_name:
            module_name = task.annotations.get("module.correct_fqcn", "")
        if not module_name:
            module_name = task.annotations.get("correct_fqcn", "")
    if not module_name and galaxy:
        if "." not in task.module:
            mappings = galaxy.get("module_name_mappings", {})
            found = mappings.get(task.module, [])
            if found and found[0] and "." in found[0]:
                module_name = found[0]
    if not module_name:
        module_name = task.module
    
    module_short_name = module_name
    if "." in module_short_name:
        module_short_name = module_short_name.split(".")[-1]

    return module_name, module_short_name


def get_rego_main_package_name(rego_path: str):
    pkg_name = ""
    with open(rego_path, "r") as file:
        prefix = "package "
        for line in file:
            _line = line.strip()
            if _line.startswith(prefix):
                pkg_name = _line[len(prefix):]
                break
    return pkg_name


def uncompress_file(fpath: str):
    if fpath.endswith(".tar.gz"):
        tar = tarfile.open(fpath, "r:gz")
        tar.extractall()
        tar.close()
    return


def process_runner_jobdata(jobdata: str, workdir: str):
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
