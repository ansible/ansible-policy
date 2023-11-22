import os
import sys
import json
import argparse
import tempfile
from ansible_gatekeeper.rego_data import (
    make_policy_input,
)
from ansible_gatekeeper.utils import (
    validate_opa_installation,
    eval_opa_policy,
    uncompress_file,
    process_runner_jobdata,
)


EvalTypeJobdata = "jobdata"
EvalTypeProject = "project"


def eval(rego_path: str, policy_input: str, galaxy_data_path: str) -> str:
    validate_opa_installation()

    result = eval_opa_policy(
        rego_path=rego_path,
        policy_input=policy_input,
        galaxy_data_path=galaxy_data_path,
    )

    return result


def main():
    parser = argparse.ArgumentParser(description="TODO")
    parser.add_argument("-r", "--rego", help='rego policy file')
    parser.add_argument("-t", "--type", required=True, help='policy evaluation type; `jobdata` or `project`')
    parser.add_argument("-f", "--file", help='jobdata file output from `ansible-runner transmit` command (if empty, use stdin)')
    parser.add_argument("-d", "--dir", help='target project directory for project type')
    parser.add_argument("-m", "--metadata-json", help='metadata json string for the target project')
    parser.add_argument("-g", "--galaxy-data", default="galaxy_data.json.tar.gz", help='galaxy data file path')
    parser.add_argument("-o", "--output", help='output json file')
    args = parser.parse_args()

    rego_path = args.rego
    eval_type = args.type
    jobdata_path = args.file
    target_dir = args.dir
    metadata_json = args.metadata_json
    galaxy_data_path = args.galaxy_data
    output_path = args.output

    metadata = {}
    if metadata_json:
        metadata = json.loads(metadata_json)

    if galaxy_data_path.endswith(".tar.gz"):
        new_galaxy_data_path = galaxy_data_path[:-7]
        if not os.path.exists(new_galaxy_data_path):
            uncompress_file(galaxy_data_path)
        galaxy_data_path = new_galaxy_data_path
    
    workdir = None
    if eval_type == EvalTypeJobdata:
        workdir = tempfile.TemporaryDirectory()
        runner_jobdata_str = ""
        if jobdata_path:
            with open(jobdata_path, "r") as file:
                runner_jobdata_str = file.read()
        else:
            for line in sys.stdin:
                runner_jobdata_str += line

        process_runner_jobdata(
            jobdata=runner_jobdata_str,
            workdir=workdir.name,
        )

    target_path = ""
    if eval_type == EvalTypeJobdata:
        target_path = workdir.name
    elif eval_type == EvalTypeProject:
        target_path = target_dir

    p_input = make_policy_input(target_path=target_path, metadata=metadata, galaxy_data_path=galaxy_data_path)

    result = eval(rego_path=rego_path, policy_input=p_input, galaxy_data_path=galaxy_data_path)
    
    if workdir:
        workdir.cleanup()

    if output_path:
        with open(output_path, "w") as ofile:
            ofile.write(json.dumps(result))
            # ofile.write(p_input.to_json())
    else:
        disp_result = {k: v for k, v in result.items() if not k.startswith("_")}
        print(json.dumps(disp_result, indent=2))
        true_exists = any([v for k, v in result.items() if isinstance(v, bool)])
        if true_exists:
            sys.exit(1)
        else:
            sys.exit(0)


if __name__ == "__main__":
    main()
