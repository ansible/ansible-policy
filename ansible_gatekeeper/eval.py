import os
import sys
import json
import argparse
import tempfile
from ansible_gatekeeper.rego_data import (
    load_input_from_jobdata,
    load_input_from_project_dir,
    process_input_data_with_external_data,
)
from ansible_gatekeeper.utils import (
    validate_opa_installation,
    eval_opa_policy,
)


EvalTypeJobdata = "jobdata"
EvalTypeProject = "project"



def eval_policy(eval_type: str, policy_path: str, project_dir: str="", jobdata_path: str="", external_data_path: str=""):
    runner_jobdata_str = None
    if eval_type == EvalTypeJobdata:
        input_data, runner_jobdata_str = load_input_from_jobdata(jobdata_path=jobdata_path)
    elif eval_type == EvalTypeProject:
        input_data = load_input_from_project_dir(project_dir=project_dir)
    else:
        raise ValueError(f"eval_type `{eval_type}` is not supported")
    
    # embed `task.module_fqcn` to input_data by using external_data
    input_data = process_input_data_with_external_data(input_data, external_data_path)

    result = _eval(rego_path=policy_path, input_data=input_data, external_data_path=external_data_path)

    return result, runner_jobdata_str


def _eval(rego_path: str, input_data: str, external_data_path: str) -> str:
    validate_opa_installation()

    result = eval_opa_policy(
        rego_path=rego_path,
        input_data=input_data,
        external_data_path=external_data_path,
    )

    return result


def main():
    parser = argparse.ArgumentParser(description="TODO")
    parser.add_argument("-r", "--rego", help='rego policy file')
    parser.add_argument("-t", "--type", required=True, help='policy evaluation type (`jobdata` or `project`)')
    parser.add_argument("-p", "--project-dir", help='target project directory for project type')
    parser.add_argument("-e", "--external-data", default="", help='filepath to external data like knowledge base data')
    parser.add_argument("-j", "--jobdata", help='alternative way to load jobdata from a file instead of stdin')
    parser.add_argument("-o", "--output", help='output json file')
    args = parser.parse_args()

    rego_path = args.rego
    eval_type = args.type
    project_dir = args.project_dir
    external_data_path = args.external_data
    jobdata_path = args.jobdata
    output_path = args.output

    if not external_data_path:
        external_data_path = os.path.join(os.path.dirname(__file__), "galaxy_data.json")

    input_data = None
    runner_jobdata_str = None
    
    result, runner_jobdata_str = eval_policy(
        eval_type=eval_type,
        policy_path=rego_path,
        project_dir=project_dir,
        jobdata_path=jobdata_path,
        external_data_path=external_data_path,
    )

    if output_path:
        with open(output_path, "w") as ofile:
            ofile.write(json.dumps(result))
    else:
        disp_result = {k: v for k, v in result.items() if not k.startswith("_")}
        print(json.dumps(disp_result, indent=2), file=sys.stderr)
        true_exists = any([v for k, v in result.items() if isinstance(v, bool)])
        if true_exists:
            msg = "[FAILURE] Policy violation detected!"
            if sys.stdout.isatty():
               msg = f"\033[91m{msg}\033[00m"
            print(msg, file=sys.stderr)
            sys.exit(1)
        else:
            msg = "[SUCCESS] All policy checks passed!"
            if sys.stdout.isatty():
               msg = f"\033[96m{msg}\033[00m"
            print(msg, file=sys.stderr)
            if runner_jobdata_str:
                print(runner_jobdata_str)


if __name__ == "__main__":
    main()
