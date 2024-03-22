import os
import json
import argparse
from ansible_gatekeeper.models import (
    PolicyEvaluator,
    ResultFormatter,
    supported_formats,
)


def eval_policy(
    eval_type: str,
    project_dir: str = None,
    event: dict = None,
    variables_path: str = None,
    jobdata_path: str = None,
    config_path: str = None,
    policy_dir: str = None,
    external_data_path: str = None,
):

    if not external_data_path:
        external_data_path = os.path.join(os.path.dirname(__file__), "galaxy_data.json")

    evaluator = PolicyEvaluator(config_path=config_path, policy_dir=policy_dir)
    result = evaluator.run(
        eval_type=eval_type,
        project_dir=project_dir,
        event=event,
        jobdata_path=jobdata_path,
        external_data_path=external_data_path,
        variables_path=variables_path,
    )
    return result


def main():
    parser = argparse.ArgumentParser(description="TODO")
    parser.add_argument("-t", "--type", default="project", help="policy evaluation type (`jobdata`, `project` or `event`)")
    parser.add_argument("-p", "--project-dir", help="target project directory for project type")
    # The `--event-file` argument here is just for debugging
    # Actual events should be handled by `event_handler.py` instead
    parser.add_argument("-e", "--event-file", help="target event JSON file output by ansible-runner")
    parser.add_argument("-v", "--variables", default="", help="filepath to variables JSON data")
    parser.add_argument("-j", "--jobdata", help="alternative way to load jobdata from a file instead of stdin")
    parser.add_argument("-c", "--config", help="path to config file which configures policies to be evaluated")
    parser.add_argument("--policy-dir", help="path to a directory containing policies to be evaluated")
    parser.add_argument("--external-data", default="", help="filepath to external data like knowledge base data")
    parser.add_argument("-f", "--format", default="plain", help="output format (`plain` or `json`, default to `plain`)")
    args = parser.parse_args()

    if args.format not in supported_formats:
        raise ValueError(f"The format type `{args.format}` is not supported; it must be one of {supported_formats}")

    event = None
    if args.event_file:
        with open(args.event_file, "r") as f:
            event = json.load(f)

    result = eval_policy(
        eval_type=args.type,
        project_dir=args.project_dir,
        event=event,
        variables_path=args.variables,
        jobdata_path=args.jobdata,
        config_path=args.config,
        policy_dir=args.policy_dir,
        external_data_path=args.external_data,
    )
    ResultFormatter(format_type=args.format).print(result=result)


if __name__ == "__main__":
    main()
