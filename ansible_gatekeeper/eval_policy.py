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
    target_data: dict = None,
    variables_path: str = None,
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
        target_data=target_data,
        external_data_path=external_data_path,
        variables_path=variables_path,
    )
    return result


def main():
    parser = argparse.ArgumentParser(description="TODO")
    parser.add_argument("-t", "--type", default="project", help="policy evaluation type (`jobdata`, `project`, `rest` or `event`)")
    parser.add_argument("-p", "--project-dir", help="target project directory for project type")
    # The `--event-file` argument here is just for debugging
    # Actual events should be handled by `event_handler.py` instead
    parser.add_argument("-j", "--json-file", help="target JSON file (only for jobdata/rest/event type evaluation")
    parser.add_argument("-v", "--variables", default="", help="filepath to variables JSON data")
    parser.add_argument("-c", "--config", help="path to config file which configures policies to be evaluated")
    parser.add_argument("--policy-dir", help="path to a directory containing policies to be evaluated")
    parser.add_argument("--external-data", default="", help="filepath to external data like knowledge base data")
    parser.add_argument("-f", "--format", default="plain", help="output format (`plain` or `json`, default to `plain`)")
    args = parser.parse_args()

    if args.format not in supported_formats:
        raise ValueError(f"The format type `{args.format}` is not supported; it must be one of {supported_formats}")

    target_data = None
    if args.json_file:
        with open(args.json_file, "r") as f:
            target_data = json.load(f)

    result = eval_policy(
        eval_type=args.type,
        project_dir=args.project_dir,
        target_data=target_data,
        variables_path=args.variables,
        config_path=args.config,
        policy_dir=args.policy_dir,
        external_data_path=args.external_data,
    )
    ResultFormatter(format_type=args.format).print(result=result)


if __name__ == "__main__":
    main()
