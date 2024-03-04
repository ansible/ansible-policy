import os
import jsonpickle
import argparse
from ansible_gatekeeper.models import PolicyEvaluator, ResultFormatter


FORMAT_PLAIN = "plain"
FORMAT_JSON = "json"
supported_formats = [FORMAT_PLAIN, FORMAT_JSON]


def main():
    parser = argparse.ArgumentParser(description="TODO")
    parser.add_argument("-t", "--type", default="project", help="policy evaluation type (`jobdata` or `project`)")
    parser.add_argument("-p", "--project-dir", help="target project directory for project type")
    parser.add_argument("-e", "--external-data", default="", help="filepath to external data like knowledge base data")
    parser.add_argument("-v", "--variables", default="", help="filepath to variables JSON data")
    parser.add_argument("-j", "--jobdata", help="alternative way to load jobdata from a file instead of stdin")
    parser.add_argument("-c", "--config", help="path to config file which configures policies to be evaluated")
    parser.add_argument("-f", "--format", default="plain", help="output format (`plain` or `json`, default to `plain`)")
    args = parser.parse_args()

    eval_type = args.type
    project_dir = args.project_dir
    external_data_path = args.external_data
    variables_path = args.variables
    jobdata_path = args.jobdata
    config_path = args.config
    _format = args.format

    if _format not in supported_formats:
        raise ValueError(f"The format type `{_format}` is not supported; it must be one of {supported_formats}")

    if not external_data_path:
        external_data_path = os.path.join(os.path.dirname(__file__), "galaxy_data.json")

    runner_jobdata_str = None

    evaluator = PolicyEvaluator(config_path=config_path)

    result, runner_jobdata_str = evaluator.run(
        eval_type=eval_type,
        project_dir=project_dir,
        jobdata_path=jobdata_path,
        external_data_path=external_data_path,
        variables_path=variables_path,
    )

    # if json format is specified, output the result object in json to stdout
    if _format == FORMAT_JSON:
        json_str = jsonpickle.encode(
            result,
            unpicklable=False,
            make_refs=False,
            separators=(",", ":"),
        )
        print(json_str)
    else:
        # otherwise, show the summary text
        ResultFormatter().print(result=result)


if __name__ == "__main__":
    main()
