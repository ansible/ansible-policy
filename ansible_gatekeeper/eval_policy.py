import os
import jsonpickle
import argparse
from ansible_gatekeeper.models import PolicyEvaluator, ResultFormatter


def main():
    parser = argparse.ArgumentParser(description="TODO")
    parser.add_argument("-t", "--type", default="project", help="policy evaluation type (`jobdata` or `project`)")
    parser.add_argument("-p", "--project-dir", help="target project directory for project type")
    parser.add_argument("-e", "--external-data", default="", help="filepath to external data like knowledge base data")
    parser.add_argument("-j", "--jobdata", help="alternative way to load jobdata from a file instead of stdin")
    parser.add_argument("-c", "--config", help="path to config file which configures policies to be evaluated")
    parser.add_argument("-o", "--output", help="output json file")
    args = parser.parse_args()

    eval_type = args.type
    project_dir = args.project_dir
    external_data_path = args.external_data
    jobdata_path = args.jobdata
    config_path = args.config
    output_path = args.output

    if not external_data_path:
        external_data_path = os.path.join(os.path.dirname(__file__), "galaxy_data.json")

    runner_jobdata_str = None

    evaluator = PolicyEvaluator(config_path=config_path)

    result, runner_jobdata_str = evaluator.run(
        eval_type=eval_type,
        project_dir=project_dir,
        jobdata_path=jobdata_path,
        external_data_path=external_data_path,
    )

    if output_path:
        with open(output_path, "w") as ofile:
            body = jsonpickle.encode(
                result,
                unpicklable=False,
                make_refs=False,
                separators=(",", ":"),
            )
            ofile.write(body)
    else:
        ResultFormatter().print(result=result)


if __name__ == "__main__":
    main()
