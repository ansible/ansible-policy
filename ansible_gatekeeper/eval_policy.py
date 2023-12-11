import os
import sys
import json
import argparse
from ansible_gatekeeper.models import PolicyEvaluator


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

    results, runner_jobdata_str = evaluator.run(
        eval_type=eval_type,
        project_dir=project_dir,
        jobdata_path=jobdata_path,
        external_data_path=external_data_path,
    )

    if output_path:
        with open(output_path, "w") as ofile:
            ofile.write(json.dumps(results))
    else:
        violation_found = False
        total_tasks = len(results)
        violation_count = 0
        term_width = os.get_terminal_size().columns

        for i, result_per_task in enumerate(results):
            task = result_per_task.get("task")
            result_for_policies = result_per_task.get("result")
            print(f"TASK [{task.name}] ".ljust(term_width, "*"), file=sys.stderr)
            for policy_name, result in result_for_policies.items():
                flag = ""
                # disp_result = {k: v for k, v in result.items() if not k.startswith("_")}
                # print(json.dumps(disp_result, indent=2), file=sys.stderr)
                true_exists = any([v for k, v in result.items() if isinstance(v, bool)])
                if true_exists:
                    msg = "    [FAILURE] Policy violation detected!"
                    flag = "NG"
                    if sys.stdout.isatty():
                        msg = f"\033[91m{msg}\033[00m"
                        flag = f"\033[91m{flag}\033[00m"
                    # print(msg, file=sys.stderr)
                    violation_count += 1
                    violation_found = True
                else:
                    msg = "    [SUCCESS] All policy checks passed!"
                    flag = "OK"
                    if sys.stdout.isatty():
                        msg = f"\033[96m{msg}\033[00m"
                        flag = f"\033[96m{flag}\033[00m"
                    else:
                        # print(msg, file=sys.stderr)
                        if runner_jobdata_str:
                            print(runner_jobdata_str)
                print("...", policy_name, flag, file=sys.stderr)
            print("", file=sys.stderr)
        print("---", file=sys.stderr)
        msg = ""
        if violation_count > 0:
            msg = f"Summary: \033[91mThe {violation_count} tasks have violations!\033[00m (out of {total_tasks} tasks)"
        else:
            msg = f"Summary: \033[96mAll checks passed!\033[00m ({total_tasks} tasks)"
        print(msg, file=sys.stderr)
        if violation_found:
            sys.exit(1)


if __name__ == "__main__":
    main()
