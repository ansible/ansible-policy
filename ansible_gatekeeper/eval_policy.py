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
        term_width = os.get_terminal_size().columns

        for input_type in results:
            violation_found = False
            policy_found_for_this_type = False
            violation_count = 0
            results_per_type = results[input_type]
            if not results_per_type:
                continue
            total_targets = len(results_per_type)
            msg = ""
            for i, result_per_target in enumerate(results_per_type):
                type_str = input_type.upper()
                input_object = result_per_target.get("object")
                result_for_policies = result_per_target.get("result")
                msg += f"{type_str} [{input_object.name}] ".ljust(term_width, "*") + "\n"
                for policy_name, single_result in result_for_policies.items():
                    is_target_type = single_result.get("is_target_type", False)
                    if is_target_type:
                        policy_found_for_this_type = True
                    rego_out = single_result.get("rego_out", {})
                    flag = ""
                    # disp_result = {k: v for k, v in result.items() if not k.startswith("_")}
                    # print(json.dumps(disp_result, indent=2), file=sys.stderr)
                    true_exists = any([v for k, v in rego_out.items() if isinstance(v, bool)])
                    if true_exists:
                        flag = "NG"
                        if sys.stdout.isatty():
                            flag = f"\033[91m{flag}\033[00m"
                        # print(msg, file=sys.stderr)
                        violation_count += 1
                        violation_found = True
                    else:
                        flag = "OK"
                        if sys.stdout.isatty():
                            flag = f"\033[96m{flag}\033[00m"
                        else:
                            # print(msg, file=sys.stderr)
                            if runner_jobdata_str:
                                print(runner_jobdata_str)
                    msg += f"... {policy_name} {flag}\n"
                msg += "\n"
            msg += "---\n"
            if violation_count > 0:
                msg += f"Summary: \033[91mThe {violation_count} {input_type}s have violations!\033[00m (out of {total_targets} {input_type}s)\n"
            else:
                msg += f"Summary: \033[96mAll checks passed!\033[00m ({total_targets} {input_type}s)\n"
            if policy_found_for_this_type:
                print(msg, file=sys.stderr)
        if violation_found:
            sys.exit(1)


if __name__ == "__main__":
    main()
