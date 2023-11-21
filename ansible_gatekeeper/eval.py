import os
import sys
import json
import argparse
from ansible_gatekeeper.rego_data import (
    make_policy_input,
)
from ansible_gatekeeper.utils import (
    validate_opa_installation,
    eval_opa_policy,
    uncompress_file,
)


def eval(rego_path: str, policy_input: str, galaxy_data_path: str) -> str:
    validate_opa_installation()

    result = eval_opa_policy(
        rego_path=rego_path,
        policy_input=policy_input,
        galaxy_data_path=galaxy_data_path,
    )

    return result



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TODO")
    parser.add_argument("-f", "--file", help='rego policy file')
    parser.add_argument("-d", "--dir", help='target project directory')
    parser.add_argument("-m", "--metadata-json", help='metadata json string for the target project')
    parser.add_argument("-g", "--galaxy-data", default="galaxy_data.json.tar.gz", help='galaxy data file path')
    parser.add_argument("-o", "--output", help='output json file')
    args = parser.parse_args()

    rego_path = args.file
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
    

    p_input = make_policy_input(target_path=target_dir, metadata=metadata)

    result = eval(rego_path=rego_path, policy_input=p_input, galaxy_data_path=galaxy_data_path)
    
    if output_path:
        with open(output_path, "w") as ofile:
            ofile.write(json.dumps(result))
            # ofile.write(p_input.to_json())
    else:
        print(json.dumps(result, indent=2))
        true_exists = any([v for v in result.values()])
        if true_exists:
            sys.exit(1)
        else:
            sys.exit(0)
