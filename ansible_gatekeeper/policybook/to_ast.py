#!/usr/bin/env python3

#  Copyright 2022 Red Hat, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import argparse
import os
import glob
import yaml
from transpiler import PolicyTranspiler


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TODO")
    parser.add_argument("-f", "--file", help="")
    parser.add_argument("-d", "--dir", help="")
    parser.add_argument("-o", "--output", help="")
    args = parser.parse_args()

    ansible_policy = args.file
    ansible_policy_dir = args.dir
    output = args.output

    pt = PolicyTranspiler()
    if ansible_policy:
        policyset = pt.policybook_to_ast(ansible_policy)
        os.makedirs(os.path.dirname(output), exist_ok=True)
        with open(output, "w") as f:
            f.write(yaml.dump(policyset))

    elif ansible_policy_dir:
        path = f"{ansible_policy_dir}/*.yml"
        policy_list = glob.glob(path)
        for p in policy_list:
            out_file = f"{output}/{os.path.basename(p)}"
            policyset = pt.policybook_to_ast(p)
            os.makedirs(os.path.dirname(out_file), exist_ok=True)
            with open(out_file, "w") as f:
                f.write(yaml.dump(policyset))
