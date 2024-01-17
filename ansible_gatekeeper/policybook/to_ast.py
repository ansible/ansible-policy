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

import os
import traceback

import yaml

from json_generator import generate_dict_policysets
from policy_parser import parse_policy_sets

import argparse

HERE = os.path.dirname(os.path.abspath(__file__))


def main(ansible_policy, ast_file):
    try:
        with open(ansible_policy, "r") as f:
            data = yaml.safe_load(f.read())
            policyset = generate_dict_policysets(
                parse_policy_sets(data)
            )

        with open(ast_file, "w") as f:
            f.write(yaml.dump(policyset))
    except Exception:
        data = None
        policyset = None
        traceback.print_exc()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TODO")
    parser.add_argument("-f", "--file", help='')
    parser.add_argument("-o", "--output", help='')
    args = parser.parse_args()

    ansible_policy = args.file
    ast_file = args.output
    main(ansible_policy, ast_file)