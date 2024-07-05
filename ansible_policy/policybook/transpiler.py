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

import traceback
import yaml
import argparse
import os
import glob
import re
import string
from ansible_policy.policybook.json_generator import generate_dict_policysets
from ansible_policy.policybook.policy_parser import parse_policy_sets, VALID_ACTIONS
from ansible_policy.policybook.rego_model import RegoPolicy, RegoFunc
from ansible_policy.utils import init_logger
from ansible_policy.policybook.expressioin_transpiler import ExpressionTranspiler

logger = init_logger(__name__, os.getenv("ANSIBLE_GK_LOG_LEVEL", "info"))

et = ExpressionTranspiler()

action_func_template = string.Template(
    """
${func_name} = true if {
    ${steps}
} else = false
"""
)


class PolicyTranspiler:
    """
    PolicyTranspiler transforms a policybook to a Rego policy.
    """

    def __init__(self, tmp_dir=None):
        self.tmp_dir = tmp_dir

    def run(self, input, outdir):
        if "extensions/policy" not in outdir:
            outdir = os.path.join(outdir, "extensions/policy")
        os.makedirs(outdir, exist_ok=True)
        if os.path.isfile(input):
            ast = self.policybook_to_ast(input)
            self.ast_to_rego(ast, outdir)
        elif os.path.isdir(input):
            pattern1 = f"{input}/**/policies/**/*.yml"
            pattern2 = f"{input}/**/extensions/policy/**/*.yml"
            policy_list = []
            _found = glob.glob(pattern1, recursive=True)
            if _found:
                policy_list.extend(_found)
            _found = glob.glob(pattern2, recursive=True)
            if _found:
                policy_list.extend(_found)
            if not policy_list:
                input_parts = input.split("/")
                if "policies" in input_parts or "policy" in input_parts:
                    pattern3 = f"{input}/**/*.yml"
                    _found = glob.glob(pattern3, recursive=True)
                    if _found:
                        policy_list.extend(_found)
            for p in policy_list:
                logger.debug(f"Transpiling policy file `{p}`")
                outdir_for_this_policy = outdir
                if "/post_run" in p and "/post_run" not in outdir_for_this_policy:
                    outdir_for_this_policy = os.path.join(outdir, "post_run")
                if "/pre_run" not in outdir_for_this_policy:
                    outdir_for_this_policy = os.path.join(outdir, "pre_run")
                os.makedirs(outdir_for_this_policy, exist_ok=True)
                ast = self.policybook_to_ast(p)
                self.ast_to_rego(ast, outdir_for_this_policy)
        else:
            raise ValueError("invalid input")

    def policybook_to_ast(self, policy_file):
        policyset = None
        try:
            with open(policy_file, "r") as f:
                data = yaml.safe_load(f.read())
                policyset = generate_dict_policysets(parse_policy_sets(data))
        except Exception:
            err = traceback.format_exc()
            logger.warning(f"Failed to transpile `{policy_file}`. details: {err}")
        return policyset

    def ast_to_rego(self, ast, rego_dir):
        for ps in ast:
            self.policyset_to_rego(ps, rego_dir)

    def policyset_to_rego(self, ast_data, rego_dir):
        if "PolicySet" not in ast_data:
            raise ValueError("no policy found")

        ps = ast_data["PolicySet"]
        if "name" not in ps:
            raise ValueError("name field is empty")

        policies = []
        for p in ps.get("policies", []):
            pol = p.get("Policy", {})

            rego_policy = RegoPolicy()
            # package
            _package = pol["name"]
            _package = self.clean_error_token(pol["name"])
            rego_policy.package = _package
            # import statements
            rego_policy.import_statements = [
                "import future.keywords.if",
                "import future.keywords.in",
                "import data.ansible_policy.resolve_var",
            ]
            # tags
            rego_policy.tags = pol.get("tags", [])
            # vars
            rego_policy.vars_declaration = ps.get("vars", [])
            # target
            rego_policy.target = pol.get("target")

            # condition -> rule
            _name = self.clean_error_token(pol["name"])
            condition = pol.get("condition", {})
            root_func, condition_funcs, used_funcs = self.condition_to_rule(condition, _name)
            rego_policy.root_condition_func = root_func
            rego_policy.condition_funcs = condition_funcs
            rego_policy.util_funcs = used_funcs

            action = pol.get("actions", [])[0]
            action_func = self.action_to_rule(action, root_func)
            rego_policy.action_func = action_func

            policies.append(rego_policy)

        for rpol in policies:
            rego_output = rpol.to_rego()
            with open(os.path.join(rego_dir, f"{rpol.package}.rego"), "w") as f:
                f.write(rego_output)
        return

    def action_to_rule(self, input: dict, condition: RegoFunc):
        action = input["Action"]
        rules = []
        action_type = action.get("action", "")
        if action_type not in VALID_ACTIONS:
            raise ValueError(f"{action_type} is not supported. supported actions are {VALID_ACTIONS}")
        action_args = action.get("action_args", "")
        rules.append(condition.name)
        msg = action_args.get("msg", "")
        print_msg = self.make_rego_print(msg)
        rules.append(print_msg)
        template = action_func_template
        return self.make_func_from_cond(action_type, template, rules)

    # func to convert each condition to rego rules
    def condition_to_rule(self, condition: dict, policy_name: str):
        root_func, condition_funcs = et.trace_ast_tree(condition=condition, policy_name=policy_name)
        # util funcs
        used_funcs = []
        for func in condition_funcs:
            used_funcs.extend(func.util_funcs)
        used_funcs = list(set(used_funcs))
        return root_func, condition_funcs, used_funcs

    def make_rego_print(self, input_text):
        pattern = r"{{\s*([^}]+)\s*}}"
        replacement = r"%v"
        # replace vars part to rego style
        result = re.sub(pattern, replacement, input_text)
        vals = re.findall(pattern, input_text)
        if len(vals) != 0:
            # Strip whitespace from all string values in the list
            vals = [v.strip() if isinstance(v, str) else v for v in vals]
            val_str = ", ".join(vals)
            # replace " with '
            result = result.replace('"', "'")
            return f'print(sprintf("{result}", [{val_str}]))'
        else:
            return f'print("{input_text}")'

    def make_func_from_cond(self, name, template, conditions):
        _steps = self.join_with_separator(conditions, separator="\n    ")
        rego_block = template.safe_substitute(
            {
                "func_name": name,
                "steps": _steps,
            }
        )
        return rego_block

    def join_with_separator(self, str_or_list: str | list, separator: str = ", "):
        value = ""
        if isinstance(str_or_list, str):
            value = str_or_list
        elif isinstance(str_or_list, list):
            value = separator.join(str_or_list)
        return value

    def clean_error_token(self, in_str):
        return in_str.replace(" ", "_").replace("-", "_").replace("?", "").replace("(", "_").replace(")", "_")


def load_file(input):
    # load yaml file
    ast_data = []
    with open(input, "r") as f:
        ast_data = yaml.safe_load(f)
    if not ast_data:
        raise ValueError("empty yaml file")
    return ast_data


def main():
    parser = argparse.ArgumentParser(description="TODO")
    parser.add_argument("-i", "--input", help="")
    parser.add_argument("-o", "--output", help="")
    args = parser.parse_args()

    input = args.input
    out_dir = args.output

    pt = PolicyTranspiler()
    pt.run(input, out_dir)


if __name__ == "__main__":
    main()
