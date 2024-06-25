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
import json
from ansible_policy.policybook.rego_templates import TemplateManager
from ansible_policy.policybook.json_generator import OPERATOR_MNEMONIC
from ansible_policy.policybook.json_generator import generate_dict_policysets
from ansible_policy.policybook.policy_parser import parse_policy_sets, VALID_ACTIONS
from ansible_policy.policybook.rego_model import RegoPolicy, RegoFunc
from ansible_policy.utils import init_logger


logger = init_logger(__name__, os.getenv("ANSIBLE_GK_LOG_LEVEL", "info"))


rego_tpl = TemplateManager()


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
            _name = pol.get("name", "")
            condition = pol.get("condition", {})
            condition_funcs, util_funcs = self.condition_to_rule(condition, _name)
            rego_policy.condition_funcs = condition_funcs
            rego_policy.util_funcs = util_funcs

            action = pol.get("actions", [])[0]
            action_func = self.action_to_rule(action, condition_funcs)
            rego_policy.action_func = action_func

            policies.append(rego_policy)

        for rpol in policies:
            rego_output = rpol.to_rego()
            with open(os.path.join(rego_dir, f"{rpol.package}.rego"), "w") as f:
                f.write(rego_output)
        return

    def action_to_rule(self, input: dict, conditions: list):
        action = input["Action"]
        rules = []
        action_type = action.get("action", "")
        if action_type not in VALID_ACTIONS:
            raise ValueError(f"{action_type} is not supported. supported actions are {VALID_ACTIONS}")
        action_args = action.get("action_args", "")
        for cond in conditions:
            if cond.name not in rules:
                rules.append(cond.name)
        msg = action_args.get("msg", "")
        print_msg = self.make_rego_print(msg)
        rules.append(print_msg)
        template = rego_tpl._action_func
        return self.make_func_from_cond(action_type, template, rules)

    # func to convert each condition to rego rules
    def condition_to_rule(self, condition: dict, policy_name: str):
        funcs = []
        used_util_funcs = []
        if "AllCondition" in condition:
            _funcs = [self.convert_condition_func(cond, policy_name, i) for i, cond in enumerate(condition["AllCondition"])]
            funcs.extend(_funcs)
            for _f in _funcs:
                used_util_funcs.extend(_f.called_util_funcs)
        elif "AnyCondition" in condition:
            _funcs = [self.convert_condition_func(cond, policy_name) for i, cond in enumerate(condition["AnyCondition"])]
            funcs.extend(_funcs)
            for _f in _funcs:
                used_util_funcs.extend(_f.called_util_funcs)
        # TODO: support NotAllCondition
        # util funcs
        used_util_funcs = list(set(used_util_funcs))
        return funcs, used_util_funcs

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

    # TODO: support all operations
    def convert_condition_func(self, condition: dict, policy_name: str, index: int = 0):
        rf = RegoFunc()
        func_name = f"{policy_name}_{index}"
        func_name = self.clean_error_token(func_name)
        rf.name = func_name
        if "AndExpression" in condition:
            rego_expressions = []
            util_funcs = []
            lhs = condition["AndExpression"]["lhs"]
            if self.has_expression(lhs):
                _exp, _utils = self.transpile_expression(lhs)
                rego_expressions.extend(_exp)
                util_funcs.extend(_utils)
            rhs = condition["AndExpression"]["rhs"]
            if self.has_expression(rhs):
                _exp, _utils = self.transpile_expression(rhs)
                rego_expressions.extend(_exp)
                util_funcs.extend(_utils)
            template = rego_tpl._if_func
            rf.called_util_funcs = util_funcs
            rf.body = self.make_func_from_cond(func_name, template, rego_expressions)
        # if "OrExpression" in condition:
        #     TODO: implementation
        else:
            rego_expressions, util_funcs = self.transpile_expression(condition)
            template = rego_tpl._if_func
            rf.called_util_funcs = util_funcs
            rf.body = self.make_func_from_cond(func_name, template, rego_expressions)
        return rf

    def transpile_expression(self, ast_exp):
        rego_expressions = []
        util_funcs = []
        if "EqualsExpression" in ast_exp:
            lhs = ast_exp["EqualsExpression"]["lhs"]
            lhs_val = self.change_data_format(lhs)
            rhs = ast_exp["EqualsExpression"]["rhs"]
            for type, val in rhs.items():
                if type == "String":
                    rhs_val = val
                    rego_expressions.append(f'{lhs_val} == "{rhs_val}"')
                elif type == "Boolean":
                    rego_expressions.append(f"{lhs_val}")
                elif type == "Variable":
                    rhs_val = val
                    rego_expressions.append(f"{lhs_val} == {rhs_val}")
        elif "NotEqualsExpression" in ast_exp:
            lhs = ast_exp["NotEqualsExpression"]["lhs"]
            lhs_val = self.change_data_format(lhs)
            rhs = ast_exp["NotEqualsExpression"]["rhs"]
            for type, val in rhs.items():
                if type == "String":
                    rhs_val = val
                    rego_expressions.append(f'{lhs_val} != "{rhs_val}"')
                elif type == "Boolean":
                    rhs_val = val
                    rego_expressions.append(f"not {lhs_val}")
                elif type == "Variable":
                    rhs_val = val
                    rego_expressions.append(f"{lhs_val} != {rhs_val}")
        elif "ItemNotInListExpression" in ast_exp:
            lhs = ast_exp["ItemNotInListExpression"]["lhs"]
            lhs_val = self.change_data_format(lhs)
            rhs = ast_exp["ItemNotInListExpression"]["rhs"]
            rhs_val = self.change_data_format(rhs)
            template = rego_tpl._item_not_in_list_expression
            util_funcs = [rego_tpl._to_list_func, rego_tpl._item_not_in_list_func]
            rego_expressions.append(self.make_expression_from_val(template, lhs=lhs_val, rhs=rhs_val))
        elif "ItemInListExpression" in ast_exp:
            lhs = ast_exp["ItemInListExpression"]["lhs"]
            lhs_val = self.change_data_format(lhs)
            rhs = ast_exp["ItemInListExpression"]["rhs"]
            rhs_val = self.change_data_format(rhs)
            template = rego_tpl._item_in_list_expression
            util_funcs = [rego_tpl._to_list_func, rego_tpl._item_in_list_func]
            rego_expressions.append(self.make_expression_from_val(template, lhs=lhs_val, rhs=rhs_val))
        elif "ListContainsItemExpression" in ast_exp:
            # ListContainsItemExpression is basically the same as ItemInListExpression
            #   except for the difference in the position of the lhs and rhs values.
            lhs = ast_exp["ListContainsItemExpression"]["lhs"]
            lhs_val = self.change_data_format(lhs)
            rhs = ast_exp["ListContainsItemExpression"]["rhs"]
            rhs_val = self.change_data_format(rhs)
            template = rego_tpl._item_in_list_expression
            util_funcs = [rego_tpl._to_list_func, rego_tpl._item_in_list_func]
            rego_expressions.append(self.make_expression_from_val(template, lhs=rhs_val, rhs=lhs_val))
        elif "ListNotContainsItemExpression" in ast_exp:
            lhs = ast_exp["ItemNotInListExpression"]["lhs"]
            lhs_val = self.change_data_format(lhs)
            rhs = ast_exp["ItemNotInListExpression"]["rhs"]
            rhs_val = self.change_data_format(rhs)
            template = rego_tpl._item_not_in_list_expression
            util_funcs = [rego_tpl._to_list_func, rego_tpl._item_not_in_list_func]
            rego_expressions.append(self.make_expression_from_val(template, lhs=rhs_val, rhs=lhs_val))
        elif "KeyInDictExpression" in ast_exp:
            lhs = ast_exp["KeyInDictExpression"]["lhs"]
            lhs_val = self.change_data_format(lhs)
            rhs = ast_exp["KeyInDictExpression"]["rhs"]
            rhs_val = self.change_data_format(rhs).replace('"', "")
            template = rego_tpl._key_in_dict_expression
            rego_expressions.append(self.make_expression_from_val(template, lhs=lhs_val, rhs=f'"{rhs_val}"'))
        elif "KeyNotInDictExpression" in ast_exp:
            lhs = ast_exp["KeyNotInDictExpression"]["lhs"]
            lhs_val = self.change_data_format(lhs)
            rhs = ast_exp["KeyNotInDictExpression"]["rhs"]
            rhs_val = self.change_data_format(rhs).replace('"', "")
            template = rego_tpl._key_not_in_dict_expression
            rego_expressions.append(self.make_expression_from_val(template, lhs=lhs_val, rhs=f'"{rhs_val}"'))
        elif "IsNotDefinedExpression" in ast_exp:
            val = self.change_data_format(ast_exp["IsNotDefinedExpression"])
            if "." in val:
                val_key = val.split(".")[-1]
                val_dict = val.replace(f".{val_key}", "")
                template = rego_tpl._args_is_not_defined_expression
                rego_expressions.append(self.make_expression_from_val(template, val1=val_dict, val2=val))
            else:
                template = rego_tpl._var_is_not_defined_expression
                rego_expressions.append(self.make_expression_from_val(template, val1=val))
        elif "IsDefinedExpression" in ast_exp:
            val = self.change_data_format(ast_exp["IsDefinedExpression"])
            if "." in val:
                val_key = val.split(".")[-1]
                val_dict = val.replace(f".{val_key}", "")
                template = rego_tpl._args_is_defined_expression
                rego_expressions.append(self.make_expression_from_val(template, val1=val_dict, val2=val))
            else:
                template = rego_tpl._var_is_defined_expression
                rego_expressions.append(self.make_expression_from_val(template, val1=val))
        # elif "GreaterThanExpression" in ast_exp:
        #     TODO: implementation
        # elif "LessThanExpression" in ast_exp:
        #     TODO: implementation
        # elif "GreaterThanOrEqualToExpression" in ast_exp:
        #     TODO: implementation
        # elif "LessThanOrEqualToExpression" in ast_exp:
        #     TODO: implementation
        # elif "AdditionExpression" in ast_exp:
        #     TODO: implementation
        # elif "SubtractionExpression" in ast_exp:
        #     TODO: implementation
        # elif "AssignmentExpression" in ast_exp:
        #     TODO: implementation
        return rego_expressions, util_funcs

    def change_data_format(self, data):
        if isinstance(data, list):
            return json.dumps([self.change_data_format(item) for item in data])
        elif isinstance(data, dict) and "String" in data:
            return f'"{data["String"]}"'
        elif isinstance(data, dict) and "Input" in data:
            return data["Input"]
        elif isinstance(data, dict) and "Variable" in data:
            return data["Variable"]
        elif isinstance(data, dict) and "Boolean" in data:
            return data["Boolean"]
        else:
            return data

    def has_expression(self, data):
        keys = data.keys()
        expressions = OPERATOR_MNEMONIC.values()
        for key in keys:
            if key in expressions:
                return True
        return False

    def make_func_from_cond(self, name, template, conditions):
        _steps = self.join_with_separator(conditions, separator="\n    ")
        rego_block = template.safe_substitute(
            {
                "func_name": name,
                "steps": _steps,
            }
        )
        return rego_block

    def make_expression_from_val(self, template, lhs="", rhs="", val1="", val2=""):
        if lhs and rhs:
            rego_block = template.safe_substitute({"lhs": lhs, "rhs": rhs})
        elif val1 and val2:
            rego_block = template.safe_substitute({"val1": val1, "val2": val2})
        elif val1:
            rego_block = template.safe_substitute({"val1": val1})
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
