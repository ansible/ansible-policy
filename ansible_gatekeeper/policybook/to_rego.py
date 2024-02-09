from sys import implementation
import yaml
from dataclasses import dataclass, field
from typing import List, Dict
import string
import argparse
import json
import os
import re
import glob
from rego_templates import TemplateManager
from json_generator import OPERATOR_MNEMONIC


rego_tpl = TemplateManager()


@dataclass
class RegoFunc:
    name: str = ""
    body: str = ""
    called_util_funcs: List[str] = field(default_factory=list)


@dataclass
class RegoPolicy:
    package: str = ""
    import_statements: List[str] = field(default_factory=list)
    condition_funcs: List[RegoFunc] = field(default_factory=list)
    util_funcs: List[str] = field(default_factory=list)
    action_func: str = ""
    vars_declaration: dict = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    target: str = ""
    
    def to_rego(self):
        content = []
        content.append(f"package {self.package}")
        content.append("\n")
        content.extend(self.import_statements)
        content.append("\n")
        # target
        content.append(f'__target__ = "{self.target}"')
        # tags
        if self.tags:
            tags_str = json.dumps(self.tags)
            content.append(f"__tags__ = {tags_str}")
            content.append("\n")
        # vars
        if self.vars_declaration:
            for var_name, val in self.vars_declaration.items():
                val_str = json.dumps(val)
                content.append(f"{var_name} = {val_str}")
        
        # util funcs
        for uf in self.util_funcs:
            content.append(uf)

        # rules
        for rf in self.condition_funcs:
            content.append(rf.body)

        content.append(self.action_func)
            
        content_str = "\n".join(content)
        return content_str


def generate_rego_from_ast(input, output):
    # load ast file
    ast_data = {}
    with open(input, "r") as f:
        ast_data = yaml.safe_load(f)
    
    if not ast_data:
        raise ValueError("empty ast file")
    
    ad = ast_data[0]

    if "PolicySet" not in ad:
        raise ValueError("no policy found")

    ps = ad["PolicySet"]
    if "name" not in ps:
        raise ValueError("name field is empty")

    policies = []
    for p in ps.get("policies", []):
        pol = p.get("Policy", {})

        rego_policy = RegoPolicy()
        # package
        _package = pol["name"]
        if " " in pol["name"]:
            _package = pol["name"].replace(" ", "_").replace("-", "_")
        rego_policy.package = _package
        # import statements
        rego_policy.import_statements = [
            "import future.keywords.if",
            "import future.keywords.in",
            "import data.ansible_gatekeeper.resolve_var"
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
        condition_funcs, util_funcs = condition_to_rule(condition, _name)
        rego_policy.condition_funcs = condition_funcs
        rego_policy.util_funcs = util_funcs
        
        action = pol.get("actions", [])[0]
        action_func = action_to_rule(action, condition_funcs)
        rego_policy.action_func = action_func
        
        policies.append(rego_policy)

    for rpol in policies:
        rego_output = rpol.to_rego()
        with open(os.path.join(output, f"{rpol.package}.rego"), "w") as f:
            f.write(rego_output)
    return


# TODO: support all actions
def action_to_rule(input: dict, conditions: list):
    action = input["Action"]
    rules = []
    action_type = action.get("action", "")
    action_args = action.get("action_args", "")
    if action_type == "deny":
        for cond in conditions:
            if cond.name not in rules:
                rules.append(cond.name)
        msg = action_args.get("msg", "")
        print_msg = convert_to_print(msg)
        rules.append(print_msg)
        template = rego_tpl._deny_func
        return make_func_from_cond("deny", template, rules)
    elif action_type == "allow":
        for cond in conditions:
            if cond.name not in rules:
                rules.append(cond.name)
        msg = action_args.get("msg", "")
        print_msg = convert_to_print(msg)
        rules.append(print_msg)
        template = rego_tpl._allow_func
        return make_func_from_cond("allow", template, rules)
    # elif action_type == "info":
    # elif action_type == "warn":
    # elif action_type == "ignore":

    return action_type, rules


def convert_to_print(input_text):
    pattern = r'{{\s*([^}]+)\s*}}'
    replacement = r'%v'

    result = re.sub(pattern, replacement, input_text)
    vals = re.findall(pattern, input_text)
    if len(vals) != 0:
        vals = [v.strip() for v in vals]
        val_str = ", ".join(vals)
        return f'print(sprintf("{result}", [{val_str}]))'
    else:
        return f'print("{input_text}")'


# func to convert each condition to rego rules
def condition_to_rule(condition: dict, policy_name: str):
    funcs = []
    used_util_funcs = []
    if "AllCondition" in condition:
        _funcs = [convert_condition_func(cond, policy_name, i) for i, cond in enumerate(condition["AllCondition"])]
        funcs.extend(_funcs)
        for _f in _funcs:
            used_util_funcs.extend(_f.called_util_funcs)
    elif "AnyCondition" in condition:
        _funcs = [convert_condition_func(cond, policy_name) for i, cond in enumerate(condition["AnyCondition"])]
        funcs.extend(_funcs)  
        for _f in _funcs:
            used_util_funcs.extend(_f.called_util_funcs)
    # util funcs
    used_util_funcs = (list(set(used_util_funcs)))
    return funcs, used_util_funcs


# TODO: support all operations
def convert_condition_func(condition: dict, policy_name: str, index: int = 0):
    rf = RegoFunc()
    func_name = f"{policy_name}_{index}"
    if " " in func_name:
        func_name = func_name.replace(" ", "_").replace("-", "_")
    rf.name = func_name
    if "AndExpression" in condition:
        rego_expressions = []
        util_funcs = []
        lhs = condition["AndExpression"]["lhs"]
        if has_expression(lhs):
            _exp, _utils = transpile_expression(lhs)
            rego_expressions.extend(_exp)
            util_funcs.extend(_utils)
        rhs = condition["AndExpression"]["rhs"]
        if has_expression(rhs):
            _exp, _utils = transpile_expression(rhs)
            rego_expressions.extend(_exp)
            util_funcs.extend(_utils)
        template = rego_tpl._if_func
        rf.called_util_funcs = util_funcs
        rf.body = make_func_from_cond(func_name, template, rego_expressions)
    # if "OrExpression" in condition:
    #     TODO: implementation
    else:
        rego_expressions, util_funcs = transpile_expression(condition)
        template = rego_tpl._if_func
        rf.called_util_funcs = util_funcs
        rf.body = make_func_from_cond(func_name, template, rego_expressions)
    return rf


def transpile_expression(ast_exp):
    rego_expressions = []
    util_funcs = []
    if "EqualsExpression" in ast_exp:
        lhs = ast_exp["EqualsExpression"]["lhs"]
        lhs_val = list(lhs.values())[0]
        rhs = ast_exp["EqualsExpression"]["rhs"]
        for type, val in rhs.items():
            if type == "String":
                rhs_val = val
                rego_expressions.append(f'{lhs_val} == {rhs_val}')
            elif type == "Boolean":
                rego_expressions.append(f"{lhs_val}")
    elif "NotEqualsExpression" in ast_exp:
        lhs = ast_exp["NotEqualsExpression"]["lhs"]
        lhs_val = list(lhs.values())[0]
        rhs = ast_exp["NotEqualsExpression"]["rhs"]
        for type, val in rhs.items():
            if type == "String":
                rhs_val = val
                rego_expressions.append(f'{lhs_val} != {rhs_val}')
            elif type == "Boolean":
                rhs_val = val
                rego_expressions.append(f"not {lhs_val}")
    elif "ItemNotInListExpression" in ast_exp:
        lhs = ast_exp["ItemNotInListExpression"]["lhs"]
        lhs_val = list(lhs.values())[0]
        rhs = ast_exp["ItemNotInListExpression"]["rhs"]
        rhs_val = list(rhs.values())[0]
        template =  rego_tpl._item_not_in_list_expression
        util_funcs = [rego_tpl._to_list_func, rego_tpl._item_not_in_list_func]
        rego_expressions.append(make_expression_from_val(template, lhs=lhs_val, rhs=rhs_val))
    elif "ItemInListExpression" in ast_exp:
        lhs = ast_exp["ItemInListExpression"]["lhs"]
        lhs_val = list(lhs.values())[0]
        rhs = ast_exp["ItemInListExpression"]["rhs"]
        rhs_val = list(rhs.values())[0]
        template = rego_tpl._item_in_list_expression
        util_funcs = [rego_tpl._to_list_func, rego_tpl._item_in_list_func]
        rego_expressions.append(make_expression_from_val(template, lhs=lhs_val, rhs=rhs_val))
    elif "ListContainsItemExpression" in ast_exp:
        # ListContainsItemExpression is basically the same as ItemInListExpression 
        #   except for the difference in the position of the lhs and rhs values.
        lhs = ast_exp["ListContainsItemExpression"]["lhs"]
        lhs_val = list(lhs.values())[0]
        rhs = ast_exp["ListContainsItemExpression"]["rhs"]
        rhs_val = list(rhs.values())[0]
        template = rego_tpl._item_in_list_expression
        util_funcs = [rego_tpl._to_list_func, rego_tpl._item_in_list_func]
        rego_expressions.append(make_expression_from_val(template, lhs=rhs_val, rhs=lhs_val))
    elif "ListNotContainsItemExpression" in ast_exp:
        lhs = ast_exp["ItemNotInListExpression"]["lhs"]
        lhs_val = list(lhs.values())[0]
        rhs = ast_exp["ItemNotInListExpression"]["rhs"]
        rhs_val = list(rhs.values())[0]
        template =  rego_tpl._item_not_in_list_expression
        util_funcs = [rego_tpl._to_list_func, rego_tpl._item_not_in_list_func]
        rego_expressions.append(make_expression_from_val(template, lhs=rhs_val, rhs=lhs_val))
    elif "KeyInDictExpression" in ast_exp:
        lhs = ast_exp["KeyInDictExpression"]["lhs"]
        lhs_val = list(lhs.values())[0]
        rhs = ast_exp["KeyInDictExpression"]["rhs"]
        rhs_val = list(rhs.values())[0].replace('"', "")
        template = rego_tpl._key_in_dict_expression
        rego_expressions.append(make_expression_from_val(template, lhs=lhs_val, rhs=f'"{rhs_val}"'))
    elif "KeyNotInDictExpression" in ast_exp:
        lhs = ast_exp["KeyNotInDictExpression"]["lhs"]
        lhs_val = list(lhs.values())[0]
        rhs = ast_exp["KeyNotInDictExpression"]["rhs"]
        rhs_val = list(rhs.values())[0].replace('"', "")
        template = rego_tpl._key_not_in_dict_expression
        rego_expressions.append(make_expression_from_val(template, lhs=lhs_val, rhs=f'"{rhs_val}"'))
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


def has_expression(data):
    keys = data.keys()
    expressions = OPERATOR_MNEMONIC.values()
    for key in keys:
        if key in expressions:
            return True
    return False

def make_func_from_cond(name, template, conditions):
    _steps = join_with_separator(conditions, separator="\n    ")
    rego_block = template.safe_substitute({
        "func_name": name,
        "steps": _steps,
    })
    return rego_block

def make_expression_from_val(template, lhs, rhs):
    rego_block = template.safe_substitute({
        "lhs": lhs,
        "rhs": rhs
    })
    return rego_block    

def join_with_separator(str_or_list: str | list, separator: str=", "):
    value = ""
    if isinstance(str_or_list, str):
        value = str_or_list
    elif isinstance(str_or_list, list):
        value = separator.join(str_or_list)
    return value



def main():
    parser = argparse.ArgumentParser(description="TODO")
    parser.add_argument("-f", "--file", help='')
    parser.add_argument("-d", "--dir", help='')
    parser.add_argument("-o", "--output", help='')
    args = parser.parse_args()

    fpath = args.file
    ast_dir = args.dir
    out_dir = args.output

    os.makedirs(out_dir, exist_ok=True)

    if fpath:
        generate_rego_from_ast(fpath, out_dir)
    elif ast_dir:
        path = f"{ast_dir}/*.yml"
        policy_list = glob.glob(path)
        for p in policy_list:
            generate_rego_from_ast(p, out_dir)



if __name__ == "__main__":
    main()