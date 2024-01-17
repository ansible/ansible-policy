import yaml
from dataclasses import dataclass, field
from typing import List, Dict
import string
import argparse
import json
import os
import re


OPERATOR_MNEMONIC = {
    "!=": "NotEqualsExpression",
    "==": "EqualsExpression",
    "and": "AndExpression",
    "or": "OrExpression",
    ">": "GreaterThanExpression",
    "<": "LessThanExpression",
    ">=": "GreaterThanOrEqualToExpression",
    "<=": "LessThanOrEqualToExpression",
    "+": "AdditionExpression",
    "-": "SubtractionExpression",
    "<<": "AssignmentExpression",
    "in": "ItemInListExpression",
    "not in": "ItemNotInListExpression",
    "contains": "ListContainsItemExpression",
    "not contains": "ListNotContainsItemExpression",
}


_if_template = string.Template(r"""
${func_name} = true if {
    ${steps}
} else = false
""")


@dataclass
class RegoFunc:
    name: str = ""
    rules: list = field(default_factory=list)

    def to_rego_func(self):
        template = _if_template

        _steps = join_with_separator(self.rules, separator="\n    ")
        _name = self.name
        if " " in self.name:
            _name = self.name.replace(" ", "_") 
        rego_block = template.safe_substitute({
            "func_name": _name,
            "steps": _steps,
        })
        return rego_block


def join_with_separator(str_or_list: str | list, separator: str=", "):
    value = ""
    if isinstance(str_or_list, str):
        value = str_or_list
    elif isinstance(str_or_list, list):
        value = separator.join(str_or_list)
    return value


@dataclass
class RegoPolicy:
    package: str = ""
    import_statements: List[str] = field(default_factory=list)
    condition_func: RegoFunc = field(default_factory=RegoFunc)
    action_func: RegoFunc = field(default_factory=RegoFunc)
    vars_declaration: dict = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    
    def to_rego(self):
        content = []
        content.append(f"package {self.package}")
        content.append("\n")
        content.extend(self.import_statements)
        content.append("\n")
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

        # rules
        rf = self.condition_func.to_rego_func()
        content.append(rf)

        rf = self.action_func.to_rego_func()
        content.append(rf)
            
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
        _package = ps["name"]
        if " " in ps["name"]:
            _package = ps["name"].replace(" ", "_")
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

        # condition -> rule
        r_func = RegoFunc()
        _name = pol.get("name", "")
        if " " in _name:
            _name = _name.replace(" ", "_")
        r_func.name = _name 
        condition = pol.get("condition", {})
        rule = condition_to_rule(condition)
        r_func.rules = rule
        rego_policy.condition_func = r_func
        
        action = pol.get("actions", [])[0]
        r_func = RegoFunc()
        action_type, rule = action_to_rule(action, rego_policy.condition_func)
        r_func.name = action_type
        r_func.rules = rule
        rego_policy.action_func = r_func
        
        policies.append(rego_policy)

    for rpol in policies:
        rego_output = rpol.to_rego()
        with open(os.path.join(output, f"{rpol.package}.rego"), "w") as f:
            f.write(rego_output)
    return


def action_to_rule(input: dict, condition: RegoFunc):
    action = input["Action"]
    rules = []
    action_type = action.get("action", "")
    action_args = action.get("action_args", "")
    if action_type == "deny":
        rules.append(condition.name)
        msg = action_args.get("msg", "")
        # The package {{ module }} is not allowed
        # -> print(sprintf("The package %v is not allowed", input.task.module))
        print_msg = convert_to_print(msg)
        rules.append(print_msg)
    return action_type, rules


def convert_to_print(input_text):
    pattern = r'{{\s*([^}]+)\s*}}'
    replacement = r'%v'

    result = re.sub(pattern, replacement, input_text)
    vals = re.findall(pattern, input_text)
    return f'print(sprintf("{result}", {vals[0]}))'


# func to convert each condition to rego rules
def condition_to_rule(condition: dict):
    rules = []
    if "AllCondition" in condition:
        all_rules = [convert_condition(cond) for cond in condition["AllCondition"]]
        rules.extend(all_rules)
    else:
        rule = convert_condition(condition)
        rules.append(rule)
    return rules


def convert_condition(condition: dict):
    print("debug: condition", condition)
    if "EqualsExpression" in condition:
        lhs = condition["EqualsExpression"]["lhs"]
        lhs_val = list(lhs.values())[0]
        rhs = condition["EqualsExpression"]["rhs"]
        rhs_val = list(rhs.values())[0]
        return f"{lhs_val} == {rhs_val}"
    elif "ItemNotInListExpression" in condition:
        lhs = condition["ItemNotInListExpression"]["lhs"]
        lhs_val = list(lhs.values())[0]
        rhs = condition["ItemNotInListExpression"]["rhs"]
        rhs_val = list(rhs.values())[0]
        return f"not {lhs_val} in {rhs_val}"


def main():
    parser = argparse.ArgumentParser(description="TODO")
    parser.add_argument("-f", "--file", help='')
    parser.add_argument("-o", "--output", help='')
    args = parser.parse_args()

    fpath = args.file
    out_dir = args.output

    os.makedirs(out_dir, exist_ok=True)

    generate_rego_from_ast(fpath, out_dir)


if __name__ == "__main__":
    main()