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


# rego templates
_if_template = string.Template(r"""
${func_name} = true if {
    ${steps}
} else = false
""")

_deny_template = string.Template(r"""
deny = true if {
    ${steps}
} else = false
""")

_allow_template = string.Template(r"""
deny = false if {
    ${steps}
} else = true
""")

_item_not_in_template = string.Template(r"""
${func_name} = true if {
    lhs_list = to_list(${lhs})
    check_item_not_in_list(lhs_list, ${rhs})
} else = false

to_list(val) = output if {
    is_array(val)
    output = val
}

to_list(val) = output if {
    not is_array(val)
    output = [val]
}
                                        
check_item_not_in_list(lhs_list, rhs_list) = true if {
	array := [item | item := lhs_list[_]; not item in rhs_list]
    count(array) > 0
} else = false
""")


@dataclass
class RegoFunc:
    name: str = ""
    body: str = ""


@dataclass
class RegoPolicy:
    package: str = ""
    import_statements: List[str] = field(default_factory=list)
    condition_funcs: List[RegoFunc] = field(default_factory=list)
    action_func: str = ""
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
            _package = pol["name"].replace(" ", "_")
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
        _name = pol.get("name", "")
        condition = pol.get("condition", {})
        condition_funcs = condition_to_rule(condition, _name)
        rego_policy.condition_funcs = condition_funcs
        
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
            rules.append(cond.name)
        msg = action_args.get("msg", "")
        print_msg = convert_to_print(msg)
        rules.append(print_msg)
        template = _deny_template
        return make_func_from_cond("deny", template, rules)
    # elif action_type == "allow":
    #     rules.append(condition.name)
    #     msg = action_args.get("msg", "")
    #     print_msg = convert_to_print(msg)
    #     rules.append(print_msg)
    # elif action_type == "info":
    # elif action_type == "warn":
    # elif action_type == "ignore":

    return action_type, rules


def convert_to_print(input_text):
    pattern = r'{{\s*([^}]+)\s*}}'
    replacement = r'%v'

    result = re.sub(pattern, replacement, input_text)
    vals = re.findall(pattern, input_text)
    vals = [v.strip() for v in vals]
    val_str = ", ".join(vals)
    return f'print(sprintf("{result}", [{val_str}]))'


# func to convert each condition to rego rules
def condition_to_rule(condition: dict, policy_name: str):
    funcs = []
    if "AllCondition" in condition:
        _funcs = [convert_condition_func(cond, policy_name, i) for i, cond in enumerate(condition["AllCondition"])]
        funcs.extend(_funcs)
    else:
        _func = convert_condition_func(condition)
        funcs.append(_func)
    return funcs


# TODO: support all operations
def convert_condition_func(condition: dict, policy_name: str, index: int):
    rf = RegoFunc()
    func_name = f"{policy_name}_{index}"
    if " " in func_name:
        func_name = func_name.replace(" ", "_") 
    rf.name = func_name
    if "EqualsExpression" in condition:
        lhs = condition["EqualsExpression"]["lhs"]
        lhs_val = list(lhs.values())[0]
        rhs = condition["EqualsExpression"]["rhs"]
        rhs_val = list(rhs.values())[0]
        conditions = [f"{lhs_val} != {rhs_val}"]
        template = _if_template
        rf.body = make_func_from_cond(func_name, template, conditions)
    elif "NotEqualsExpression" in condition:
        lhs = condition["NotEqualsExpression"]["lhs"]
        lhs_val = list(lhs.values())[0]
        rhs = condition["NotEqualsExpression"]["rhs"]
        rhs_val = list(rhs.values())[0]
        conditions = [f"{lhs_val} != {rhs_val}"]
        template = _if_template
        rf.body = make_func_from_cond(func_name, template, conditions)
    elif "ItemNotInListExpression" in condition:
        lhs = condition["ItemNotInListExpression"]["lhs"]
        lhs_val = list(lhs.values())[0]
        rhs = condition["ItemNotInListExpression"]["rhs"]
        rhs_val = list(rhs.values())[0]
        template = _item_not_in_template
        rf.body = make_func_from_val(func_name, template, lhs=lhs_val, rhs=rhs_val)
    return rf


def make_func_from_cond(name, template, conditions):
    _steps = join_with_separator(conditions, separator="\n    ")
    rego_block = template.safe_substitute({
        "func_name": name,
        "steps": _steps,
    })
    return rego_block

def make_func_from_val(name, template, lhs, rhs):
    _name = name
    if " " in name:
        _name = name.replace(" ", "_") 
    rego_block = template.safe_substitute({
        "func_name": _name,
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
    parser.add_argument("-o", "--output", help='')
    args = parser.parse_args()

    fpath = args.file
    out_dir = args.output

    os.makedirs(out_dir, exist_ok=True)

    generate_rego_from_ast(fpath, out_dir)


if __name__ == "__main__":
    main()