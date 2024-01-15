import yaml
from dataclasses import dataclass, field
from typing import List, Dict
import string
import argparse
import json


_func_template = string.Template(r"""
${func_name}(${args}) := ${return} {
    ${steps}
}
""")

_filter_template = string.Template(r"""
${func_name}[${key}] {
    ${steps}
}
""")

_if_template = string.Template(r"""
${func_name} = true if {
    ${steps}
} else = false
""")


@dataclass
class RuleSet:
    hosts: List[str]
    name: str
    rules: list


@dataclass
class RegoPolicy:
    package: str = ""
    import_statements: List[str] = field(default_factory=list)
    rulesets: List[RuleSet] = field(default_factory=list)
    vars_declaration: list = field(default_factory=list)
    
    def to_rego(self):
        content = []
        content.append(f"package {self.package}")
        content.append("\n")
        content.extend(self.import_statements)
        content.append("\n")
        # vars
        if self.vars_declaration:
            for vars in self.vars_declaration:
                for var_name, val in vars.items():
                    content.append(f"{var_name} = {val}")

        # rules
        for rule in self.rulesets:
            content.append(rule)
            content.append("\n")
        
        content_str = "\n".join(content)
        return content_str


def convert_condition_to_rule(condition_data):
    rules = []
    if "AllCondition" in condition_data:
        conditions = [convert_condition_to_rule(cond) for cond in condition_data["AllCondition"]]
        rules.extend(conditions)
    elif "EqualsExpression" in condition_data:
        lhs = list(condition_data["EqualsExpression"]["lhs"].keys())[0]
        rhs = list(condition_data["EqualsExpression"]["rhs"].keys())[0]
        return f"{lhs} == {rhs}"



def generate_rego_from_ast(input):
    # load ast file
    ast_data = {}
    with open(input, "r") as f:
        ast_data = yaml.safe_load(f)
    
    if not ast_data:
        raise ValueError("empty ast file")
    
    ad = ast_data[0]

    if "PoliciesSet" not in ad:
        raise ValueError("no policy found")

    ps = ad["PoliciesSet"]
    if "name" not in ps:
        raise ValueError("name field is empty")

    rego_policy = RegoPolicy()
    rego_policy.package = ps["name"]
    rego_policy.import_statements = [
        "import future.keywords.if",
        "import future.keywords.in",
        "import data.ansible_gatekeeper.resolve_var"
    ]
    rego_policy.vars_declaration = ps.get("vars", [])

    rules = []
    for pol in ps.get("policies", []):
        # condition -> rule
        rule = condition_to_rule(pol)
        rules.append(rule)
    rego_policy.rulesets = rules


    output = rego_policy.to_rego()
    print("----- test output\n")
    print(output)
    return


def condition_to_rule(condition):
    return


def main():
    parser = argparse.ArgumentParser(description="TODO")
    parser.add_argument("-f", "--file", help='')
    args = parser.parse_args()

    fpath = args.file

    generate_rego_from_ast(fpath)


if __name__ == "__main__":
    main()