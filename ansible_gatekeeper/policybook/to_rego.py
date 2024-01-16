import yaml
from dataclasses import dataclass, field
from typing import List, Dict
import string
import argparse
import json


_if_template = string.Template(r"""
${func_name} = true if {
    ${steps}
} else = false
""")


@dataclass
class RegoCondition:
    name: str = ""
    conditions: list = field(default_factory=list)

    def to_rego_func(self):
        template = _if_template

        _steps = "\n".join(self.conditions)
        _name = self.name
        if " " in self.name:
            _name = self.name.replace(" ", "_") 
        rego_block = template.safe_substitute({
            "func_name": _name,
            "steps": _steps,
        })
        return rego_block

@dataclass
class RegoPolicy:
    package: str = ""
    import_statements: List[str] = field(default_factory=list)
    rulesets: List[RegoCondition] = field(default_factory=list)
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
        for rc in self.rulesets:
            rf = rc.to_rego_func()
            content.append(rf)
            content.append("\n")
        
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

    if "PoliciesSet" not in ad:
        raise ValueError("no policy found")

    ps = ad["PoliciesSet"]
    if "name" not in ps:
        raise ValueError("name field is empty")

    rego_policy = RegoPolicy()
    _package = ps["name"]
    if " " in ps["name"]:
        _package = ps["name"].replace(" ", "_")
    rego_policy.package = _package
    rego_policy.import_statements = [
        "import future.keywords.if",
        "import future.keywords.in",
        "import data.ansible_gatekeeper.resolve_var"
    ]
    rego_policy.vars_declaration = ps.get("vars", [])

    rules = []
    for p in ps.get("policies", []):
        pol = p.get("Policy", {})
        # condition -> rule
        rc = RegoCondition()
        rc.name = pol.get("name", "")
        condition = pol.get("condition", {})
        rule = condition_to_rule(condition)
        rc.conditions = rule
        rules.append(rc)

    rego_policy.rulesets = rules

    rego_output = rego_policy.to_rego()
    print("----- test output\n")
    print(rego_output)

    with open(output, "w") as f:
        f.write(rego_output)
    return


def condition_to_rule(condition: dict):
    rules = []
    if "AllCondition" in condition:
        all_rules = [convert_condition(cond) for cond in condition["AllCondition"]]
        rules.extend(all_rules)
    else:
        rule = convert_condition(condition)
        rules.append(rule)
    return rules

def convert_condition(condition):
    print("debug: condition", condition)
    if "EqualsExpression" in condition:
        lhs = condition["EqualsExpression"]["lhs"]
        lhs_val = list(lhs.values())[0]
        rhs = condition["EqualsExpression"]["rhs"]
        rhs_val = list(rhs.values())[0]
        return f"{lhs_val} == {rhs_val}"


def main():
    parser = argparse.ArgumentParser(description="TODO")
    parser.add_argument("-f", "--file", help='')
    parser.add_argument("-o", "--output", help='')
    args = parser.parse_args()

    fpath = args.file
    out_fpath = args.output

    generate_rego_from_ast(fpath, out_fpath)


if __name__ == "__main__":
    main()