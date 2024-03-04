from dataclasses import dataclass, field
from typing import List
import json


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
