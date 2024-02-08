from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, NamedTuple, Optional, Union

import ansible_rulebook.condition_types as ct



class Action(NamedTuple):
    action: str
    action_args: dict


class Condition(NamedTuple):
    when: str
    value: List[ct.Condition]


class Policy(NamedTuple):
    name: str
    condition: Condition
    actions: List[Action]
    enabled: bool
    tags: List[str]
    target: str


class PolicySet(NamedTuple):
    name: str
    hosts: Union[str, List[str]]
    vars: Dict
    policies: List[Policy]
    match_multiple_policies: bool = False



# # package-example.yml
# ---
# - name: Check for mysql package installation
#   hosts: localhost # decision environment (can be a container) 
#   vars:
#     allowed_packages:
#       - mysql
#   ## Define the conditions we are looking for
#   policies:
#     - name: Check for package name
#       condition: input["ansible.bultin.package"].name not in allowed_packages ## Define the action we should take should the condition be met 
#       actions:
#         - deny:
#             msg: The package {{ input["ansible.builtin.package"].name }} is not allowed, allowed packages are one of {{ allowed_packages.join(", ") }}
#       tags:
#         - compliance