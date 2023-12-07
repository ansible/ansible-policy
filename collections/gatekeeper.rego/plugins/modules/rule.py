#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: rule
short_description: define a new rule to be transpiled to Rego policy
version_added: 0.0.1
description:
    - Define a new rule to be transpiled to Rego policy
author: 'TODO'
options:
  args:
    description:
      - TODO
    required: false
    default: {}
    type: dict
"""

EXAMPLES = r"""

"""

RETURN = r"""
rego:
    description: The generated Rego block
    type: str
    returned: always
    sample: ''
message:
    description: The output message that the test module generates.
    type: str
    returned: always
    sample: 'OK'
"""

import string

from ansible.module_utils.basic import AnsibleModule


_rule_template = string.Template(
    r"""
${rule_name}${args} := ${return} {
    ${exprs}
}
"""
)

_filter_template = string.Template(
    r"""
${rule_name}[${key}] {
    ${exprs}
}
"""
)

_if_template = string.Template(
    r"""
${rule_name} = true if {
    ${exprs}
} else = false
"""
)


def join_with_separator(str_or_list: str | list, separator: str = ", "):
    value = ""
    if isinstance(str_or_list, str):
        value = str_or_list
    elif isinstance(str_or_list, list):
        value = separator.join(str_or_list)
    return value


def create_rego_block(params: dict):
    rego_block = ""
    _type = params["type"]
    template = None
    if _type == "rule":
        template = _rule_template
    elif _type == "filter":
        template = _filter_template
    elif _type == "if":
        template = _if_template
    else:
        raise ValueError(f"{_type} is not supported type of rule")

    _args = join_with_separator(params["args"])
    if _args:
        _args = f"({_args})"
    _return = join_with_separator(params["return"])
    _exprs = join_with_separator(params["exprs"], separator="\n    ")

    rego_block = template.safe_substitute(
        {
            "rule_name": params["name"],
            "args": _args,
            "return": _return,
            "exprs": _exprs,
        }
    )

    return rego_block


def main():
    # define available arguments/parameters a user can pass to the module
    module_args = {
        "type": dict(type="str", required=False, default="rule"),
        "name": dict(type="str", required=True),
        "args": dict(type="list", required=False, default=[]),
        "exprs": dict(type="list", required=False),
        "return": dict(type="list", required=False),
    }

    # seed the result dict in the object
    # we primarily care about changed and state
    # changed is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    success = False
    result = dict(changed=False, rego="", message="")

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        module.exit_json(**result)

    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)

    rego_block = create_rego_block(module.params)

    success = True
    result["message"] = "OK"

    # use whatever logic you need to determine whether or not this module
    # made any modifications to your target
    if success:
        result["changed"] = True
        result["rego"] = rego_block

    # during the execution of the module, if there is an exception or a
    # conditional state that effectively causes a failure, run
    # AnsibleModule.fail_json() to pass in the message and the result
    if module.params["name"] == "fail me":
        module.fail_json(msg="You requested this to fail", **result)

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


if __name__ == "__main__":
    main()
