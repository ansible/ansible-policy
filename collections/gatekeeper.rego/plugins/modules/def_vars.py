#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: def_vars
short_description: define a new vars to be transpiled to Rego policy
version_added: 0.0.1
description:
    - Define a new funciton to be transpiled to Rego policy
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
rego_block:
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

import os
import string

from ansible.module_utils.basic import AnsibleModule


_vars_template = string.Template(
    r"""
${vars}
"""
)

_policy_template = string.Template(
    r"""
package ${policy_name}

import future.keywords.if
import future.keywords.in
import data.ansible_gatekeeper.resolve_var
"""
)


def join_with_separator(str_or_list: str | list, separator: str = ", "):
    value = ""
    if isinstance(str_or_list, str):
        value = str_or_list
    elif isinstance(str_or_list, list):
        value = separator.join(str_or_list)
    return value


def to_rego_value(value: any):
    rego_value = ""
    if isinstance(value, str):
        rego_value = f'"{value}"'
    elif isinstance(value, list):
        _items = [to_rego_value(v) for v in value]
        rego_value = "[" + join_with_separator(_items) + "]"
    elif isinstance(value, dict):
        _key_value_list = [to_rego_value(k) + ": " + to_rego_value(v) for k, v in value.items()]
        rego_value = "{" + join_with_separator(_key_value_list) + "}"
    else:
        rego_value = f"{value}"
    return rego_value


def create_rego_block(params: dict):
    rego_block = ""
    template = _vars_template

    if params["type"] == "rego":
        vars_lines = [f"{k} = {v}" for k, v in params["vars"].items()]
    else:
        vars_lines = [f"{k} = " + to_rego_value(v) for k, v in params["vars"].items()]

    _vars = join_with_separator(vars_lines, separator="\n")

    rego_block = template.safe_substitute(
        {
            "vars": _vars,
        }
    )

    return rego_block


# TODO: avoid to use /tmp
def get_filepath(policy_name: str):
    return f"/tmp/{policy_name}.rego"


def init_policy(policy_name: str):
    fpath = get_filepath(policy_name=policy_name)
    if os.path.exists(fpath):
        os.remove(fpath)
    policy_header = _policy_template.safe_substitute({"policy_name": policy_name})
    with open(fpath, "w") as file:
        file.write(policy_header)
    return


def append_rego_block(policy_name: str, rego_block: str):
    fpath = get_filepath(policy_name=policy_name)
    with open(fpath, "a") as file:
        file.write(rego_block)
    return


def main():
    # define available arguments/parameters a user can pass to the module
    module_args = {
        "policy": dict(type="str", required=False, default="ansible_sample_policy"),
        "type": dict(type="str", required=False, default="rego"),
        "vars": dict(type="dict", required=True),
        "create_policy": dict(type="bool", required=False, default=False),
    }

    # seed the result dict in the object
    # we primarily care about changed and state
    # changed is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    success = False
    result = dict(changed=False, rego_block="", message="")

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
    policy_name = module.params["policy"]
    policy_filepath = get_filepath(policy_name)
    if not os.path.exists(policy_filepath) or module.params["create_policy"]:
        init_policy(policy_name=policy_name)

    append_rego_block(policy_name=policy_name, rego_block=rego_block)

    success = True
    result["message"] = "OK"

    # use whatever logic you need to determine whether or not this module
    # made any modifications to your target
    if success:
        result["changed"] = True
        result["rego_block"] = rego_block

    # during the execution of the module, if there is an exception or a
    # conditional state that effectively causes a failure, run
    # AnsibleModule.fail_json() to pass in the message and the result
    # if module.params['name'] == 'fail me':
    #     module.fail_json(msg='You requested this to fail', **result)

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


if __name__ == "__main__":
    main()
