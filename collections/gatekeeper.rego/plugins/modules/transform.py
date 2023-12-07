#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: transform
short_description: generate a Rego policy based on Rego blocks
version_added: 0.0.1
description:
    - Define new variables to be transpiled to Rego policy
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


_policy_template = string.Template(
    r"""
package ${package_name}

import future.keywords.if
import future.keywords.in
import data.ansible_gatekeeper.resolve_var

__target_module__ = "${match_module}"
__tags__ = ${tags}

${blocks}

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


def create_policy_rego_block(params: dict):
    rego_block = ""
    template = _policy_template

    _match = params["match"]
    _match_module = "*"
    if _match:
        _match_module = _match[0]["module"]

    _tags = to_rego_value(params["tags"])

    registered_blocks = params["compose"]
    blocks = [b["rego"] for b in registered_blocks]
    _blocks = join_with_separator(blocks, separator="")

    rego_block = template.safe_substitute(
        {
            "package_name": params["package_name"],
            "match_module": _match_module,
            "tags": _tags,
            "blocks": _blocks,
        }
    )

    return rego_block


def write_file(filepath: str, body: str):
    with open(filepath, "w") as file:
        file.write(body)
    return


def main():
    # define available arguments/parameters a user can pass to the module
    module_args = {
        "filepath": dict(type="str", required=True),
        "package_name": dict(type="str", required=True),
        "tags": dict(type="list", required=False, default=[]),
        "match": dict(type="list", required=False, default=[]),
        "compose": dict(type="list", required=False, default=[]),
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

    rego_body = create_policy_rego_block(module.params)

    write_file(module.params["filepath"], rego_body)

    success = True
    result["message"] = "OK"

    # use whatever logic you need to determine whether or not this module
    # made any modifications to your target
    if success:
        result["changed"] = True
        result["rego"] = rego_body

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
