#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: eval
short_description: run evaluation with a generated Rego policy
version_added: 0.0.1
description:
    - Run evaluation with a generated Rego policy
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
result:
    description: Result from evaluation
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
import json
import subprocess

from operator import itemgetter

from ansible.module_utils.basic import AnsibleModule


executable = 'ansible-gatekeeper'

def eval_policy(policy_path: str, project_dir: str):
    cmd_str = f'{executable} -t project -p {project_dir} -r {policy_path}'
    proc = subprocess.run(
        cmd_str,
        shell=True,
        # stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    
    result = {
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "returncode": proc.returncode,
    }
    return result


# TODO: avoid to use /tmp
def get_filepath(policy_name: str):
    return f"/tmp/{policy_name}.rego"


def main():
    # define available arguments/parameters a user can pass to the module
    module_args = {
        "policy": dict(type='str', required=False, default='ansible_sample_policy'),
        "project": dict(type='str', required=True),
    }

    # seed the result dict in the object
    # we primarily care about changed and state
    # changed is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    success = False
    result = dict(
        changed=False,
        rego_block="",
        message=''
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        module.exit_json(**result)

    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)
    
    policy_path = get_filepath(policy_name=module.params['policy'])

    eval_result = eval_policy(
        policy_path=policy_path,
        project_dir=module.params['project'],
    )

    success = True
    result['result'] = eval_result

    # use whatever logic you need to determine whether or not this module
    # made any modifications to your target
    if success:
        result['result'] = eval_result

    # during the execution of the module, if there is an exception or a
    # conditional state that effectively causes a failure, run
    # AnsibleModule.fail_json() to pass in the message and the result
    if eval_result.get('returncode', 1) != 0:
        module.fail_json(msg='Policy violation detected', **result)

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


if __name__ == '__main__':
    main()