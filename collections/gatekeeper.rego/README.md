## Getting started

### 1. git clone

clone this repository

### 2. install collection

```bash
$ cd collections/gatekeeper.rego

$ ansible-galaxy collection install ./ --force

Starting galaxy collection install process
Process install dependency map
Starting collection install process
Installing 'gatekeeper.rego:0.0.1' to '/Users/user/.ansible/collections/ansible_collections/ansible/rego'
Created collection for gatekeeper.rego:0.0.1 at /Users/user/.ansible/collections/ansible_collections/ansible/rego
gatekeeper.rego:0.0.1 was installed successfully
```

### 3. try an example playbook

The example playbook `examples/check_variables/check_database_name.yml` is a policy to check variable values, and it reports policy violation if some variables match with its conditions.

The example project `examples/check_variables/db_user` has a playbook which is using a database which is not allowed in the policy, so the policy reports this violation like the following.


```bash
$ ansible-playbook collections/gatekeeper.rego/examples/check_variables/check_database_name.yml

PLAY [localhost] ************************************************************************************************************************

TASK [Gathering Facts] ******************************************************************************************************************
ok: [localhost]

TASK [gatekeeper.rego.def_vars] *********************************************************************************************************
changed: [localhost]

TASK [gatekeeper.rego.def_rule] *********************************************************************************************************
changed: [localhost]

TASK [gatekeeper.rego.def_rule] *********************************************************************************************************
changed: [localhost]

TASK [gatekeeper.rego.def_rule] *********************************************************************************************************
changed: [localhost]

TASK [gatekeeper.rego.eval] *************************************************************************************************************
fatal: [localhost]: FAILED! => {"changed": false, "message": "", "msg": "Policy violation detected", "rego_block": "", "result": {"returncode": 1, "stderr": "{\n  \"not_allowed_databases\": [\n    \"not-allowed-db\"\n  ],\n  \"using_forbidden_database\": true\n}\n[FAILURE] Policy violation detected!\n", "stdout": ""}}

PLAY RECAP ******************************************************************************************************************************
localhost                  : ok=5    changed=4    unreachable=0    failed=1    skipped=0    rescued=0    ignored=0
```
