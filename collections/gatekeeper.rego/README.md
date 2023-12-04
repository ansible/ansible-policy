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

### 3. try test playbook

```bash
$ ansible-playbook tests/test.yml

PLAY [localhost] *****************************************************************************************************************************************************************************

TASK [Gathering Facts] ***********************************************************************************************************************************************************************
ok: [localhost]

TASK [gatekeeper.rego.def_vars] *****************************************************************************************************************************************************************
changed: [localhost]

TASK [gatekeeper.rego.def_func] *****************************************************************************************************************************************************************
changed: [localhost]

TASK [gatekeeper.rego.def_func] *****************************************************************************************************************************************************************
changed: [localhost]

TASK [gatekeeper.rego.def_func] *****************************************************************************************************************************************************************
changed: [localhost]

PLAY RECAP ***********************************************************************************************************************************************************************************
localhost                  : ok=5    changed=4    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
```

### 4. check the generated policy

NOTE: currently the policy will be generated at `/tmp/<policy_name>.rego`, but this should be changed in the future

```bash
$ cat /tmp/ansible_sample_policy.rego

package ansible_sample_policy

import future.keywords.if
import future.keywords.in
import data.ansible_gatekeeper.resolve_var

_allowed_databases:['allowed-db-1', 'allowed-db-2']
_target_module:community.mongodb.mongodb_user

find_not_allowed_db(task) := database {
    fqcn := task.module_fqcn
    fqcn == _target_module
    database := resolve_var(task.module_options.database, input.variables)
    not database in _allowed_databases
}

not_allowed_databases[x] {
    task := input.playbooks[_].tasks[_]
    x := find_not_allowed_db(task)
}

using_forbidden_database = true if {
    count(not_allowed_databases) > 0
} else = false
```