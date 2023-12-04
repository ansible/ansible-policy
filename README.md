# ansible-gatekeeper

## Getting started

### 1. install `opa` command

refer to OPA [document](https://github.com/open-policy-agent/opa#want-to-download-opa)

### 2. git clone

clone this repository

### 3. install `ansbile-gatekeeper` command

```bash
$ cd ansible-gatekeeper
$ pip install -e .
```

### 4. install `gatekeeper.rego` modules

```bash
$ ansible-galaxy collection install collections/gatekeeper.rego --force

Starting galaxy collection install process
Process install dependency map
Starting collection install process
Installing 'gatekeeper.rego:0.0.1' to '/Users/user/.ansible/collections/ansible_collections/gatekeeper/rego'
Created collection for gatekeeper.rego:0.0.1 at /Users/user/.ansible/collections/ansible_collections/gatekeeper/rego
gatekeeper.rego:0.0.1 was installed successfully
```

### 5. running example policy playbook

[The example project](collections/gatekeeper.rego/examples/check_requirements/firewall_role/) has a requirements.yml, but there is a missing requirement `community.crypto` which is used in a playbook in the project.

[check_requirements.yml](collections/gatekeeper.rego/examples/check_requirements/check_requirements.yml) is a policy playbook to check requirements, so it reports this missing requirement like the following.

```bash
$ ansible-playbook collections/gatekeeper.rego/examples/check_requirements/check_requirements.yml

PLAY [localhost] *************************************************************************************************************

TASK [Gathering Facts] *******************************************************************************************************
ok: [localhost]

TASK [gatekeeper.rego.def_vars] **********************************************************************************************
changed: [localhost]

TASK [gatekeeper.rego.def_rule] **********************************************************************************************
changed: [localhost]

TASK [gatekeeper.rego.def_rule] **********************************************************************************************
changed: [localhost]

TASK [gatekeeper.rego.def_rule] **********************************************************************************************
changed: [localhost]

TASK [gatekeeper.rego.def_rule] **********************************************************************************************
changed: [localhost]

TASK [gatekeeper.rego.run_eval] **************************************************************************************************
fatal: [localhost]: FAILED! => {"changed": false, "message": "", "msg": "Policy violation detected", "rego_block": "", "result": {"returncode": 1, "stderr": "{\n  \"has_missing_dependencies\": true,\n  \"missing_dependencies\": [\n    \"community.crypto\"\n  ],\n  \"requirements_yml\": [\n    \"community.general\"\n  ]\n}\n[FAILURE] Policy violation detected!\n", "stdout": ""}}

PLAY RECAP *******************************************************************************************************************
localhost                  : ok=6    changed=5    unreachable=0    failed=1    skipped=0    rescued=0    ignored=0

```


<details>

<summary>backlog</summary>

<div>

### 4. run `ansible-gatekeeper` for **project directory**

ansible-gatekeeper can be used for checking Ansible project contents at develop time.

For example, the [example policy](examples/develop/policy_satisfy_requirements.rego) checks if all the dependencies are correctly specified in the requirements.yml.

```rego
package sample_ansible_policy

import future.keywords.if
import future.keywords.in
import future.keywords.every

requirements_yml = [req.name | req := input.project.requirements.collections[_]]
_builtin_and_deps := array.concat(["ansible.builtin"], requirements_yml)

detect_missing_dependencies(task) := collection {
    fqcn := task.module_fqcn
    collection := get_module_collection_name(fqcn)
    not collection in _builtin_and_deps
}

get_module_collection_name(fqcn) := coll {
    contains(fqcn, ".")
    parts := split(fqcn, ".")
    coll := concat(".", [parts[0], parts[1]])
}

missing_dependencies[x] {
    task := input.taskfiles[_].tasks[_]
    x := detect_missing_dependencies(task)
}

has_missing_dependencies = true if {
    count(missing_dependencies) > 0
} else = false
```

The example project is a role which uses `community.general` and `community.crypto` as non-builtin dependencies, but its requirements.yml only speciies `community.general`.

Then ansible-gatekeeper can detect the missing dependency like the following.

```bash
$ ansible-gatekeeper -t project -p examples/develop/firewall_role \
    -r examples/develop/policy_satisfy_requirements.rego
{
  "has_missing_dependencies": true,
  "missing_dependencies": [
    "community.crypto"
  ],
  "requirements_yml": [
    "community.general"
  ]
}
[FAILURE] Policy violation detected!
```


### 5. run `ansible-gatekeeper` for **ansible-runner jobdata**

ansible-gatekeeper can be used for checking runtime jobdata created by `ansibler-runner`, and this feature is useful to stop the playbook execution when policy violation is detected.

The [example policy](examples/runtime/policy_use_allowed_dbs_only.rego) is a policy to check if all database names used in tasks are allowed or not.

```rego
package sample_ansible_policy

import future.keywords.if
import future.keywords.in
import data.ansible_gatekeeper.resolve_var

_allowed_databases = ["allowed-db-1", "allowed-db-2"]
_target_module = "community.mongodb.mongodb_user"

find_not_allowed_db(task) := database {
    fqcn := task.module_fqcn
    fqcn == _target_module
    database := resolve_var(task.module_options.database, input.variables) # <== variable resolution
    not database in _allowed_databases
}

not_allowed_databases[x] {
    task := input.playbooks[_].tasks[_] # <== loaded from project content
    x := find_not_allowed_db(task)
}

using_forbidden_database = true if {
    count(not_allowed_databases) > 0
} else = false
```

The example directory has [env/extravars](./examples/runtime/target/env/extravars) which `ansible-runner` command loads as variables at runtime, so this example uses `not-allowed-db` database which is not allowed.

Then ansible-gatekeeper can detect it and stop playbook execution like the following.

```bash
$ ansible-runner transmit examples/runtime/db_user -p playbook.yml | \
    ansible-gatekeeper -t jobdata -r examples/runtime/policy_use_allowed_dbs_only.rego | \
    ansible-runner worker | \
    ansible-runner process /tmp/
{
  "not_allowed_databases": [
    "my-db"
  ],
  "using_forbidden_database": true
}
[FAILURE] Policy violation detected!
```

If the variable is using a valid database name (`allowed-db-1` for instance), then you can execute the playbook as usual like this.

```bash
$ cat examples/runtime/target/env/extravars
---
database_name: allowed-db-1
database_user: john
```

```bash
$ ansible-runner transmit examples/runtime/db_user -p playbook.yml | \
    ansible-gatekeeper -t jobdata -r examples/runtime/policy_use_allowed_dbs_only.rego | \
    ansible-runner worker | \
    ansible-runner process /tmp/
{
  "not_allowed_databases": [],
  "using_forbidden_database": false
}
[SUCCESS] All policy checks passed!


PLAY [localhost] ***************************************************************

TASK [Gathering Facts] *********************************************************

ok: [localhost]

TASK [Include variables] *******************************************************

ok: [localhost]

TASK [Create mongodb user] *****************************************************

changed: [localhost]

PLAY RECAP *********************************************************************
localhost                  : ok=3    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
```

</div>

</details>