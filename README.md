# ansible-gatekeeper

## Getting started

### 1. install `opa` command

refer to OPA [document](https://github.com/open-policy-agent/opa#want-to-download-opa)

### 2. git clone

clone this repository

### 3. pip install

```bash
$ cd ansible-gatekeeper
$ pip install -e .
```

### 4. check an example rego policy

The example policy below checks if database name which is used in a project is allowed or not.

`using_forbidden_database` is a boolean which represents whether the forbidden database is used or not.

`not_allowed_databases` is a list of detected database names that are not allowed.


```bash
$ cat examples/runtime/policy.rego
package sample_ansible_policy

import future.keywords.if
import future.keywords.in
import data.ansible_gatekeeper.resolve_var

_allowed_databases = ["allowed-db-1", "allowed-db-2"]
_target_module = "community.mongodb.mongodb_user"

find_not_allowed_db(task) := database {
    fqcn := task.module_fqcn
    fqcn == _target_module
    database := resolve_var(task.module_options.database, input.variables)
    not database in _allowed_databases
}

not_allowed_databases := found {
    found := [
        find_not_allowed_db(task) | task := input.playbooks[_].tasks[_]; find_not_allowed_db(task)
    ]
}

using_forbidden_database = true if {
    found := not_allowed_databases
    count(found) > 0
} else = false

```


### 5. run `ansible-gatekeeper` for **project directory**

WIP
```


### 6. run `ansible-gatekeeper` for **ansible-runner jobdata**

ansible-gatekeeper can be used for checking runtime jobdata created by `ansibler-runner`, and this feature is useful to stop the playbook execution when policy violation is detected.

The example directory has [env/extravars](./examples/runtime/target/env/extravars) which `ansible-runner` command loads as variables at runtime, so this example uses `my-db` database which is not allowed.

Then ansible-gatekeeper can detect it like the following.

```bash
$ ansible-runner transmit examples/runtime/target -p playbook.yml | ansible-gatekeeper -t jobdata -r examples/runtime/policy.rego
{
  "not_allowed_databases": [
    "my-db"
  ],
  "using_forbidden_database": true
}
```