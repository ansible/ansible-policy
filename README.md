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

`detected_forbidden_databases` is a list of detected database names that are not allowed.


```bash
$ cat examples/sample1.rego
package sample_ansible_policy

import future.keywords.if
import future.keywords.in
import data.ansible_gatekeeper.resolve_var

_allowed_databases = ["allowed-db-1", "allowed-db-2"]

is_allowed_db(task) {
    fqcn := task.module_fqcn
    fqcn == "community.mongodb.mongodb_user"
    database := resolve_var(task.module_options.database, input.variables)
    database in _allowed_databases
}

using_forbidden_database = true if {
    some i
    task := input.playbooks[_].tasks[i]
    task.module_fqcn == "community.mongodb.mongodb_user"
    not is_allowed_db(task)
} else = false

detected_forbidden_databases = [
    resolve_var(task.module_options.database, input.variables) | task := input.playbooks[_].tasks[_]; task.module_fqcn == "community.mongodb.mongodb_user"; not is_allowed_db(task)
]
```


### 5. run `ansible-gatekeeper` for **project directory**

The example project is using an allowed database `allowed-db-1` (in [vars.yml](./examples/sample1/project/vars.yml)), so no policy violations are reported.

```bash
$ ansible-gatekeeper -t project -d examples/sample1/project -r examples/sample1.rego
{
  "detected_forbidden_databases": [],
  "using_forbidden_database": false
}
```


### 6. run `ansible-gatekeeper` for **ansible-runner jobdata**

The example directory has [env/extravars](./examples/sample1/env/extravars) which `ansible-runner` command loads as variables at runtime, so this example uses `my-db` database which is not allowed.

This time ansible-gatekeeper can detect this forbidden database name like the following.

```bash
$ ansible-runner transmit examples/sample1 -p playbook.yml | ansible-gatekeeper -t jobdata -r examples/sample1.rego
{
  "detected_forbidden_databases": [
    "my-db"
  ],
  "using_forbidden_database": true
}
```