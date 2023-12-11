## Getting started

### 1. git clone

clone this repository

### 2. Install collection

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

### 3. Create a policy YAML file

A policy YAML file can be written in YAML format with `gatekeeper.rego` modules like the following example.

This example is [here](examples/check_variables/check_database_name.yml).

```yaml
- hosts: localhost
  vars:
    allowed_databases: []
    package_name: "mongodb_user_db_policy"
    filepath: "/tmp/{{ package_name }}.rego"
  tasks:
    - gatekeeper.rego.vars:
        vars:
          _allowed_databases: "{{ allowed_databases }}"
      register: declare_vars

    - gatekeeper.rego.rule:
        name: database
        exprs:
          - db_name := resolve_var(input.task.module_options.database, input.task)
        return: db_name
      register: database

    - gatekeeper.rego.check:
        name: using_forbidden_database
        exprs:
          - database != ""
          - not database in _allowed_databases
      register: using_forbidden_database

    - gatekeeper.rego.transform:
        filepath: "{{ filepath }}"
        package_name: "{{ package_name }}"
        tags:
          - security
        match:
          - module: "community.mongodb.mongodb_user"
        compose:
          - "{{ declare_vars }}"
          - "{{ database }}"
          - "{{ using_forbidden_database }}"

```

There are 4 modules in `gatekeeper.rego`.

`vars`: define variables

`rule`: define a rule with Rego expressions

`check`: define a rule to determine whether to report violation or not

`transform`: generate a Rego policy; combine rules, set tags and match conditions and specify filepath and package name

Also, you can use Ansible variables in this policy YAML file like `{{ filepath }}` and `{{ allowed_databases }}` in the example above.


### 4. Check the generated Rego policy file

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
