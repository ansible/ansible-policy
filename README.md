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

### 5. running ansible-gatekeeper with example policies

[The example config file](examples/ansible-gatekeeper.cfg) has 2 fields `policy` and `source`.

```ini
[policy]
default disabled
policies.community.*      tag=security    enabled
policies.org.compliance   tag=compliance  enabled

[source]
# policies.community.mongodb = policies.community_mongodb:0.0.1     # collection policy
policies.community.mongodb = examples/policies-community_mongodb-0.0.1.tar.gz   # collection policy
policies.org.compliance    = examples/org_wide_policies/compliance    # org-wide compliance policy
```


`source` is a list of modules and their source like ansible-galaxy or local directory. ansible-gatekeeper installs policies based on this configuration.

`policy` is a configuration like iptable to enable/disable policies. Users can use tag for configuring this in detail.

This example is configured to enable the follwoing 2 policies.

- `mongodb_user_db_policy`: check if a database name which is used in the task is allowed or not, for tasks using `community.mongodb.mongodb_user`.
- `check_become_policy`: check if `become: true` is used or not for all tasks

Then, [The example playbook](examples/project/playbook.yml) has some tasks that violate the 2 policies above.

ansible-gatekeeper can report these violations like the following.

```bash
$ ansible-gatekeeper -p examples/project/playbook.yml -c examples/ansible-gatekeeper.cfg
```

<img src="images/example_output.png" width="600px">



```
NOTE: Only first time you run the command below, ansible-gatekeeper installs policy files based on the configuration.
      If you changed your policy files, please reinstall them by removing the installed policies manually. They are installed `/tmp/ansible-gatekeeper/installed_policies` by default.
```