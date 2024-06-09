# Policybooks

Policybooks contain a list of policysets. Each policyset within a policybook
should have a unique name.

### Policysets

A policyset has the following properties:

| Name               | Description                                                                      | Required |
|--------------------|----------------------------------------------------------------------------------|----------|
| name               | The name to identify the policyset. Each policyset must have a unique name across the policybook. | Yes      |
| policies           | The list of one or more policies.                         | Yes      |
| hosts              | Similar to hosts in an Ansible playbook                                           | Yes      |
| vars               | Variables used in policy    | No       |

The example of policyset is below.

```yaml
- name: Check for mysql package installation
  hosts: localhost
  vars:
    allowed_packages:
      - "mysql-server"
  policies:
    - name: Check for package name
      target: task
      condition: input["ansible.builtin.package"].name not in allowed_packages
      actions:
        - deny:
            msg: The package {{ input["ansible.builtin.package"].name }} is not allowed, allowed packages are one of {{ allowed_packages }}
      tags:
        - compliance
```

### Policies

The policies node in a policyset contains a list of policies.
The policy decides to run actions by evaluating the condition(s)
that is defined by the policybook author.

A policy comprises of:

| Name      | Description                                                                                           | Required |
|-----------|-------------------------------------------------------------------------------------------------------|----------|
| name      | The name is a string to identify the policy. This field is mandatory. Each policy in a policieset must have a unique name across the policybook. You can use Jinja2 substitution in the name. | Yes      |
| condition |  See [conditions](#condition)                                                               | Yes      |
| actions   |  Specify an action from `deny`, `allow`, `info`, `warn` or `ignore`                             | Yes      |
| target    | Specify the target to evaluate by this policy. Target should be `task`, `play` or `role`.                                                                           | Yes      |
| enabled   | If the policy should be enabled, default is true. Can be set to false to disable a policy.    | No       |
| tags | List of tags used in ansible policy    | No |

### Conditions


A condition can contain
 * One condition
 * Multiple conditions where all of them have to match
 * Multiple conditions where any one of them has to match
 * Multiple conditions where not all one of them have to match

Supported Operators
*******************

Conditions support the following operators:

| Name                 | Description                                                                                                        |
|----------------------|--------------------------------------------------------------------------------------------------------------------|
| ==                   | The equality operator for strings and numbers                                                                      |
| !=                   | The non-equality operator for strings and numbers                                                                  |
| and                  | The conjunctive AND, for making compound expressions                                                               |
| or                   | The disjunctive OR                                                                                                 |
| in                   | To check if a value in the left-hand side exists in the list on the right-hand side                                |
| not in               | To check if a value in the left-hand side does not exist in the list on the right-hand side                        |
| contains             | To check if the list on the left-hand side contains the value on the right-hand side                               |
| not contains         | To check if the list on the left-hand side does not contain the value on the right-hand side                       |
| has key              | To check if a value on the left-hand side exists as a key in dict on the right-hand side                           |
| lack key             | To check if a value on the left-hand side does not exists as a key in dict on the right-hand side                  |
<!-- | >                    | The greater than operator for numbers                                                                              |
| <                    | The less than operator for numbers                                                                                 |
| >=                   | The greater than or equal to operator for numbers                                                                  |
| <=                   | The less than or equal to operator for numbers                                                                     | -->
<!-- | `+`                  | The addition operator for numbers                                                                                  |
| `-`                  | The subtraction operator for numbers                                                                                |
| `*`                  | The multiplication operator for numbers                                                                            | -->
<!-- | is defined           | To check if a variable is defined                                                                                  |
| is not defined       | To check if a variable is not defined, please see caveats listed below                                             |
| is match(pattern, ignorecase=true) | To check if the pattern exists at the beginning of the string. Regex supported                           |
| is not match(pattern, ignorecase=true) | To check if the pattern does not exist at the beginning of the string. Regex supported                     |
| is search(pattern, ignorecase=true) | To check if the pattern exists anywhere in the string. Regex supported                                    |
| is not search(pattern, ignorecase=true) | To check if the pattern does not exist anywhere in the string. Regex supported                              |
| is regex(pattern, ignorecase=true) | To check if the regular expression pattern exists in the string                                           |
| is not regex(pattern, ignorecase=true) | To check if the regular expression pattern does not exist in the string                                   |
| is select(operator, value) | To check if an item exists in the list that satisfies the test defined by operator and value            |
| is not select(operator, value) | To check if an item does not exist in the list that satisfies the test defined by operator and value    |
| is selectattr(key, operator, value) | To check if an object exists in the list that satisfies the test defined by key, operator, and value |
| is not selectattr(key, operator, value) | To check if an object does not exist in the list that satisfies the test defined by key, operator, and value |
| `<<`                 | Assignment operator, to save the matching events or facts with the events or facts prefix                        |
| not                  | Negation operator, to negate a boolean expression                                                                   | -->
