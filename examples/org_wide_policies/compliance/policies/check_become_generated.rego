# This is a generated file by the following command 
#   $ ansible-playbook check_become.yml --extra-vars="filepath=./check_become_generated.rego"

package check_become_policy

import future.keywords.if
import future.keywords.in
import data.ansible_gatekeeper.resolve_var

__target_module__ = "*"
__tags__ = ["compliance"]


become_true_task := task_name {
    input.task.become.enabled
    task_name = input.task.name
}

using_become = true if {
    become_true_task != ""
} else = false


