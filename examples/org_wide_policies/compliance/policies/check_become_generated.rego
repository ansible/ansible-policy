
package check_become_policy

import future.keywords.if
import future.keywords.in
import data.ansible_gatekeeper.resolve_var

__target_module__ = "*"
__tags__ = ["compliance"]


become_true_task := task_name {
    input.become
    task_name = input._agk.task.name
}

using_become = true if {
    become_true_task != ""
} else = false


