package check_become_policy

import future.keywords.if
import future.keywords.in
import data.ansible_gatekeeper.resolve_var

__target_module__ = "*"

become_true_task = task_name {
    input.task.become.enabled
    task_name = input.task.name
}

using_become = true if {
    become_true_task != ""
} else = false
