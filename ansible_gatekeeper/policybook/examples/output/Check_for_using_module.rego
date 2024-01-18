package Check_for_using_module


import future.keywords.if
import future.keywords.in
import data.ansible_gatekeeper.resolve_var


__tags__ = ["compliance"]


allowed_modules = ["ansible.builtin.set_fact", "ansible.builtin.file"]

Check_for_module_name = true if {
    not input._agk.task.module_fqcn in allowed_modules
} else = false


deny = true if {
    Check_for_module_name
    print(sprintf("The package %v is not allowed, allowed modules are one of %v", [input._agk.task.module_fqcn, allowed_modules]))
} else = false
