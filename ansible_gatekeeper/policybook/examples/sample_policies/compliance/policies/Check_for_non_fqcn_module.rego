package Check_for_non_fqcn_module


import future.keywords.if
import future.keywords.in
import data.ansible_gatekeeper.resolve_var


__tags__ = ["compliance"]



Check_for_non_fqcn_module_0 = true if {
    input._agk.task.module_info.fqcn != input._agk.task.module
}


deny = true if {
    Check_for_non_fqcn_module_0
    print("module is written in non-fqcn")
} else = false
