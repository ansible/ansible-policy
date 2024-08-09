package match_operator_test


import future.keywords.if
import future.keywords.in
import data.ansible_policy.resolve_var


__target__ = "task"
__tags__ = ["security"]



match_operator_test_0_2 = true if {
    not startswith(input.test_val, "val")
}


match_operator_test_0_1 = true if {
    match_operator_test_0_2
}


allow = true if {
    match_operator_test_0_1
    print("match operator test")
} else = false
