package affirm_operator_test


import future.keywords.if
import future.keywords.in
import data.ansible_policy.resolve_var


__target__ = "task"
__tags__ = ["security"]



affirm_operator_test_1_1 = true if {
    input.test_val
}


affirm_operator_test_0_1 = true if {
    affirm_operator_test_1_1
}


allow = true if {
    affirm_operator_test_0_1
    print("affirm operator test")
} else = false
