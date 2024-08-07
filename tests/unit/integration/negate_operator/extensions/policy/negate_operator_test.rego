package negate_operator_test


import future.keywords.if
import future.keywords.in
import data.ansible_policy.resolve_var


__target__ = "task"
__tags__ = ["security"]



negate_operator_test_1_1 = true if {
    not input.test_val
}


negate_operator_test_0_1 = true if {
    negate_operator_test_1_1
}


allow = true if {
    negate_operator_test_0_1
    print("negate operator test")
} else = false
