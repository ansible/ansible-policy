package equal_operator_test


import future.keywords.if
import future.keywords.in
import data.ansible_policy.resolve_var


__target__ = "task"
__tags__ = ["security"]



equal_operator_test_0_2 = true if {
    input.test_val == 1
}


equal_operator_test_0_1 = true if {
    equal_operator_test_0_2
}


allow = true if {
    equal_operator_test_0_1
    print("equal operator test")
} else = false
