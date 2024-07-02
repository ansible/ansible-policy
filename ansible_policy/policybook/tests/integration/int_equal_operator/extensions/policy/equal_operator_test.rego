package equal_operator_test


import future.keywords.if
import future.keywords.in
import data.ansible_policy.resolve_var


__target__ = "task"
__tags__ = ["security"]



equal_operator_test_0 = true if {
    input.test_val == 1
}


deny = true if {
    equal_operator_test_0
    print("equal operator test")
} else = false
