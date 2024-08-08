package search_operator_test


import future.keywords.if
import future.keywords.in
import data.ansible_policy.resolve_var


__target__ = "task"
__tags__ = ["security"]



search_operator_test_0_2 = true if {
    regex.find_n("v.l", input.test_val, 1) != []
}


search_operator_test_0_1 = true if {
    search_operator_test_0_2
}


allow = true if {
    search_operator_test_0_1
    print("search operator test")
} else = false
