package equal_operator_test


import future.keywords.if
import future.keywords.in
import data.ansible_policy.resolve_var


__target__ = "task"
__tags__ = ["security"]



check_item_not_in_list(lhs_list, rhs_list) = true if {
    array := [item | item := lhs_list[_]; not item in rhs_list]
    count(array) > 0
} else = false


to_list(val) = output if {
    is_array(val)
    output = val
}

to_list(val) = output if {
    not is_array(val)
    output = [val]
}


equal_operator_test_1_1 = true if {
    input
    input.test_val
}


equal_operator_test_0_1 = true if {
    equal_operator_test_1_1
}


allow = true if {
    equal_operator_test_0_1
    print("equal operator test")
} else = false
