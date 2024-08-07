package in_operator_test


import future.keywords.if
import future.keywords.in
import data.ansible_policy.resolve_var


__target__ = "task"
__tags__ = ["security"]


sample_list = ["val1", "val2"]

to_list(val) = output if {
    is_array(val)
    output = val
}

to_list(val) = output if {
    not is_array(val)
    output = [val]
}


check_item_in_list(lhs_list, rhs_list) = true if {
    array := [item | item := lhs_list[_]; item in rhs_list]
    count(array) > 0
} else = false


in_operator_test_0_2 = true if {
    lhs_list = to_list(input.test_val)
    check_item_in_list(lhs_list, sample_list)
}


in_operator_test_0_1 = true if {
    in_operator_test_0_2
}


allow = true if {
    in_operator_test_0_1
    print("in operator test")
} else = false
