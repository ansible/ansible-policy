package select_operator_test


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


check_item_not_in_list(lhs_list, rhs_list) = true if {
    array := [item | item := lhs_list[_]; item in rhs_list]
    count(array) == 0
} else = false


select_operator_test_0_2 = true if {
    rhs_list = to_list(input.test_val)
    check_item_not_in_list(sample_list, rhs_list)
}


select_operator_test_0_1 = true if {
    select_operator_test_0_2
}


allow = true if {
    select_operator_test_0_1
    print("select operator test")
} else = false
