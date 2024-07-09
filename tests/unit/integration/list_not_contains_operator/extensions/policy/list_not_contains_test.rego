package list_not_contains_test


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
    array := [item | item := lhs_list[_]; not item in rhs_list]
    count(array) > 0
} else = false


list_not_contains_test_1_1 = true if {
    lhs_list = to_list(input.test_val)
    check_item_not_in_list(lhs_list, sample_list)
}


list_not_contains_test_0_1 = true if {
    list_not_contains_test_1_1
}


allow = true if {
    list_not_contains_test_0_1
    print("list not contains test")
} else = false
