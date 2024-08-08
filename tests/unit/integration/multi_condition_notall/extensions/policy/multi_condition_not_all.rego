package multi_condition_not_all


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


multi_condition_not_all_1_1 = true if {
    lhs_list = to_list(input.test_val)
    check_item_in_list(lhs_list, sample_list)
}


multi_condition_not_all_1_2 = true if {
    input.test_val2 == "val2"
}


multi_condition_not_all_0_1 = true if {
    not multi_condition_not_all_1_1
}

multi_condition_not_all_0_1 = true if {
    not multi_condition_not_all_1_2
}


allow = true if {
    multi_condition_not_all_0_1
    print("multi condition not all")
} else = false
