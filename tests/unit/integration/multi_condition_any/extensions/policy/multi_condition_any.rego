package multi_condition_any


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


multi_condition_any_0_2 = true if {
    lhs_list = to_list(input.test_val)
    check_item_in_list(lhs_list, sample_list)
}


multi_condition_any_0_4 = true if {
    lhs_list = to_list(input.test_val2)
    check_item_in_list(lhs_list, sample_list)
}


multi_condition_any_0_5 = true if {
    input.test_val2 == "val2"
}


multi_condition_any_0_3 = true if {
    multi_condition_any_0_4
}

multi_condition_any_0_3 = true if {
    multi_condition_any_0_5
}


multi_condition_any_0_1 = true if {
    multi_condition_any_0_2
}

multi_condition_any_0_1 = true if {
    multi_condition_any_0_3
}


allow = true if {
    multi_condition_any_0_1
    print("multi condition any")
} else = false
