package not_selectattr_operator_test


import future.keywords.if
import future.keywords.in
import data.ansible_policy.resolve_var


__target__ = "task"
__tags__ = ["security"]


sample_list = [{"name": "val1"}, {"name": "val2"}]

to_list(val) = output if {
    is_array(val)
    output = val
}

to_list(val) = output if {
    not is_array(val)
    output = [val]
}


check_item_key_not_in_list(lhs_list, rhs_list, key) = true if {
    array := [item | item := lhs_list[_]; object.get(item, key, "none") in rhs_list]
    count(array) == 0
} else = false


not_selectattr_operator_test_0_2 = true if {
    rhs_list = to_list(input.test_val)
    check_item_key_not_in_list(sample_list, rhs_list, ["name"])
}


not_selectattr_operator_test_0_1 = true if {
    not_selectattr_operator_test_0_2
}


allow = true if {
    not_selectattr_operator_test_0_1
    print("not selectattr operator test")
} else = false
