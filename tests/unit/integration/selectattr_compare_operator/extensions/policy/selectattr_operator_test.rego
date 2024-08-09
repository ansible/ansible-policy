package selectattr_operator_test


import future.keywords.if
import future.keywords.in
import data.ansible_policy.resolve_var


__target__ = "task"
__tags__ = ["security"]


sample_list = [{"age": 10}, {"age": 20}]

to_list(val) = output if {
    is_array(val)
    output = val
}

to_list(val) = output if {
    not is_array(val)
    output = [val]
}


check_item_key_in_list(lhs_list, rhs_list, key) = true if {
    array := [item | item := lhs_list[_]; object.get(item, key, "none") in rhs_list]
    count(array) > 0
} else = false


selectattr_operator_test_0_2 = true if {
    array := [item | item := sample_list[_]; object.get(item, ["age"], "none") >= input.test_val]
    count(array) > 0
}


selectattr_operator_test_0_1 = true if {
    selectattr_operator_test_0_2
}


allow = true if {
    selectattr_operator_test_0_1
    print("selectattr operator test")
} else = false
