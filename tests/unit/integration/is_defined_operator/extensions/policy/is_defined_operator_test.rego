package is_defined_operator_test


import future.keywords.if
import future.keywords.in
import data.ansible_policy.resolve_var


__target__ = "task"
__tags__ = ["security"]



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


is_defined_operator_test_1_1 = true if {
    input
    input.test_val
}


is_defined_operator_test_0_1 = true if {
    is_defined_operator_test_1_1
}


allow = true if {
    is_defined_operator_test_0_1
    print("is defined operator test")
} else = false
