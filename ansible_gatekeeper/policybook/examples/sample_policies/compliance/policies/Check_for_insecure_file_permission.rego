package Check_for_insecure_file_permission


import future.keywords.if
import future.keywords.in
import data.ansible_gatekeeper.resolve_var


__tags__ = ["compliance"]


insecure_file_permission = ["1777"]
recommended_permissions = ["0755"]

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


Check_for_insecure_file_permission_0 = true if {
    lhs_list = to_list(input["ansible.builtin.file"].mode)
    check_item_in_list(lhs_list, insecure_file_permission)
} else = false             


Check_for_insecure_file_permission_1 = true if {
    lhs_list = to_list(input["ansible.builtin.copy"].mode)
    check_item_in_list(lhs_list, insecure_file_permission)
} else = false             


Check_for_insecure_file_permission_2 = true if {
    lhs_list = to_list(input["ansible.builtin.template"].mode)
    check_item_in_list(lhs_list, insecure_file_permission)
} else = false             


deny = true if {
    Check_for_insecure_file_permission_0
    Check_for_insecure_file_permission_1
    Check_for_insecure_file_permission_2
    print(sprintf("file permission is insecure, recommended permissions are %v.", [recommended_permissions]))
} else = false
