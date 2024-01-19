package Check_for_package_name


import future.keywords.if
import future.keywords.in
import data.ansible_gatekeeper.resolve_var


__tags__ = ["compliance"]


allowed_packages = ["mysql-server"]

Check_for_package_name_0 = true if {
    lhs_list = to_list(input["ansible.builtin.package"].name)
    check_item_not_in_list(lhs_list, allowed_packages)
} else = false

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


deny = true if {
    Check_for_package_name_0
    print(sprintf("The package %v is not allowed, allowed packages are one of %v", [input["ansible.builtin.package"].name, allowed_packages]))
} else = false
