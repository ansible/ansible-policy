package Check_for_ec2_instance_type


import future.keywords.if
import future.keywords.in
import data.ansible_gatekeeper.resolve_var


__tags__ = ["compliance"]


allowed_instance_types = ["t2.micro", "t3.micro", "t3a.micro"]

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


Check_for_ec2_instance_type_0 = true if {
    lhs_list = to_list(input["amazon.aws.ec2_instance"].instance_type)
    check_item_not_in_list(lhs_list, allowed_instance_types)
}


deny = true if {
    Check_for_ec2_instance_type_0
    print(sprintf("The instance type %v is not allowed, allowed instance types are one of %v", [input["amazon.aws.ec2_instance"].instance_type, allowed_instance_types]))
} else = false
