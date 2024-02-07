package Restrict_instances_with_unapproved_AMIs


import future.keywords.if
import future.keywords.in
import data.ansible_gatekeeper.resolve_var


__tags__ = ["compliance"]


allowed_image_ids = ["ami-123456", "ami-789011"]

check_item_not_in_list(lhs_list, rhs_list) = true if {
	array := [item | item := lhs_list[_]; not item in rhs_list]
    count(array) > 0
} else = false


to_list(val) = output if {
    is_array(val)
    output = val
}

to_list(val) = output if {
    not is_array(val)
    output = [val]
}


Restrict_instances_with_unapproved_AMIs_0 = true if {
    lhs_list = to_list(input["amazon.aws.rds_instance"].image_id)
    check_item_not_in_list(lhs_list, allowed_image_ids)
} else = false


deny = true if {
    Restrict_instances_with_unapproved_AMIs_0
    print(sprintf("The image %v is not allowed, allowed images are one of %v", [input["amazon.aws.rds_instance"].image_id, allowed_image_ids]))
} else = false
