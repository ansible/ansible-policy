package Check_for_rds_instance_version


import future.keywords.if
import future.keywords.in
import data.ansible_gatekeeper.resolve_var


__tags__ = ["compliance"]


allowed_versions = ["8.0.23", "10.0.35"]

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


Check_for_rds_instance_version_0 = true if {
    lhs_list = to_list(input["amazon.aws.rds_instance"].engine_version)
    check_item_not_in_list(lhs_list, allowed_versions)
}


deny = true if {
    Check_for_rds_instance_version_0
    print(sprintf("The version %v is not allowed, allowed versions are one of %v", [input["amazon.aws.rds_instance"].engine_version, allowed_versions]))
} else = false
