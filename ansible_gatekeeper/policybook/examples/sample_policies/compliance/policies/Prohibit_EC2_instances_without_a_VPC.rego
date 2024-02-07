package Prohibit_EC2_instances_without_a_VPC


import future.keywords.if
import future.keywords.in
import data.ansible_gatekeeper.resolve_var


__tags__ = ["compliance"]



Prohibit_EC2_instances_without_a_VPC_0 = true if {
    
}


deny = true if {
    Prohibit_EC2_instances_without_a_VPC_0
    print("creating EC2 instances without a VPC is prohibited. specify vpc_subnet_id.")
} else = false
