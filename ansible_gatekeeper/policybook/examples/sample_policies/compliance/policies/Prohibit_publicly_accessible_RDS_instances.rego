package Prohibit_publicly_accessible_RDS_instances


import future.keywords.if
import future.keywords.in
import data.ansible_gatekeeper.resolve_var


__target__ = "task"
__tags__ = ["compliance"]



Prohibit_publicly_accessible_RDS_instances_0 = true if {
    input["amazon.aws.rds_instance"].publicly_accessible
}


deny = true if {
    Prohibit_publicly_accessible_RDS_instances_0
    print("it is not allowed to create publicly accessible RDS instances")
} else = false
