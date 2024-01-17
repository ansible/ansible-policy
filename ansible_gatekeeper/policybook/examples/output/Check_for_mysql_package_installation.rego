package Check_for_mysql_package_installation


import future.keywords.if
import future.keywords.in
import data.ansible_gatekeeper.resolve_var


__tags__ = ["compliance"]


allowed_packages = ["mysql"]

Check_for_package_name = true if {
    not input.task.module in allowed_packages
} else = false


deny = true if {
    Check_for_package_name
    print(sprintf("The package %v is not allowed, allowed packages are one of %v", input.task.module ))
} else = false
