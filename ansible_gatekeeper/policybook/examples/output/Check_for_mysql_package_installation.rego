package Check_for_mysql_package_installation


import future.keywords.if
import future.keywords.in
import data.ansible_gatekeeper.resolve_var


allowed_packages = ['mysql']

Check_for_package_name = true if {
    input.task.module == custom.unauthorized.package
} else = false




deny = true if {
    Check_for_package_name
    print(sprintf("The package %v is not allowed", input.task.module ))
} else = false


