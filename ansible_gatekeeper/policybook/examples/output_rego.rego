package Check_for_mysql_package_installation


import future.keywords.if
import future.keywords.in
import data.ansible_gatekeeper.resolve_var


allowed_packages = ['mysql']

Check_for_package_name = true if {
    input.task.module == custom.unauthorized.package
} else = false


