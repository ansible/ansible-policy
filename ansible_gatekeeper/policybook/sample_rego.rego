package example

# allowed_packages = []

using_unauthorized_module = true if {
    input.task.module == "custom.unauthorized.package"
} else = false
