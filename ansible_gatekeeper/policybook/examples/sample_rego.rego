package example

# allowed_packages = []

using_unauthorized_module = true if {
    input.task.module == "custom.unauthorized.package"
} else = false


deny = true if {
    using_unauthorized_module
    print(sprintf("The package %v is not allowed", input.task.module))
} else = false
