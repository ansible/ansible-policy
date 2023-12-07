package sample_ansible_policy

import future.keywords.if
import future.keywords.in

requirements_yml = [req.name | req := input.project.requirements.collections[_]]
_builtin_and_deps := array.concat(["ansible.builtin"], requirements_yml)

detect_missing_dependencies(task) := collection {
    fqcn := task.module_fqcn
    collection := get_module_collection_name(fqcn)
    not collection in _builtin_and_deps
}

get_module_collection_name(fqcn) := coll {
    contains(fqcn, ".")
    parts := split(fqcn, ".")
    coll := concat(".", [parts[0], parts[1]])
}

missing_dependencies[x] {
    task := input.taskfiles[_].tasks[_]
    x := detect_missing_dependencies(task)
}

has_missing_dependencies = true if {
    count(missing_dependencies) > 0
} else = false
