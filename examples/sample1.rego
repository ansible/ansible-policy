package sample_ansible_policy

import future.keywords.if
import future.keywords.in

_allowed_databases = ["allowed-db-1", "allowed-db-2"]

resolve(db_ref, vars) := name {
    db_var_name_0 := db_ref
    db_var_name_1 = replace(db_var_name_0, "{{", "")
    db_var_name_2 = replace(db_var_name_1, "}}", "")
    db_var_name = replace(db_var_name_2, " ", "")
    name := vars[db_var_name]
}

is_allowed_db(task) {
    fqcn := task.module_fqcn
    fqcn == "community.mongodb.mongodb_user"
    database := resolve(task.module_options.database, input.variables)
    database in _allowed_databases
}

using_forbidden_database = true if {
    some i
    task := input.playbooks[_].tasks[i]
    task.module_fqcn == "community.mongodb.mongodb_user"
    not is_allowed_db(task)
} else = false

detected_forbidden_databases = [
    resolve(task.module_options.database, input.variables) | task := input.playbooks[_].tasks[_]; task.module_fqcn == "community.mongodb.mongodb_user"; not is_allowed_db(task)
]
