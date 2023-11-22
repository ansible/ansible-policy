package sample_ansible_policy

import future.keywords.if
import future.keywords.in
import data.ansible_gatekeeper.resolve_var

_allowed_databases = ["allowed-db-1", "allowed-db-2"]

is_allowed_db(task) {
    fqcn := task.module_fqcn
    fqcn == "community.mongodb.mongodb_user"
    database := resolve_var(task.module_options.database, input.variables)
    database in _allowed_databases
}

using_forbidden_database = true if {
    some i
    task := input.playbooks[_].tasks[i]
    task.module_fqcn == "community.mongodb.mongodb_user"
    not is_allowed_db(task)
} else = false

detected_forbidden_databases = [
    resolve_var(task.module_options.database, input.variables) | task := input.playbooks[_].tasks[_]; task.module_fqcn == "community.mongodb.mongodb_user"; not is_allowed_db(task)
]
