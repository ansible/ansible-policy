package sample_ansible_policy

import future.keywords.if
import future.keywords.in

_allowed_databases = ["allowed-db-1", "allowed-db-2"]

is_allowed_db(task) {
    fqcn := task.module_fqcn
    fqcn == "community.mongodb.mongodb_user"
    database := task.module_options.database
    database in _allowed_databases
}

using_forbidden_database = true if {
    some i
    task := input.playbooks[_].tasks[i]
    task.module_fqcn == "community.mongodb.mongodb_user"
    not is_allowed_db(task)
} else = false

detected_forbidden_databases = [
    task.module_options.database | task := input.playbooks[_].tasks[_]; task.module_fqcn == "community.mongodb.mongodb_user"; not is_allowed_db(task)
]
