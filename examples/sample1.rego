package sample_ansible_policy

import future.keywords.if
import future.keywords.in
import data.ansible_gatekeeper.get_module_fqcn
import data.ansible_gatekeeper.request_http_data_source

using_not_allowed_database = true if {
    some i, j
    task := input.playbooks[i].tasks[j]
    fqcn := get_module_fqcn(task)
    fqcn == "community.mongodb.mongodb_user"
    database := task.module_options.database
    allowed_databases := request_http_data_source("http://localhost:3780/list-allowed-databases")
    not database in allowed_databases
} else = false
