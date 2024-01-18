
package mongodb_user_db_policy

import future.keywords.if
import future.keywords.in
import data.ansible_gatekeeper.resolve_var

__target_module__ = "community.mongodb.mongodb_user"
__tags__ = ["security"]


_allowed_databases = []

database := db_name {
    db_name := resolve_var(input._agk.task.module_options.database, input._agk.task)
}

using_forbidden_database = true if {
    database != ""
    not database in _allowed_databases
} else = false


