# util functions that can be imported by rego policies executed from ansible-policy
package ansible_policy

has_key(x, key) if { _ = x[key] }

# trial1: when task.module is FQCN
get_module_fqcn(task) := fqcn if {
    has_key(data.galaxy.modules, task.module)
    fqcn := data.galaxy.modules[task.module].fqcn
}

# trial2: when task.module is a valid short name
get_module_fqcn(task) := fqcn if {
    not has_key(data.galaxy.modules, task.module)
    has_key(data.galaxy.module_name_mappings, task.module)
    fqcn := data.galaxy.module_name_mappings[task.module][0]
}

request_http_data_source(url) := ext_data if {
    resp := http.send({
        "method": "get",
        "headers": {
            "Content-Type": "application/json"
        },
        "url": url
    })
    ext_data := resp.body
}

_find_playbook_by_task(task) := playbook_key if {
    playbook := input._agk.playbooks[_]
    current_task = playbook.tasks[_]
    current_task.key == task.key
    playbook_key := playbook.key
}

_find_taskfile_by_task(task) := taskfile_key if {
    taskfile := input._agk.taskfiles[_]
    current_task = taskfile.tasks[_]
    current_task.key == task.key
    taskfile_key := taskfile.key
}

_find_entrypoint_by_task(task) := playbook_key if {
    playbook_key := _find_playbook_by_task(task)
    playbook_key
}

_find_entrypoint_by_task(task) := taskfile_key if {
    taskfile_key := _find_taskfile_by_task(task)
    taskfile_key
}

resolve_var(ref, task) := var_value if {
    var_name_tmp1 := replace(ref, "{{", "")
    var_name_tmp2 := replace(var_name_tmp1, "}}", "")
    var_name := replace(var_name_tmp2, " ", "")
    entrypoint_key := _find_entrypoint_by_task(task)
    variables := input._agk.variables[entrypoint_key]
    var_value := variables[var_name]
}
