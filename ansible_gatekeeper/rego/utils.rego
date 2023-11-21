# util functions that can be imported by rego policies executed from ansible-gatekeeper

package ansible_gatekeeper

has_key(x, key) { _ = x[key] }

# trial1: when task.module is FQCN
get_module_fqcn(task) := fqcn {
    has_key(data.galaxy.modules, task.module)
    fqcn := data.galaxy.modules[task.module].fqcn
}

# trial2: when task.module is a valid short name
get_module_fqcn(task) := fqcn {
    not has_key(data.galaxy.modules, task.module)
    has_key(data.galaxy.module_name_mappings, task.module)
    fqcn := data.galaxy.module_name_mappings[task.module][0]
}

request_http_data_source(url) := ext_data {
    resp := http.send({
        "method": "get",
        "headers": {
            "Content-Type": "application/json"
        },
        "url": url
    })
    ext_data := resp.body
}
