package Check_for_file_change


import future.keywords.if
import future.keywords.in
import data.ansible_gatekeeper.resolve_var


__tags__ = ["compliance"]



Check_for_file_change_0 = true if {
    input["ansible.builtin.file"].mode != "444"
}


deny = true if {
    Check_for_file_change_0
    print(sprintf("The file permission %v is not allowed", [input["ansible.builtin.file"].mode]))
} else = false
