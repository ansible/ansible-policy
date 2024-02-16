package Check_for_using_become_in_play


import future.keywords.if
import future.keywords.in
import data.ansible_gatekeeper.resolve_var


__target__ = "play"
__tags__ = ["compliance"]


allowed_users = ["trusted_user"]

to_list(val) = output if {
    is_array(val)
    output = val
}

to_list(val) = output if {
    not is_array(val)
    output = [val]
}


check_item_not_in_list(lhs_list, rhs_list) = true if {
    array := [item | item := lhs_list[_]; not item in rhs_list]
    count(array) > 0
} else = false


Check_for_using_become_in_play_0 = true if {
    input.become
    lhs_list = to_list(input.become_user)
    check_item_not_in_list(lhs_list, allowed_users)
}


Check_for_using_become_in_play_0 = true if {
    input.become
    input
    input_keys := [key | input[key]; key == "become_user"]
    count(input_keys) == 0
}


deny = true if {
    Check_for_using_become_in_play_0
    print(sprintf("privilage escalation is detected. allowed users are one of %v", [allowed_users]))
} else = false
