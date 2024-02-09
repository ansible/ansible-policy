import string

# action func
deny = """
deny = true if {
    ${steps}
} else = false
"""

allow = """
allow = true if {
    ${steps}
} else = false
"""

if_func = """
${func_name} = true if {
    ${steps}
}
"""

# rego operation templates
item_not_in_list_condition = """lhs_list = to_list(${lhs})
    check_item_not_in_list(lhs_list, ${rhs})"""

item_in_list_condition = """lhs_list = to_list(${lhs})
    check_item_in_list(lhs_list, ${rhs})"""

key_in_dict_condition = """${lhs}
    input_keys := [key | ${lhs}[key]; key == ${rhs}]
    count(input_keys) > 0"""

key_not_in_dict_condition = """${lhs}
    input_keys := [key | ${lhs}[key]; key == ${rhs}]
    count(input_keys) == 0"""

# rego util funcs
item_not_in_list_func = """
check_item_not_in_list(lhs_list, rhs_list) = true if {
    array := [item | item := lhs_list[_]; not item in rhs_list]
    count(array) > 0
} else = false
"""

item_in_list_func = """
check_item_in_list(lhs_list, rhs_list) = true if {
    array := [item | item := lhs_list[_]; item in rhs_list]
    count(array) > 0
} else = false
"""

to_list_func = """
to_list(val) = output if {
    is_array(val)
    output = val
}

to_list(val) = output if {
    not is_array(val)
    output = [val]
}
"""


class TemplateManager:
    def __init__(self):
        self.templates = {}
        # action func
        self._deny_func = self.add_template(deny)
        self._allow_func = self.add_template(allow)
        # condition func
        self._if_func = self.add_template(if_func)
        # operation
        self._item_not_in_list_expression = self.add_template(item_not_in_list_condition)
        self._item_in_list_expression = self.add_template(item_in_list_condition)
        self._key_in_dict_expression = self.add_template(key_in_dict_condition)
        self._key_not_in_dict_expression = self.add_template(key_not_in_dict_condition)
        # util funcs
        self._item_not_in_list_func = item_not_in_list_func
        self._item_in_list_func = item_in_list_func
        self._to_list_func = to_list_func

    def add_template(self, template):
        return string.Template(template)
