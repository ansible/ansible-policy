import string

# action func
action_func = """
${func_name} = true if {
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

args_is_not_defined_condition = """${val1}
    not ${val2}"""

args_is_defined_condition = """${val1}
    ${val2}"""

var_is_not_defined_condition = """not ${val1}"""

var_is_defined_condition = """${val1}"""

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
        self._action_func = self.add_template(action_func)
        # condition func
        self._if_func = self.add_template(if_func)
        # operation
        self._item_not_in_list_expression = self.add_template(item_not_in_list_condition)
        self._item_in_list_expression = self.add_template(item_in_list_condition)
        self._key_in_dict_expression = self.add_template(key_in_dict_condition)
        self._key_not_in_dict_expression = self.add_template(key_not_in_dict_condition)
        self._args_is_not_defined_expression = self.add_template(args_is_not_defined_condition)
        self._args_is_defined_expression = self.add_template(args_is_defined_condition)
        self._var_is_not_defined_expression = self.add_template(var_is_not_defined_condition)
        self._var_is_defined_expression = self.add_template(var_is_defined_condition)
        # util funcs
        self._item_not_in_list_func = item_not_in_list_func
        self._item_in_list_func = item_in_list_func
        self._to_list_func = to_list_func

    def add_template(self, template):
        return string.Template(template)
