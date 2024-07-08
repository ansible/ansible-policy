#  Copyright 2022 Red Hat, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from ansible_policy.policybook.expressioin_transpiler import ExpressionTranspiler

et = ExpressionTranspiler()

##
# EqualsExpression
##
ast_equal_1 = {"EqualsExpression": {"lhs": {"Input": "input.range.i"}, "rhs": {"Integer": 1}}}
rego_equal_1 = """
test = true if {
    input.range.i == 1
}
"""

ast_equal_2 = {
    "EqualsExpression": {
        "lhs": {"Input": "input.become_user"},
        "rhs": {"String": "malicious-user"},
    }
}
rego_equal_2 = """
test = true if {
    input.become_user == "malicious-user"
}
"""


def test_Equals():
    assert rego_equal_1 == et.EqualsExpression.make_rego("test", ast_equal_1)
    assert rego_equal_2 == et.EqualsExpression.make_rego("test", ast_equal_2)


##
# NotEqualsExpression
##
ast_notequal_1 = {"NotEqualsExpression": {"lhs": {"Input": "input.range.i"}, "rhs": {"Integer": 0}}}
rego_notequal_1 = """
test = true if {
    input.range.i != 0
}
"""

ast_notequal_2 = {
    "NotEqualsExpression": {
        "lhs": {"Input": "input.become_user"},
        "rhs": {"String": "malicious-user"},
    }
}
rego_notequal_2 = """
test = true if {
    input.become_user != "malicious-user"
}
"""


def test_NotEquals():
    assert rego_notequal_1 == et.NotEqualsExpression.make_rego("test", ast_notequal_1)
    assert rego_notequal_2 == et.NotEqualsExpression.make_rego("test", ast_notequal_2)


##
# ItemInListExpression and ItemNotInListExpression
##
ast_ItemInList_1 = {
    "ItemInListExpression": {
        "lhs": {"Input": "input.i"},
        "rhs": [{"Integer": 1}, {"Integer": 2}, {"Integer": 3}],
    }
}

rego_ItemInList_1 = """
test = true if {
    lhs_list = to_list(input.i)
    check_item_in_list(lhs_list, [1, 2, 3])
}
"""

ast_ItemNotInList_1 = {
    "ItemNotInListExpression": {
        "lhs": {"Input": "input.i"},
        "rhs": [{"Integer": 1}, {"Integer": 2}, {"Integer": 3}],
    }
}

rego_ItemNotInList_1 = """
test = true if {
    lhs_list = to_list(input.i)
    check_item_not_in_list(lhs_list, [1, 2, 3])
}
"""


def test_ItemInList():
    assert rego_ItemInList_1 == et.ItemInListExpression.make_rego("test", ast_ItemInList_1)
    assert rego_ItemNotInList_1 == et.ItemNotInListExpression.make_rego("test", ast_ItemNotInList_1)


##
# ListContainsItemExpression and ListNotContainsItemExpression
##
# TODO: 本当にregoあっている？？
ast_ListContainsItem_1 = {
    "ListContainsItemExpression": {
        "lhs": {"Input": "input.mylist"},
        "rhs": {"Integer": 1},
    }
}

rego_ListContainsItem_1 = """
test = true if {
    lhs_list = to_list(1)
    check_item_in_list(lhs_list, input.mylist)
}
"""

ast_ListNotContainsItem_1 = {
    "ListNotContainsItemExpression": {
        "lhs": {"Input": "input.mylist"},
        "rhs": {"Integer": 1},
    }
}

rego_ListNotContainsItem_1 = """
test = true if {
    lhs_list = to_list(1)
    check_item_not_in_list(lhs_list, input.mylist)
}
"""


def test_ListContainsItem():
    assert rego_ListContainsItem_1 == et.ListContainsItemExpression.make_rego("test", ast_ListContainsItem_1)
    assert rego_ListNotContainsItem_1 == et.ListNotContainsItemExpression.make_rego("test", ast_ListNotContainsItem_1)


##
# KeyInDictExpression and KeyNotInDictExpression
##
# TODO: 本当にregoあっている？？
ast_KeyInDict_1 = {
    "KeyInDictExpression": {
        "lhs": {"Input": "input.friends"},
        "rhs": {"String": "fred"},
    }
}

rego_KeyInDict_1 = """
test = true if {
    input.friends
    input_keys := [key | input.friends[key]; key == "fred"]
    count(input_keys) > 0
}
"""

ast_KeyNotInDict_1 = {
    "KeyNotInDictExpression": {
        "lhs": {"Input": "input.friends"},
        "rhs": {"String": "fred"},
    }
}

rego_KeyNotInDict_1 = """
test = true if {
    input.friends
    input_keys := [key | input.friends[key]; key == "fred"]
    count(input_keys) == 0
}
"""


def test_KeyInDict():
    assert rego_KeyInDict_1 == et.KeyInDictExpression.make_rego("test", ast_KeyInDict_1)
    assert rego_KeyNotInDict_1 == et.KeyNotInDictExpression.make_rego("test", ast_KeyNotInDict_1)


##
# IsDefinedExpression and IsNotDefinedExpression
##
ast_IsDefined_1 = {"IsDefinedExpression": {"Input": "input.range.i"}}

rego_IsDefined_1 = """
test = true if {
    input.range
    input.range.i
}
"""

ast_IsNotDefined_1 = {"IsNotDefinedExpression": {"Input": "input.range.i"}}

rego_IsNotDefined_1 = """
test = true if {
    input.range
    not input.range.i
}
"""


def test_IsDefined():
    assert rego_IsDefined_1 == et.IsDefinedExpression.make_rego("test", ast_IsDefined_1)
    assert rego_IsNotDefined_1 == et.IsNotDefinedExpression.make_rego("test", ast_IsNotDefined_1)


##
# GreaterThanExpression and GreaterThanOrEqualToExpression
##
ast_GreaterThan_1 = {
    "GreaterThanExpression": {
        "lhs": {"Input": "input.range.i"},
        "rhs": {"Integer": 1},
    }
}

rego_GreaterThan_1 = """
test = true if {
    input.range.i > 1
}
"""

ast_GreaterThanOrEqualTo_1 = {
    "GreaterThanOrEqualToExpression": {
        "lhs": {"Input": "input.range.i"},
        "rhs": {"Integer": 1},
    }
}

rego_GreaterThanOrEqualTo_1 = """
test = true if {
    input.range.i >= 1
}
"""


def test_GreaterThan():
    assert rego_GreaterThan_1 == et.GreaterThanExpression.make_rego("test", ast_GreaterThan_1)
    assert rego_GreaterThanOrEqualTo_1 == et.GreaterThanOrEqualToExpression.make_rego("test", ast_GreaterThanOrEqualTo_1)


##
# LessThanExpression and LessThanOrEqualToExpression
##
ast_LessThan_1 = {
    "LessThanExpression": {
        "lhs": {"Input": "input.range.i"},
        "rhs": {"Integer": 1},
    }
}

rego_LessThan_1 = """
test = true if {
    input.range.i < 1
}
"""

ast_LessThanOrEqualTo_1 = {
    "LessThanOrEqualToExpression": {
        "lhs": {"Input": "input.range.i"},
        "rhs": {"Integer": 1},
    }
}

rego_LessThanOrEqualTo_1 = """
test = true if {
    input.range.i <= 1
}
"""


def test_LessThan_than():
    assert rego_LessThan_1 == et.LessThanExpression.make_rego("test", ast_LessThan_1)
    assert rego_LessThanOrEqualTo_1 == et.LessThanOrEqualToExpression.make_rego("test", ast_LessThanOrEqualTo_1)


##
# OrExpression, AnyCondition, AndExpression, AllCondition
##
rego_OrAny = """
test = true if {
    condition1
}

test = true if {
    condition2
}

test = true if {
    condition3
}
"""

rego_AndAll = """
test = true if {
    condition1
    condition2
    condition3
}
"""


def test_combination():
    assert rego_OrAny == et.OrAnyExpression.make_rego("test", ["condition1", "condition2", "condition3"])
    assert rego_AndAll == et.AndAllExpression.make_rego("test", ["condition1", "condition2", "condition3"])
