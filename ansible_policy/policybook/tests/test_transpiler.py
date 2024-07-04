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
ast1 = {"EqualsExpression": {"lhs": {"Input": "input.range.i"}, "rhs": {"Integer": 1}}}
rego1 = """
test = true if {
    input.range.i == 1
}
"""

ast2 = {
    "EqualsExpression": {
        "lhs": {"Input": "input.become_user"},
        "rhs": {"String": "malicious-user"},
    }
}
rego2 = """
test = true if {
    input.become_user == "malicious-user"
}
"""


def test_equal():
    assert rego1 == et.EqualsExpression.make_rego("test", ast1)
    assert rego2 == et.EqualsExpression.make_rego("test", ast2)


##
# LessThanExpression and LessThanOrEqualToExpression
##
ast3 = {
    "LessThanExpression": {
        "lhs": {"Input": "input.range.i"},
        "rhs": {"Integer": 1},
    }
}

rego3 = """
test = true if {
    input.range.i < 1
}
"""

ast4 = {
    "LessThanOrEqualToExpression": {
        "lhs": {"Input": "input.range.i"},
        "rhs": {"Integer": 1},
    }
}

rego4 = """
test = true if {
    input.range.i <= 1
}
"""


def test_less_than():
    assert rego3 == et.LessThanExpression.make_rego("test", ast3)
    assert rego4 == et.LessThanOrEqualToExpression.make_rego("test", ast4)


##
# IsDefinedExpression and IsNotDefinedExpression
##
ast5 = {"IsNotDefinedExpression": {"Input": "input.become_user"}}
rego5 = """
test = true if {
    input
    not input.become_user
}
"""


def test_defined():
    assert rego5 == et.IsNotDefinedExpression.make_rego("test", ast5)


##
# OrExpression, AnyCondition, AndExpression, AllCondition
##
rego6 = """
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

rego7 = """
test = true if {
    condition1
    condition2
    condition3
}
"""


def test_combination():
    assert rego6 == et.OrAnyExpression.make_rego("test", ["condition1", "condition2", "condition3"])
    assert rego7 == et.AndAllExpression.make_rego("test", ["condition1", "condition2", "condition3"])
