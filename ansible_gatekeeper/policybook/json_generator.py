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

"""Generate condition AST from Ansible condition."""

from typing import List

from ansible_rulebook.condition_types import (
    Boolean,
    Condition,
    ConditionTypes,
    Float,
    Identifier,
    Integer,
    KeywordValue,
    NegateExpression,
    Null,
    OperatorExpression,
    SearchType,
    SelectattrType,
    SelectType,
    String,
)
from ansible_rulebook.exception import (
    InvalidAssignmentException,
    InvalidIdentifierException,
)
from ansible_gatekeeper.policybook.policybook_models import (
    Action,
    Condition as RuleCondition,
    Policy,
    PolicySet,
)


OPERATOR_MNEMONIC = {
    "!=": "NotEqualsExpression",
    "==": "EqualsExpression",
    "and": "AndExpression",
    "or": "OrExpression",
    ">": "GreaterThanExpression",
    "<": "LessThanExpression",
    ">=": "GreaterThanOrEqualToExpression",
    "<=": "LessThanOrEqualToExpression",
    "+": "AdditionExpression",
    "-": "SubtractionExpression",
    "<<": "AssignmentExpression",
    "in": "ItemInListExpression",
    "not in": "ItemNotInListExpression",
    "contains": "ListContainsItemExpression",
    "not contains": "ListNotContainsItemExpression",
    "has key": "KeyInDictExpression",
    "lacks key": "KeyNotInDictExpression",
}


def visit_condition(parsed_condition: ConditionTypes):
    """Visit the condition and generate the AST."""
    if isinstance(parsed_condition, list):
        return [visit_condition(c) for c in parsed_condition]
    elif isinstance(parsed_condition, Condition):
        return visit_condition(parsed_condition.value)
    elif isinstance(parsed_condition, Boolean):
        return {"Boolean": True} if parsed_condition.value == "true" else {"Boolean": False}
    elif isinstance(parsed_condition, Identifier):
        if parsed_condition.value.startswith("fact."):
            return {"Fact": parsed_condition.value[5:]}
        elif parsed_condition.value.startswith("fact["):
            return {"Fact": parsed_condition.value[4:]}
        elif parsed_condition.value.startswith("event."):
            return {"Event": parsed_condition.value[6:]}
        elif parsed_condition.value.startswith("event["):
            return {"Event": parsed_condition.value[5:]}
        elif parsed_condition.value.startswith("events."):
            return {"Events": parsed_condition.value[7:]}
        elif parsed_condition.value.startswith("facts."):
            return {"Facts": parsed_condition.value[6:]}
        else:
            msg = f"Invalid identifier : {parsed_condition.value} " + "Should start with event., events.,fact., facts. or vars."
            raise InvalidIdentifierException(msg)

    elif isinstance(parsed_condition, String):
        return {"String": parsed_condition.value}
    elif isinstance(parsed_condition, Null):
        return {"NullType": None}
    elif isinstance(parsed_condition, Integer):
        return {"Integer": parsed_condition.value}
    elif isinstance(parsed_condition, Float):
        return {"Float": parsed_condition.value}
    elif isinstance(parsed_condition, SearchType):
        data = dict(
            kind=visit_condition(parsed_condition.kind),
            pattern=visit_condition(parsed_condition.pattern),
        )
        if parsed_condition.options:
            data["options"] = [visit_condition(v) for v in parsed_condition.options]
        return {"SearchType": data}
    elif isinstance(parsed_condition, SelectattrType):
        return dict(
            key=visit_condition(parsed_condition.key),
            operator=visit_condition(parsed_condition.operator),
            value=visit_condition(parsed_condition.value),
        )
    elif isinstance(parsed_condition, SelectType):
        return dict(
            operator=visit_condition(parsed_condition.operator),
            value=visit_condition(parsed_condition.value),
        )
    elif isinstance(parsed_condition, KeywordValue):
        return dict(
            name=visit_condition(parsed_condition.name),
            value=visit_condition(parsed_condition.value),
        )
    elif isinstance(parsed_condition, OperatorExpression):
        if parsed_condition.operator == "<<":
            validate_assignment_expression(parsed_condition.left.value)

        if parsed_condition.operator in OPERATOR_MNEMONIC:
            return create_binary_node(
                OPERATOR_MNEMONIC[parsed_condition.operator],
                parsed_condition,
            )
        elif parsed_condition.operator == "is":
            if isinstance(parsed_condition.right, String):
                if parsed_condition.right.value == "defined":
                    return {"IsDefinedExpression": visit_condition(parsed_condition.left)}
            elif isinstance(parsed_condition.right, SearchType):
                return create_binary_node("SearchMatchesExpression", parsed_condition)
            elif isinstance(parsed_condition.right, SelectattrType):
                return create_binary_node("SelectAttrExpression", parsed_condition)
            elif isinstance(parsed_condition.right, SelectType):
                return create_binary_node("SelectExpression", parsed_condition)
        elif parsed_condition.operator == "is not":
            if isinstance(parsed_condition.right, String):
                if parsed_condition.right.value == "defined":
                    return {"IsNotDefinedExpression": visit_condition(parsed_condition.left)}
            elif isinstance(parsed_condition.right, SearchType):
                return create_binary_node("SearchNotMatchesExpression", parsed_condition)
            elif isinstance(parsed_condition.right, SelectattrType):
                return create_binary_node("SelectAttrNotExpression", parsed_condition)
            elif isinstance(parsed_condition.right, SelectType):
                return create_binary_node("SelectNotExpression", parsed_condition)
        else:
            raise Exception(f"Unhandled token {parsed_condition}")
    elif isinstance(parsed_condition, NegateExpression):
        return {"NegateExpression": visit_condition(parsed_condition.value)}
    else:
        raise Exception(f"Unhandled token {parsed_condition}")


def create_binary_node(name, parsed_condition):
    return {
        name: {
            "lhs": visit_condition(parsed_condition.left),
            "rhs": visit_condition(parsed_condition.right),
        }
    }


def visit_policy(parsed_policy: Policy):
    data = {
        "name": parsed_policy.name,
        "target": parsed_policy.target,
        "condition": generate_condition(parsed_policy.condition),
        "actions": visit_actions(parsed_policy.actions),
        "enabled": parsed_policy.enabled,
        "tags": parsed_policy.tags,
    }

    return {"Policy": data}


def visit_actions(actions: List[Action]):
    return [visit_action(a) for a in actions]


def visit_action(parsed_action: Action):
    return {
        "Action": {
            "action": parsed_action.action,
            "action_args": parsed_action.action_args,
        }
    }


def generate_condition(ansible_condition: RuleCondition):
    """Generate the condition AST."""
    condition = visit_condition(ansible_condition.value)
    if ansible_condition.when == "any":
        data = {"AnyCondition": condition}
    elif ansible_condition.when == "all":
        data = {"AllCondition": condition}
    elif ansible_condition.when == "not_all":
        data = {"NotAllCondition": condition}
    else:
        data = {"AllCondition": condition}

    return data


def visit_policyset(policyset: PolicySet):
    """Generate JSON compatible rules."""
    data = {
        "name": policyset.name,
        "hosts": policyset.hosts,
        "policies": [visit_policy(pol) for pol in policyset.policies],
        "vars": policyset.vars,
    }

    return {"PolicySet": data}


def generate_dict_policysets(policysets: List[PolicySet]):
    """Generate JSON compatible policysets."""
    return [visit_policyset(policyset) for policyset in policysets]


def validate_assignment_expression(value):
    tokens = value.split(".")
    if len(tokens) != 2:
        msg = (
            f"Assignment variable: {value} is invalid."
            + "Valid values start with events or facts. e.g events.var1 "
            + "or facts.var1 "
            + "Where var1 can only contain alpha numeric and _ charachters"
        )
        raise InvalidAssignmentException(msg)

    if tokens[0] not in ["events", "facts"]:
        msg = "Only events and facts can be used in assignment. " + f"{value} is invalid."
        raise InvalidAssignmentException(msg)
