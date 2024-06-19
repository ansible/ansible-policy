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

import logging

from pyparsing import (
    Combine,
    Group,
    Keyword,
    Literal,
    OpAssoc,
    Optional,
    ParseException,
    ParserElement,
    QuotedString,
    Suppress,
    Word,
    ZeroOrMore,
    DelimitedList,
    Forward,
    alphanums,
    infix_notation,
    one_of,
    originalTextFor,
    pyparsing_common,
)

from ansible_rulebook.exception import (
    ConditionParsingException,
    SelectattrOperatorException,
    SelectOperatorException,
)

from typing import Dict

ParserElement.enable_packrat()

from ansible_rulebook.condition_types import (  # noqa: E402
    Boolean,
    Condition,
    Identifier,
    KeywordValue,
    NegateExpression,
    Null,
    OperatorExpression,
    SearchType,
    SelectattrType,
    SelectType,
    String,
    to_condition_type,
)

VALID_SELECT_ATTR_OPERATORS = [
    "==",
    "!=",
    ">",
    ">=",
    "<",
    "<=",
    "regex",
    "search",
    "match",
    "in",
    "not in",
    "contains",
    "not contains",
    "has key",
    "lacks key",
]

VALID_SELECT_OPERATORS = [
    "==",
    "!=",
    ">",
    ">=",
    "<",
    "<=",
    "regex",
    "search",
    "match",
]
SUPPORTED_SEARCH_KINDS = ("match", "regex", "search")

logger = logging.getLogger(__name__)


def as_list(var):
    if hasattr(var.__class__, "as_list"):
        return var.as_list()
    return var


def SelectattrTypeFactory(tokens):
    if tokens[1].value not in VALID_SELECT_ATTR_OPERATORS:
        raise SelectattrOperatorException(f"Operator {tokens[1]} is not supported")

    return SelectattrType(tokens[0], tokens[1], as_list(tokens[2]))


def SelectTypeFactory(tokens):
    if tokens[0].value not in VALID_SELECT_OPERATORS:
        raise SelectOperatorException(f"Operator {tokens[0]} is not supported")

    return SelectType(tokens[0], as_list(tokens[1]))


def SearchTypeFactory(kind, tokens):
    options = []
    if len(tokens) > 1:
        for i in range(1, len(tokens), 2):
            options.append(KeywordValue(String(tokens[i]), tokens[i + 1]))

    return SearchType(String(kind), tokens[0], options)


def OperatorExpressionFactory(tokens):
    return_value = None
    logger.debug(tokens)
    while tokens:
        if return_value is None:
            if (tokens[1] == "is" or tokens[1] == "is not") and (tokens[2] in SUPPORTED_SEARCH_KINDS):
                search_type = SearchTypeFactory(tokens[2], tokens[3])
                return_value = OperatorExpression(tokens[0], tokens[1], search_type)
                tokens = tokens[4:]
            elif tokens[2] == "selectattr":
                select_attr_type = SelectattrTypeFactory(tokens[3])
                return_value = OperatorExpression(tokens[0], tokens[1], select_attr_type)
                tokens = tokens[4:]
            elif tokens[2] == "select":
                select_type = SelectTypeFactory(tokens[3])
                return_value = OperatorExpression(tokens[0], tokens[1], select_type)
                tokens = tokens[4:]
            else:
                return_value = OperatorExpression(as_list(tokens[0]), tokens[1], as_list(tokens[2]))
                tokens = tokens[3:]
        else:
            return_value = OperatorExpression(return_value, tokens[0], tokens[1])
            tokens = tokens[2:]
    return return_value


def make_valid_prefix(vars: Dict):
    valid_prefix = Keyword("input")
    if not vars:
        return valid_prefix
    for prefix in vars.keys():
        valid_prefix |= Keyword(prefix)
    return valid_prefix


def define_condition(vars: Dict):
    number_t = pyparsing_common.number.copy().add_parse_action(lambda toks: to_condition_type(toks[0]))

    ident = pyparsing_common.identifier

    valid_prefix = make_valid_prefix(vars)
    varname = (
        Combine(
            valid_prefix
            + ZeroOrMore(
                ("." + ident)
                | (("[") + (originalTextFor(QuotedString('"')) | originalTextFor(QuotedString("'")) | pyparsing_common.signed_integer) + ("]"))
            )
        )
        .copy()
        .add_parse_action(lambda toks: Identifier(toks[0]))
    )
    true = Literal("true") | Literal("True")
    false = Literal("false") | Literal("False")
    boolean = (true | false).copy().add_parse_action(lambda toks: Boolean(toks[0].lower()))

    null_t = Literal("null").copy().add_parse_action(lambda toks: Null())

    string1 = QuotedString("'").copy().add_parse_action(lambda toks: String(toks[0]))
    string2 = QuotedString('"').copy().add_parse_action(lambda toks: String(toks[0]))

    plain_string = Word(alphanums + "_").copy().add_parse_action(lambda toks: String(toks[0]))
    allowed_values = number_t | boolean | null_t | string1 | string2
    key_value = ident + Suppress("=") + allowed_values
    string_search_t = (
        one_of("regex match search") + Suppress("(") + Group(Optional(DelimitedList(string1 | string2 | varname | key_value))) + Suppress(")")
    )

    list_values = Forward()

    allowed_values = number_t | boolean | null_t | string1 | string2

    delim_value = Group(DelimitedList(number_t | null_t | boolean | varname | string1 | string2 | list_values))

    list_values <<= Suppress("[") + delim_value + Suppress("]")

    selectattr_t = Literal("selectattr") + Suppress("(") + Group(DelimitedList(allowed_values | list_values | varname)) + Suppress(")")

    select_t = Literal("select") + Suppress("(") + Group(DelimitedList(allowed_values | list_values | varname)) + Suppress(")")

    all_terms = selectattr_t | select_t | string_search_t | list_values | number_t | null_t | boolean | varname | plain_string | string1 | string2

    condition = infix_notation(
        base_expr=all_terms,
        op_list=[
            (
                ">=",
                2,
                OpAssoc.LEFT,
                lambda toks: OperatorExpressionFactory(toks[0]),
            ),
            (
                "<=",
                2,
                OpAssoc.LEFT,
                lambda toks: OperatorExpressionFactory(toks[0]),
            ),
            (
                one_of("< >"),
                2,
                OpAssoc.LEFT,
                lambda toks: OperatorExpressionFactory(toks[0]),
            ),
            (
                "!=",
                2,
                OpAssoc.LEFT,
                lambda toks: OperatorExpressionFactory(toks[0]),
            ),
            (
                "==",
                2,
                OpAssoc.LEFT,
                lambda toks: OperatorExpressionFactory(toks[0]),
            ),
            (
                one_of(strs=["is not", "is"]),
                2,
                OpAssoc.LEFT,
                lambda toks: OperatorExpressionFactory(toks[0]),
            ),
            (
                one_of(
                    strs=["not in", "in", "not contains", "contains"],
                    caseless=True,
                    as_keyword=True,
                ),
                2,
                OpAssoc.LEFT,
                lambda toks: OperatorExpressionFactory(toks[0]),
            ),
            (
                one_of(
                    strs=["has key", "lacks key"],
                    caseless=True,
                    as_keyword=True,
                ),
                2,
                OpAssoc.LEFT,
                lambda toks: OperatorExpressionFactory(toks[0]),
            ),
            ("not", 1, OpAssoc.RIGHT, lambda toks: NegateExpression(*toks[0])),
            (
                one_of(["and", "or"]),
                2,
                OpAssoc.LEFT,
                lambda toks: OperatorExpressionFactory(toks[0]),
            ),
        ],
    ).add_parse_action(lambda toks: Condition(toks[0]))
    return condition


def parse_condition(condition_string: str, vars: Dict) -> Condition:
    condition = define_condition(vars)
    condition.debug = True
    condition.parseString(condition_string, parse_all=True)[0]
    try:
        return condition.parseString(condition_string, parse_all=True)[0]
    except ParseException as pe:
        msg = f"Error parsing: {condition_string}. {pe}"
        logger.debug(pe.explain(depth=0))
        raise ConditionParsingException(msg)


def main():
    test_condition_strings = [
        # not in
        'input["ansible.builtin.package"].name not in allowed_packages',
        # nested list
        'input["ansible.builtin.package"].name not in [[input["amazon.aws"], "A2"], "B", "C"]',
        # in
        'input["ansible.builtin.package"].name in input["ansible.builtin.package"].alist',
        # bool, multi_cond
        '"input.become == true and input.become_user not in allowed_users"',
        # lacks key
        '"input.become == true and input lacks key become_user"',
        # input._agk.xxx
        '"input._agk.task.module_info.collection not in allowed_collections"',
        # input["xxx"]
        'input["ansible.posix.firewalld"].service in banned_services',
        # "-"
        'input.become == true and input.become_user != "malicious-user"',
        'input["ansible.builtin.lineinfile"].line != \'DOCKER_OPTS="--dns"\'',
        # "*"
        'input.become == true and input.become_user != "*"',
        # "+"
        'input["ansible.builtin.package"].name != "package++"',
        # is not defined
        'input["kubernetes.core.k8s"].kubeconfig is not defined',
        # defined
        'input["kubernetes.core.k8s"].kubeconfig is defined',
    ]

    for s in test_condition_strings:
        print(f"condition string: \n{s}\n")
        r = parse_condition(s)
        print(f"parse result:\n{r}\n\n")


if __name__ == "__main__":
    main()
