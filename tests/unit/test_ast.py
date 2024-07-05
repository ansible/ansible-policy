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

import os

import pytest
import yaml

from ansible_policy.policybook.condition_parser import parse_condition
from ansible_rulebook.exception import (
    SelectattrOperatorException,
    SelectOperatorException,
)
from ansible_policy.policybook.json_generator import (
    generate_dict_policysets,
    visit_condition,
)
from ansible_policy.policybook.policy_parser import parse_policy_sets

HERE = os.path.dirname(os.path.abspath(__file__))


def test_parse_condition():
    assert {"Input": "input.data"} == visit_condition(parse_condition("input.data", {}))
    assert {"Variable": "var1"} == visit_condition(parse_condition("var1", {"var1": "val1"}))
    assert {"Boolean": True} == visit_condition(parse_condition("True", {}))
    assert {"Boolean": False} == visit_condition(parse_condition("False", {}))
    assert {"Integer": 42} == visit_condition(parse_condition("42", {}))
    assert {"Float": 3.1415} == visit_condition(parse_condition("3.1415", {}))
    assert {"String": "Hello"} == visit_condition(parse_condition("'Hello'", {}))
    assert {"EqualsExpression": {"lhs": {"Input": "input.range.i"}, "rhs": {"Integer": 1}}} == visit_condition(
        parse_condition("input.range.i == 1", {})
    )
    assert {"EqualsExpression": {"lhs": {"Input": "input['i']"}, "rhs": {"Integer": 1}}} == visit_condition(parse_condition("input['i'] == 1", {}))
    assert {
        "EqualsExpression": {
            "lhs": {"Input": "input.range.pi"},
            "rhs": {"Float": 3.1415},
        }
    } == visit_condition(parse_condition("input.range.pi == 3.1415", {}))
    assert {
        "GreaterThanExpression": {
            "lhs": {"Input": "input.range.i"},
            "rhs": {"Integer": 1},
        }
    } == visit_condition(parse_condition("input.range.i > 1", {}))

    assert {
        "EqualsExpression": {
            "lhs": {"Input": "input.range['pi']"},
            "rhs": {"Float": 3.1415},
        }
    } == visit_condition(parse_condition("input.range['pi'] == 3.1415", {}))
    assert {
        "EqualsExpression": {
            "lhs": {"Input": 'input.range["pi"]'},
            "rhs": {"Float": 3.1415},
        }
    } == visit_condition(parse_condition('input.range["pi"] == 3.1415', {}))

    assert {
        "EqualsExpression": {
            "lhs": {"Input": 'input.range["pi"].value'},
            "rhs": {"Float": 3.1415},
        }
    } == visit_condition(parse_condition('input.range["pi"].value == 3.1415', {}))
    assert {
        "EqualsExpression": {
            "lhs": {"Input": "input.range[0]"},
            "rhs": {"Float": 3.1415},
        }
    } == visit_condition(parse_condition("input.range[0] == 3.1415", {}))
    assert {
        "EqualsExpression": {
            "lhs": {"Input": "input.range[-1]"},
            "rhs": {"Float": 3.1415},
        }
    } == visit_condition(parse_condition("input.range[-1] == 3.1415", {}))

    assert {
        "EqualsExpression": {
            "lhs": {"Input": 'input.range["x"][1][2].a["b"]'},
            "rhs": {"Float": 3.1415},
        }
    } == visit_condition(parse_condition('input.range["x"][1][2].a["b"] == 3.1415', {}))

    assert {
        "EqualsExpression": {
            "lhs": {"Input": "input.become_user"},
            "rhs": {"String": "malicious-user"},
        }
    } == visit_condition(parse_condition('input.become_user == "malicious-user"', {}))

    assert {
        "NegateExpression": {
            "Input": "input.enabled",
        }
    } == visit_condition(parse_condition("not input.enabled", {}))

    assert {
        "NegateExpression": {
            "LessThanExpression": {
                "lhs": {"Input": "input.range.i"},
                "rhs": {"Integer": 1},
            }
        }
    } == visit_condition(parse_condition("not (input.range.i < 1)", {}))

    assert {
        "LessThanExpression": {
            "lhs": {"Input": "input.range.i"},
            "rhs": {"Integer": 1},
        }
    } == visit_condition(parse_condition("input.range.i < 1", {}))

    assert {
        "NegateExpression": {
            "Variable": "enabled",
        }
    } == visit_condition(parse_condition("not enabled", {"enabled": True}))

    assert {
        "NegateExpression": {
            "LessThanExpression": {
                "lhs": {"Input": "input.range.i"},
                "rhs": {"Integer": 1},
            }
        }
    } == visit_condition(parse_condition("not (input.range.i < 1)", {}))
    assert {
        "LessThanOrEqualToExpression": {
            "lhs": {"Input": "input.range.i"},
            "rhs": {"Integer": 1},
        }
    } == visit_condition(parse_condition("input.range.i <= 1", {}))
    assert {
        "GreaterThanOrEqualToExpression": {
            "lhs": {"Input": "input.range.i"},
            "rhs": {"Integer": 1},
        }
    } == visit_condition(parse_condition("input.range.i >= 1", {}))
    assert {
        "EqualsExpression": {
            "lhs": {"Input": "input.range.i"},
            "rhs": {"String": "Hello"},
        }
    } == visit_condition(parse_condition("input.range.i == 'Hello'", {}))

    assert {"IsDefinedExpression": {"Input": "input.range.i"}} == visit_condition(parse_condition("input.range.i is defined", {}))
    assert {"IsNotDefinedExpression": {"Input": "input.range.i"}} == visit_condition(parse_condition("input.range.i is not defined", {}))

    assert {"IsNotDefinedExpression": {"Input": "input.range.i"}} == visit_condition(parse_condition("(input.range.i is not defined)", {}))

    assert {"IsNotDefinedExpression": {"Input": "input.range.i"}} == visit_condition(parse_condition("(((input.range.i is not defined)))", {}))
    assert {
        "OrExpression": {
            "lhs": {"IsNotDefinedExpression": {"Input": "input.range.i"}},
            "rhs": {"IsDefinedExpression": {"Input": "input.range.i"}},
        }
    } == visit_condition(parse_condition("(input.range.i is not defined) or (input.range.i is defined)", {}))
    assert {
        "AndExpression": {
            "lhs": {"IsNotDefinedExpression": {"Input": "input.range.i"}},
            "rhs": {"IsDefinedExpression": {"Input": "input.range.i"}},
        }
    } == visit_condition(parse_condition("(input.range.i is not defined) and (input.range.i is defined)", {}))
    assert {
        "AndExpression": {
            "lhs": {
                "AndExpression": {
                    "lhs": {"IsNotDefinedExpression": {"Input": "input.range.i"}},
                    "rhs": {"IsDefinedExpression": {"Input": "input.range.i"}},
                }
            },
            "rhs": {
                "EqualsExpression": {
                    "lhs": {"Input": "input.range.i"},
                    "rhs": {"Integer": 1},
                }
            },
        }
    } == visit_condition(parse_condition("(input.range.i is not defined) and (input.range.i is defined) " "and (input.range.i == 1)", {}))
    assert {
        "OrExpression": {
            "lhs": {
                "AndExpression": {
                    "lhs": {"IsNotDefinedExpression": {"Input": "input.range.i"}},
                    "rhs": {"IsDefinedExpression": {"Input": "input.range.i"}},
                }
            },
            "rhs": {
                "EqualsExpression": {
                    "lhs": {"Input": "input.range.i"},
                    "rhs": {"Integer": 1},
                }
            },
        }
    } == visit_condition(parse_condition("(input.range.i is not defined) and (input.range.i is defined) or (input.range.i == 1)", {}))

    assert {
        "AndExpression": {
            "lhs": {"IsNotDefinedExpression": {"Input": "input.range.i"}},
            "rhs": {
                "OrExpression": {
                    "lhs": {"IsDefinedExpression": {"Input": "input.range.i"}},
                    "rhs": {
                        "EqualsExpression": {
                            "lhs": {"Input": "input.range.i"},
                            "rhs": {"Integer": 1},
                        }
                    },
                }
            },
        }
    } == visit_condition(parse_condition("(input.range.i is not defined) and " "((input.range.i is defined) or (input.range.i == 1))", {}))

    assert {
        "ItemInListExpression": {
            "lhs": {"Input": "input.i"},
            "rhs": [{"Integer": 1}, {"Integer": 2}, {"Integer": 3}],
        }
    } == visit_condition(parse_condition("input.i in [1,2,3]", {}))

    assert {
        "ItemInListExpression": {
            "lhs": {"Input": "input.name"},
            "rhs": [
                {"String": "fred"},
                {"String": "barney"},
                {"String": "wilma"},
            ],
        }
    } == visit_condition(parse_condition("input.name in ['fred','barney','wilma']", {}))

    assert {
        "ItemInListExpression": {
            "lhs": {"Input": 'input["ansible.builtin.package"].name'},
            "rhs": [[{"String": "A1"}, {"String": "A2"}], {"String": "B"}, {"String": "C"}],
        }
    } == visit_condition(parse_condition('input["ansible.builtin.package"].name in [["A1", "A2"], "B", "C"]', {}))

    assert {
        "ItemNotInListExpression": {
            "lhs": {"Input": "input.i"},
            "rhs": [{"Integer": 1}, {"Integer": 2}, {"Integer": 3}],
        }
    } == visit_condition(parse_condition("input.i not in [1,2,3]", {}))

    assert {
        "ItemNotInListExpression": {
            "lhs": {"Input": "input['ansible.builtin.package'].name"},
            "rhs": [
                {"String": "fred"},
                {"String": "barney"},
                {"String": "wilma"},
            ],
        }
    } == visit_condition(parse_condition("input['ansible.builtin.package'].name not in ['fred','barney','wilma']", {}))
    assert {
        "ItemNotInListExpression": {
            "lhs": {"Input": "input.radius"},
            "rhs": [
                {"Float": 1079.6234},
                {"Float": 3985.8},
                {"Float": 2106.1234},
            ],
        }
    } == visit_condition(parse_condition("input.radius not in [1079.6234,3985.8,2106.1234]", {}))

    assert {
        "ItemNotInListExpression": {
            "lhs": {"Input": "input._agk.task.module_info.collection"},
            "rhs": {"Variable": "allowed_collections"},
        }
    } == visit_condition(
        parse_condition("input._agk.task.module_info.collection not in allowed_collections", {"allowed_collections": ["ansible.builtin"]})
    )

    assert {
        "ListContainsItemExpression": {
            "lhs": {"Input": "input.mylist"},
            "rhs": {"Integer": 1},
        }
    } == visit_condition(parse_condition("input.mylist contains 1", {}))

    assert {
        "ListContainsItemExpression": {
            "lhs": {"Input": "input.friends"},
            "rhs": {"String": "fred"},
        }
    } == visit_condition(parse_condition("input.friends contains 'fred'", {}))

    assert {
        "ListNotContainsItemExpression": {
            "lhs": {"Input": "input.mylist"},
            "rhs": {"Integer": 1},
        }
    } == visit_condition(parse_condition("input.mylist not contains 1", {}))

    assert {
        "ListNotContainsItemExpression": {
            "lhs": {"Input": "input.friends"},
            "rhs": {"String": "fred"},
        }
    } == visit_condition(parse_condition("input.friends not contains 'fred'", {}))

    assert {
        "KeyInDictExpression": {
            "lhs": {"Input": "input.friends"},
            "rhs": {"String": "fred"},
        }
    } == visit_condition(parse_condition("input.friends has key 'fred'", {}))

    assert {
        "KeyNotInDictExpression": {
            "lhs": {"Input": "input.friends"},
            "rhs": {"String": "fred"},
        }
    } == visit_condition(parse_condition("input.friends lacks key 'fred'", {}))

    assert {
        "SearchMatchesExpression": {
            "lhs": {"Input": "input['url']"},
            "rhs": {
                "SearchType": {
                    "kind": {"String": "match"},
                    "pattern": {"String": "https://example.com/users/.*/resources"},
                    "options": [
                        {
                            "name": {"String": "ignorecase"},
                            "value": {"Boolean": True},
                        }
                    ],
                }
            },
        }
    } == visit_condition(parse_condition("input['url'] is " + 'match("https://example.com/users/.*/resources", ' + "ignorecase=true)", {}))
    assert {
        "SearchMatchesExpression": {
            "lhs": {"Input": "input.url"},
            "rhs": {
                "SearchType": {
                    "kind": {"String": "match"},
                    "pattern": {"String": "https://example.com/users/.*/resources"},
                    "options": [
                        {
                            "name": {"String": "ignorecase"},
                            "value": {"Boolean": True},
                        }
                    ],
                }
            },
        }
    } == visit_condition(parse_condition("input.url is " + 'match("https://example.com/users/.*/resources", ' + "ignorecase=true)", {}))

    assert {
        "SearchNotMatchesExpression": {
            "lhs": {"Input": "input.url"},
            "rhs": {
                "SearchType": {
                    "kind": {"String": "match"},
                    "pattern": {"String": "https://example.com/users/.*/resources"},
                    "options": [
                        {
                            "name": {"String": "ignorecase"},
                            "value": {"Boolean": True},
                        }
                    ],
                }
            },
        }
    } == visit_condition(parse_condition("input.url is not " + 'match("https://example.com/users/.*/resources",ignorecase=true)', {}))
    assert {
        "SearchMatchesExpression": {
            "lhs": {"Input": "input.url"},
            "rhs": {
                "SearchType": {
                    "kind": {"String": "regex"},
                    "pattern": {"String": "example.com/foo"},
                    "options": [
                        {
                            "name": {"String": "ignorecase"},
                            "value": {"Boolean": True},
                        }
                    ],
                }
            },
        }
    } == visit_condition(parse_condition('input.url is regex("example.com/foo",ignorecase=true)', {}))

    assert {
        "SelectAttrExpression": {
            "lhs": {"Input": "input.persons"},
            "rhs": {
                "key": {"String": "person.age"},
                "operator": {"String": ">="},
                "value": {"Integer": 50},
            },
        }
    } == visit_condition(parse_condition('input.persons is selectattr("person.age", ">=", 50)', {}))

    assert {
        "SelectAttrExpression": {
            "lhs": {"Input": "input.persons"},
            "rhs": {
                "key": {"String": "person.employed"},
                "operator": {"String": "=="},
                "value": {"Boolean": True},
            },
        }
    } == visit_condition(parse_condition('input.persons is selectattr("person.employed", "==", true)', {}))

    assert {
        "SelectAttrNotExpression": {
            "lhs": {"Input": "input.persons"},
            "rhs": {
                "key": {"String": "person.name"},
                "operator": {"String": "=="},
                "value": {"String": "fred"},
            },
        }
    } == visit_condition(parse_condition('input.persons is not selectattr("person.name", "==", "fred")', {}))

    assert {
        "SelectExpression": {
            "lhs": {"Input": "input.ids"},
            "rhs": {"operator": {"String": ">="}, "value": {"Integer": 10}},
        }
    } == visit_condition(parse_condition('input.ids is select(">=", 10)', {}))

    assert {
        "SelectNotExpression": {
            "lhs": {"Input": "input.persons"},
            "rhs": {
                "operator": {"String": "regex"},
                "value": {"String": "fred|barney"},
            },
        }
    } == visit_condition(
        parse_condition('input.persons is not select("regex", "fred|barney")', {}),
    )

    assert {
        "SelectExpression": {
            "lhs": {"Input": "input.is_true"},
            "rhs": {"operator": {"String": "=="}, "value": {"Boolean": False}},
        }
    } == visit_condition(parse_condition('input.is_true is select("==", False)', {}))

    assert {
        "SelectExpression": {
            "lhs": {"Input": "input.my_list"},
            "rhs": {
                "operator": {"String": "=="},
                "value": {"Input": "input.my_int"},
            },
        }
    } == visit_condition(parse_condition("input.my_list is select('==', input.my_int)", {}))

    assert {
        "SelectExpression": {
            "lhs": {"Input": "input.my_list"},
            "rhs": {
                "operator": {"String": "=="},
                "value": {"Variable": "my_int"},
            },
        }
    } == visit_condition(parse_condition("input.my_list is select('==', my_int)", {"my_int": 42}))

    assert {
        "SelectAttrExpression": {
            "lhs": {"Input": "input.persons"},
            "rhs": {
                "key": {"String": "person.age"},
                "operator": {"String": ">"},
                "value": {"Variable": "minimum_age"},
            },
        }
    } == visit_condition(parse_condition("input.persons is selectattr('person.age', '>', minimum_age)", dict(minimum_age=42)))


def test_invalid_select_operator():
    with pytest.raises(SelectOperatorException):
        parse_condition('input.persons is not select("in", ["fred","barney"])', {})


def test_invalid_selectattr_operator():
    with pytest.raises(SelectattrOperatorException):
        parse_condition('input.persons is not selectattr("name", "cmp", "fred")', {})


def test_null_type():
    assert {
        "EqualsExpression": {
            "lhs": {"Input": "input.friend"},
            "rhs": {"NullType": None},
        }
    } == visit_condition(parse_condition("input.friend == null", {}))


@pytest.mark.parametrize(
    "policybook",
    [
        "policies_with_multiple_conditions.yml",
        "policies_with_multiple_conditions2.yml",
        "policies_with_multiple_conditions3.yml",
        "policies_with_multiple_conditions4.yml",
    ],
)
def test_generate_dict_policysets(policybook):

    os.chdir(HERE)
    with open(os.path.join("policybooks", policybook)) as f:
        data = yaml.safe_load(f.read())

    policyset = generate_dict_policysets(parse_policy_sets(data))
    print(yaml.dump(policyset))

    with open(os.path.join("asts", policybook)) as f:
        ast = yaml.safe_load(f.read())

    assert policyset == ast
