from typing import Any, Dict, List, Optional
import policybook_models as pm
from condition_parser import parse_condition as parse_condition_value


def parse_hosts(hosts):
    if isinstance(hosts, str):
        return [hosts]
    elif isinstance(hosts, list):
        return hosts
    else:
        raise Exception(f"Unsupported hosts value {hosts}")


def parse_vars(vars):
    if isinstance(vars, dict):
        return vars
    else:
        raise Exception(f"unsupported vars value {vars}. vars should be defined by dict.")


def parse_policy_sets(policy_sets: Dict) -> List[pm.PolicySet]:
    policy_set_list = []
    policyset_names = []
    for policy_set in policy_sets:
        name = policy_set.get("name")
        if name is None:
            raise Exception("Policyset name not provided")

        name = name.strip()
        if name == "":
            raise Exception(
                "Policyset name cannot be an empty string"
            )

        if name in policyset_names:
            raise Exception(
                f"Policy with name: {name} defined multiple times"
            )

        policyset_names.append(name)

        policy_set_list.append(
            pm.PolicySet(
                name=name,
                hosts=parse_hosts(policy_set["hosts"]),
                vars=parse_vars(policy_set.get("vars", {})),
                policies=parse_policies(policy_set.get("policies", {})),
                match_multiple_policies=policy_set.get(
                    "match_multiple_policies", False
                ),
            )
        )
    return policy_set_list


def parse_policies(policies: Dict) -> List[pm.Policy]:
    pol_list = []
    pol_names = []

    for pol in policies:
        name = pol.get("name")
        if name is None:
            raise Exception("Policy name not provided")

        if name == "":
            raise Exception("Policy name cannot be an empty string")

        if name in pol_names:
            raise Exception(
                f"Policy with name {name} defined multiple times"
            )

        tags = pol.get("tags", [])
        target = pol.get("target")
        if target is None:
            raise Exception("Policy target not provided")
        if target == "":
            raise Exception("Policy target cannot be an empty string")
        pol_names.append(name)

        parsed_pol = pm.Policy(
            name=name,
            condition=parse_condition(pol["condition"]),
            actions=parse_actions(pol),
            enabled=pol.get("enabled", True),
            tags=tags,
            target=target
        )
        if parsed_pol.enabled:
            pol_list.append(parsed_pol)

    return pol_list


def parse_condition(condition: Any) -> pm.Condition:
    if isinstance(condition, str):
        return pm.Condition("all", [parse_condition_value(condition)])
    elif isinstance(condition, bool):
        return pm.Condition("all", [parse_condition_value(str(condition))])
    elif isinstance(condition, dict):
        keys = list(condition.keys())
        if len(condition) == 1 and keys[0] in ["any", "all", "not_all"]:
            when = keys[0]
            return pm.Condition(
                when,
                [parse_condition_value(str(c)) for c in condition[when]],
            )
        else:
            raise Exception(
                f"Condition should have one of any, all, not_all: {condition}"
            )
    else:
        raise Exception(f"Unsupported condition {condition}")


def parse_actions(rule: Dict) -> List[pm.Action]:
    actions = []
    if "actions" in rule:
        for action in rule["actions"]:
            actions.append(parse_action(action))
    elif "action" in rule:
        actions.append(parse_action(rule["action"]))

    return actions


def parse_action(action: Dict) -> pm.Action:
    action_name = list(action.keys())[0]
    if action[action_name]:
        action_args = {k: v for k, v in action[action_name].items()}
    else:
        action_args = {}
    return pm.Action(action=action_name, action_args=action_args)



