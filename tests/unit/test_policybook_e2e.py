import json
import subprocess
import os
import glob
from ansible_policy.policybook.transpiler import PolicyTranspiler

INPUT_PASS = "input_pass.json"
INPUT_FAIL = "input_fail.json"
POLICYBOOK = "policybook.yml"


def get_rego_main_package_name(rego_path: str):
    pkg_name = ""
    with open(rego_path, "r") as file:
        prefix = "package "
        for line in file:
            _line = line.strip()
            if _line.startswith(prefix):
                pkg_name = _line[len(prefix) :]
                break
    return pkg_name


def run_rego(rego_path, input_path):
    rego_pkg_name = get_rego_main_package_name(rego_path)
    cmd_str = f"opa eval --data {rego_path} --input {input_path} 'data.{rego_pkg_name}'"
    proc = subprocess.run(
        cmd_str,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.returncode != 0:
        error = f"failed to run `opa eval` command; error details:\nSTDOUT: {proc.stdout}\nSTDERR: {proc.stderr}"
        raise ValueError(error)
    result = json.loads(proc.stdout)
    return result


def get_eval_result(output, action="allow"):
    result = output.get("result", [])
    if not result:
        return ValueError("no result found")
    expressions = result[0].get("expressions", [])
    if expressions:
        return expressions[0].get("value", {}).get(action)
    else:
        return ValueError("no result found")


transpiler = PolicyTranspiler()
test_source_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "integration")


class TestTranspiler:
    def get_test_result(self, target_dir):
        target_dir = os.path.join(test_source_dir, "in_operator")
        input_policybook = os.path.join(target_dir, POLICYBOOK)
        input_pass = os.path.join(target_dir, INPUT_PASS)
        input_fail = os.path.join(target_dir, INPUT_FAIL)
        transpiler.run(input_policybook, target_dir)
        pattern = f"{target_dir}/**/*.rego"
        _found = glob.glob(pattern, recursive=True)
        rego = _found[0]
        result = get_eval_result(run_rego(rego, input_pass))
        assert result
        result = get_eval_result(run_rego(rego, input_fail))
        assert not result

    def test_in_operator(self):
        target_dir = os.path.join(test_source_dir, "in_operator")
        self.get_test_result(target_dir)

    def test_not_in_operator(self):
        target_dir = os.path.join(test_source_dir, "not_in_operator")
        self.get_test_result(target_dir)

    def test_int_equal_operator(self):
        target_dir = os.path.join(test_source_dir, "int_equal_operator")
        self.get_test_result(target_dir)

    def test_str_equal_operator(self):
        target_dir = os.path.join(test_source_dir, "str_equal_operator")
        self.get_test_result(target_dir)

    def test_null_not_equal_operator(self):
        target_dir = os.path.join(test_source_dir, "null_not_equal_operator")
        self.get_test_result(target_dir)

    def test_item_in_list_operator(self):
        target_dir = os.path.join(test_source_dir, "item_in_list_operator")
        self.get_test_result(target_dir)

    def test_item_not_in_list_operator(self):
        target_dir = os.path.join(test_source_dir, "item_not_in_list_operator")
        self.get_test_result(target_dir)

    def test_list_contains_operator(self):
        target_dir = os.path.join(test_source_dir, "list_contains_operator")
        self.get_test_result(target_dir)

    def test_list_not_contains_operator(self):
        target_dir = os.path.join(test_source_dir, "list_not_contains_operator")
        self.get_test_result(target_dir)

    def test_is_defined_operator(self):
        target_dir = os.path.join(test_source_dir, "is_defined_operator")
        self.get_test_result(target_dir)

    def test_negate_operator(self):
        target_dir = os.path.join(test_source_dir, "negate_operator")
        self.get_test_result(target_dir)

    def test_affirm_operator(self):
        target_dir = os.path.join(test_source_dir, "affirm_operator")
        self.get_test_result(target_dir)

    def test_search_operator(self):
        target_dir = os.path.join(test_source_dir, "search_operator")
        self.get_test_result(target_dir)

    def test_not_search_operator(self):
        target_dir = os.path.join(test_source_dir, "not_search_operator")
        self.get_test_result(target_dir)

    def test_match_operator(self):
        target_dir = os.path.join(test_source_dir, "match_operator")
        self.get_test_result(target_dir)

    def test_not_match_operator(self):
        target_dir = os.path.join(test_source_dir, "not_match_operator")
        self.get_test_result(target_dir)

    def test_regex_operator(self):
        target_dir = os.path.join(test_source_dir, "regex_operator")
        self.get_test_result(target_dir)

    def test_not_regex_operator(self):
        target_dir = os.path.join(test_source_dir, "not_regex_operator")
        self.get_test_result(target_dir)

    def test_select_search_operator(self):
        target_dir = os.path.join(test_source_dir, "select_search_operator")
        self.get_test_result(target_dir)

    def test_select_compare_operator(self):
        target_dir = os.path.join(test_source_dir, "select_compare_operator")
        self.get_test_result(target_dir)

    def test_not_select_search_operator(self):
        target_dir = os.path.join(test_source_dir, "not_select_search_operator")
        self.get_test_result(target_dir)

    def test_not_select_compare_operator(self):
        target_dir = os.path.join(test_source_dir, "not_select_compare_operator")
        self.get_test_result(target_dir)

    def test_selectattr_search_operator(self):
        target_dir = os.path.join(test_source_dir, "selectattr_search_operator")
        self.get_test_result(target_dir)

    def test_selectattr_compare_operator(self):
        target_dir = os.path.join(test_source_dir, "selectattr_compare_operator")
        self.get_test_result(target_dir)

    def test_not_selectattr_search_operator(self):
        target_dir = os.path.join(test_source_dir, "not_selectattr_search_operator")
        self.get_test_result(target_dir)

    def test_not_selectattr_compare_operator(self):
        target_dir = os.path.join(test_source_dir, "not_selectattr_compare_operator")
        self.get_test_result(target_dir)

    def test_multi_condition_any(self):
        target_dir = os.path.join(test_source_dir, "multi_condition_any")
        self.get_test_result(target_dir)

    def test_multi_condition_all(self):
        target_dir = os.path.join(test_source_dir, "multi_condition_all")
        self.get_test_result(target_dir)

    def test_multi_condition_notall(self):
        target_dir = os.path.join(test_source_dir, "multi_condition_notall")
        self.get_test_result(target_dir)
