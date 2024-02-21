import os
import sys
import re
import glob
import tempfile
import shutil
from dataclasses import dataclass, field
from typing import List, Union

from ansible_gatekeeper.rego_data import (
    Task,
    Play,
    PolicyInput,
    load_input_from_jobdata,
    load_input_from_project_dir,
    process_input_data_with_external_data,
)
from ansible_gatekeeper.utils import (
    init_logger,
    install_galaxy_collection,
    transpile_yml_policy,
    match_str_expression,
    get_tags_from_rego_policy_file,
    detect_target_module_pattern,
    detect_target_type_pattern,
    get_rego_main_package_name,
    validate_opa_installation,
    eval_opa_policy,
    match_target_module,
    match_target_type,
    find_task_line_number,
    find_play_line_number,
)


logger = init_logger(__name__, os.getenv("ANSIBLE_GK_LOG_LEVEL", "info"))

field_re = r"\[([a-zA-Z0-9._\-]+)\]"
policy_pattern_re = r"[ ]*([^ #]*)[ ]+(tag[ ]?=[ ]?[^ ]+)?.*(enabled|disabled).*"
source_pattern_re = r"[ ]*([^ #]*)[ ]*=[ ]*([^ ]+)([ ]+type[ ]?=[ ]?[^ ]+)?.*"

default_policy_install_dir = "/tmp/ansible-gatekeeper/installed_policies"

EvalTypeJobdata = "jobdata"
EvalTypeProject = "project"


@dataclass
class PolicyPattern(object):
    name: str = ""
    tags: str | list = None
    enabled: bool = None

    @staticmethod
    def load(line: str):
        matched = re.match(policy_pattern_re, line)
        if not matched:
            return None
        pp = PolicyPattern()
        name = matched.group(1)
        tags_raw = matched.group(2)
        enabled_raw = matched.group(3)
        tags = None
        if tags_raw:
            tags = tags_raw.replace(" ", "").split("=")[-1].split(",")
        enabled = True if enabled_raw == "enabled" else False if enabled_raw == "disabled" else None
        # special name
        if name == "default":
            name = "*"
        pp.name = name
        pp.tags = tags
        pp.enabled = enabled
        return pp

    def check_enabled(self, filepath: str, policy_root_dir: str):
        relative = os.path.relpath(filepath, policy_root_dir)
        parts = relative.split("/")
        policy_source_name = parts[0]
        # if name pattern does not match, just ignore this pattern by returning None
        if not match_str_expression(self.name, policy_source_name):
            return None
        # otherwise, this pattern matches the policy filepath at least in terms of its source name
        # then checks matching in detail
        if self.tags:
            pattern_tags = set()
            if isinstance(self.tags, str):
                pattern_tags.add(self.tags)
            elif isinstance(self.tags, list):
                pattern_tags = set(self.tags)

            tags = get_tags_from_rego_policy_file(policy_path=filepath)
            # it tag is specified for this pattern but the policy file does not have any tag,
            # this pattern is not related to the policy
            if not tags:
                return None
            # otherwise, checks if any tags are matched with this pattern or not

            matched_tags = pattern_tags.intersection(set(tags))
            if not matched_tags:
                return None

        return self.enabled


@dataclass
class Source(object):
    name: str = ""
    source: str = ""
    type: str = ""

    @staticmethod
    def load(line: str):
        matched = re.match(source_pattern_re, line)
        if not matched:
            return None
        name = matched.group(1)
        _source = matched.group(2)
        _type_raw = matched.group(3)
        _type = ""
        if _type_raw:
            _type = _type_raw.replace(" ", "").split("=")[-1]
        else:
            if "/" in _source and not _source.endswith(".tar.gz"):
                _type = "path"
            else:
                _type = "galaxy"
        source = Source()
        source.name = name
        source.source = _source
        source.type = _type
        return source

    def install(self, install_root_dir: str = "", force: bool = False):
        target_dir = os.path.join(install_root_dir, self.name)
        exists = False
        if os.path.exists(target_dir) and len(os.listdir(target_dir)) > 0:
            exists = True
        if exists and not force:
            return None

        logger.info(f"Installing policies `{self.name}` to `{target_dir}`")

        installed_path = None
        if self.type == "path":
            with tempfile.TemporaryDirectory() as tmp_dir:
                shutil.copytree(src=self.source, dst=tmp_dir, dirs_exist_ok=True)
                os.makedirs(target_dir, exist_ok=True)
                shutil.copytree(src=tmp_dir, dst=target_dir, dirs_exist_ok=True)
                installed_path = target_dir
        elif self.type == "galaxy":
            with tempfile.TemporaryDirectory() as tmp_dir:
                install_galaxy_collection(name=self.source, target_dir=tmp_dir)
                os.makedirs(target_dir, exist_ok=True)
                shutil.copytree(src=tmp_dir, dst=target_dir, dirs_exist_ok=True)
                installed_path = target_dir
        else:
            raise ValueError(f"`{self.type}` is not a supported policy type")

        if installed_path:
            transpiler = Transpiler()
            yml_policy_files = transpiler.search_target(policy_dir=installed_path)
            if yml_policy_files:
                policy_num = len(yml_policy_files)
                logger.debug(f"Transpiling {policy_num} policis")
                transpiler.run(yml_policy_files=yml_policy_files)

        return installed_path


@dataclass
class PolicyConfig(object):
    patterns: List[PolicyPattern] = field(default_factory=list)

    @staticmethod
    def from_lines(lines: list):
        config = PolicyConfig()
        for line in lines:
            # skip a line which is not setting `enabled`/`disabled`
            if "enabled" not in line and "disabled" not in line:
                continue
            pattern = PolicyPattern.load(line)
            if not pattern:
                continue
            config.patterns.append(pattern)
        return config


@dataclass
class SourceConfig(object):
    sources: list = field(default_factory=list)

    @staticmethod
    def from_lines(lines: list):
        config = SourceConfig()
        for line in lines:
            source = Source.load(line)
            if not source:
                continue
            config.sources.append(source)
        return config


_mapping = {
    "policy": PolicyConfig,
    "source": SourceConfig,
}


@dataclass
class Config(object):
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    source: SourceConfig = field(default_factory=SourceConfig)

    def __post_init__(self):
        pass

    @staticmethod
    def load(filepath: str):
        config = Config()
        config_lines = {}
        current_field = ""
        with open(filepath, "r") as file:
            for line in file:
                _line = line.strip()
                if not _line:
                    continue

                matched = re.match(field_re, _line)
                if matched:
                    current_field = matched.group(1)
                    config_lines[current_field] = []
                else:
                    config_lines[current_field].append(_line)
        for _field, lines in config_lines.items():
            if _field not in _mapping:
                raise ValueError(f"`{_field}` is an unknown field name in a config file")
            _cls = _mapping[_field]
            single_config = _cls.from_lines(lines=lines)
            setattr(config, _field, single_config)
        return config


@dataclass
class CodeBlock(object):
    begin: int = None
    end: int = None

    @staticmethod
    def dict2str(line_dict: dict):
        block = CodeBlock.from_dict(line_dict=line_dict)
        return str(block)

    @classmethod
    def from_str(cls, line_str: str):
        if line_str.startswith("L") and "-" in line_str:
            parts = line_str.replace("L", "").split("-")
            block = cls()
            block.begin = parts[0]
            block.end = parts[1]
            return block

        raise ValueError(f"failed to construct a CodeBlock from the string `{line_str}`")

    @classmethod
    def from_dict(cls, line_dict: dict):
        if "begin" in line_dict and "end" in line_dict:
            block = cls()
            block.begin = line_dict["begin"]
            block.end = line_dict["end"]
            return block

        raise ValueError(f"failed to construct a CodeBlock from the dict `{line_dict}`")

    def __repr__(self):
        if not isinstance(self.begin, int):
            raise ValueError("`begin` is not found for this code block")

        if not isinstance(self.end, int):
            raise ValueError("`end` is not found for this code block")

        return f"L{self.begin}-{self.end}"

    def to_dict(self):
        return {"begin": self.begin, "end": self.end}


@dataclass
class LineIdentifier(object):
    def find_block(self, body: str, obj: Union[Task, Play]) -> CodeBlock:
        if not body:
            return None

        if not isinstance(obj, (Task, Play)):
            raise TypeError(f"find a code block for {type(obj)} object is not supported")

        if isinstance(obj, Task):
            task = obj
            _, lines = find_task_line_number(
                yaml_body=body,
                task_name=task.name,
                module_name=task.module,
                module_options=task.module_options,
                task_options=task.options,
            )
            if lines and len(lines) == 2:
                return CodeBlock(begin=lines[0], end=lines[1])

        elif isinstance(obj, Play):
            play = obj
            _, lines = find_play_line_number(
                yaml_body=body,
                play_name=play.name,
                play_options=play.options,
            )
            if lines and len(lines) == 2:
                return CodeBlock(begin=lines[0], end=lines[1])

        return None


@dataclass
class Transpiler(object):
    def search_target(self, policy_dir: str):
        yml_policy_pattern = os.path.join(policy_dir, "**", "policies/*.yml")
        found_files = glob.glob(pathname=yml_policy_pattern, recursive=True)
        return found_files

    def run(self, yml_policy_files: list):
        for yml_policy_path in yml_policy_files:
            dst_path = os.path.splitext(yml_policy_path)[0] + ".rego"
            transpile_yml_policy(src=yml_policy_path, dst=dst_path)


class ResultType:
    OK = "OK"
    NG = "NG"
    N_A = "N/A"

    @staticmethod
    def from_eval_result(eval_result: dict, is_target_type: bool):
        if not is_target_type:
            return ResultType.N_A

        eval_result_value = eval_result.get("value", {})
        violation = False
        if "deny" in eval_result_value:
            if eval_result_value["deny"]:
                violation = True
        elif "allow" in eval_result_value:
            if not eval_result_value["allow"]:
                violation = True
        if violation:
            return ResultType.NG
        else:
            return ResultType.OK


@dataclass
class TargetResult(object):
    name: str = None
    lines: dict = field(default_factory=dict)
    result: str = None
    message: str = None


@dataclass
class PolicyResult(object):
    policy_name: str = None
    target_type: str = None
    violation: bool = False
    targets: List[TargetResult] = field(default_factory=list)

    def add_target_result(self, obj: any, lines: dict, result: str, message: str):
        target_name = getattr(obj, "name", None)
        target = TargetResult(name=target_name, lines=lines, result=result, message=message)
        if result == ResultType.NG:
            self.violation = True
        self.targets.append(target)


@dataclass
class FileResult(object):
    path: str = None
    violation: bool = False
    policies: List[PolicyResult] = field(default_factory=list)

    def add_policy_result(
        self,
        eval_result: dict,
        is_target_type: bool,
        policy_name: str,
        target_type: str,
        obj: any,
        lines: dict,
    ):
        policy_result = self.get_policy_result(policy_name=policy_name)
        need_append = False
        result_str = ResultType.from_eval_result(eval_result=eval_result, is_target_type=is_target_type)
        message = eval_result.get("message")
        if not policy_result:
            policy_result = PolicyResult(
                policy_name=policy_name,
                target_type=target_type,
            )
            need_append = True
        if is_target_type:
            policy_result.add_target_result(obj=obj, lines=lines, result=result_str, message=message)
        if need_append:
            self.policies.append(policy_result)

        if any([p.violation for p in self.policies]):
            self.violation = True
        return

    def get_policy_result(self, policy_name: str):
        for p in self.policies:
            if p.policy_name == policy_name:
                return p
        return None


@dataclass
class EvaluationSummary(object):
    policies: dict = field(default_factory=dict)
    files: dict = field(default_factory=dict)

    @staticmethod
    def from_files(files: List[FileResult]):
        total_files = len(files)
        file_names = []
        violation_files = 0
        policy_names = []
        violation_policy_names = []
        for f in files:
            for p in f.policies:
                if p.policy_name not in policy_names:
                    policy_names.append(p.policy_name)
                if p.violation and p.policy_name not in violation_policy_names:
                    violation_policy_names.append(p.policy_name)
            if f.violation:
                violation_files += 1
            if f.path not in file_names:
                file_names.append(f.path)
        total_policies = len(policy_names)
        violation_policies = len(violation_policy_names)
        policies_data = {
            "total": total_policies,
            "violation_detected": violation_policies,
            "list": policy_names,
        }
        files_data = {
            "total": total_files,
            "OK": total_files - violation_files,
            "NG": violation_files,
            "list": file_names,
        }
        return EvaluationSummary(
            policies=policies_data,
            files=files_data,
        )


@dataclass
class EvaluationResult(object):
    summary: EvaluationSummary = None
    files: List[FileResult] = field(default_factory=list)

    def add_single_result(
        self,
        eval_result: dict,
        is_target_type: bool,
        policy_name: str,
        target_type: str,
        obj: any,
        filepath: str,
        lines: dict,
    ):
        file_result = self.get_file_result(filepath=filepath)
        need_append = False
        if not file_result:
            file_result = FileResult(path=filepath)
            need_append = True

        file_result.add_policy_result(
            eval_result=eval_result,
            is_target_type=is_target_type,
            policy_name=policy_name,
            target_type=target_type,
            obj=obj,
            lines=lines,
        )
        if need_append:
            self.files.append(file_result)

        self.summary = EvaluationSummary.from_files(self.files)
        return

    def get_file_result(self, filepath: str):
        for f in self.files:
            if f.path == filepath:
                return f
        return None


@dataclass
class PolicyEvaluator(object):
    config_path: str = ""
    root_dir: str = ""

    patterns: List[PolicyPattern] = field(default_factory=list)
    sources: List[Source] = field(default_factory=list)

    def __post_init__(self):
        validate_opa_installation()

        if self.config_path:
            cfg = Config.load(filepath=self.config_path)
            self.patterns = cfg.policy.patterns
            self.sources = cfg.source.sources

        if not self.root_dir:
            self.root_dir = default_policy_install_dir

        installed_path_list = []
        if self.sources:
            for source in self.sources:
                installed_path = source.install(
                    install_root_dir=self.root_dir,
                    force=False,
                )
                if installed_path:
                    installed_path_list.append(installed_path)
        return

    def list_enabled_policies(self):
        policy_dir = self.root_dir
        rego_policy_pattern = os.path.join(policy_dir, "**", "policies/*.rego")
        found_files = glob.glob(pathname=rego_policy_pattern, recursive=True)
        # sort patterns by their name because a longer pattern is prioritized than a shorter one
        patterns = sorted(self.patterns, key=lambda x: len(x.name))

        policies_and_enabled = {}
        for policy_filepath in found_files:
            for pattern in patterns:
                enabled = pattern.check_enabled(filepath=policy_filepath, policy_root_dir=self.root_dir)
                # if enabled is None, it means this pattern is not related to the policy
                if enabled is None:
                    continue
                policies_and_enabled[policy_filepath] = enabled
        enabled_policies = []
        for path, enabled in policies_and_enabled.items():
            if enabled:
                enabled_policies.append(path)
        return enabled_policies

    def run(self, eval_type: str = "project", project_dir: str = "", jobdata_path: str = "", external_data_path: str = ""):
        policy_files = self.list_enabled_policies()

        runner_jobdata_str = None
        if eval_type == EvalTypeJobdata:
            input_data_dict, runner_jobdata_str = load_input_from_jobdata(jobdata_path=jobdata_path)
        elif eval_type == EvalTypeProject:
            input_data_dict = load_input_from_project_dir(project_dir=project_dir)
        else:
            raise ValueError(f"eval_type `{eval_type}` is not supported")

        target_modules = []
        for policy_path in policy_files:
            target_module = detect_target_module_pattern(policy_path=policy_path)
            target_modules.append(target_module)

        if "task" in input_data_dict:
            # embed `task.module_fqcn` to input_data by using external_data
            input_data_all_tasks = []
            for input_data_for_task in input_data_dict["task"]:
                input_data_for_task = process_input_data_with_external_data("task", input_data_for_task, external_data_path)
                input_data_all_tasks.append(input_data_for_task)
            if input_data_all_tasks:
                input_data_dict["task"] = input_data_all_tasks

        result = EvaluationResult()
        for input_type in input_data_dict:
            input_data_per_type = input_data_dict[input_type]
            for single_input_data in input_data_per_type:
                filepath = single_input_data.object.filepath
                if filepath == "__in_memory__":
                    filepath = project_dir

                lines = None
                body = ""
                with open(filepath, "r") as f:
                    body = f.read()
                if input_type in ["task", "play"]:
                    _identifier = LineIdentifier()
                    block = _identifier.find_block(body=body, obj=single_input_data.object)
                    lines = block.to_dict()

                for policy_path in policy_files:
                    policy_name = get_rego_main_package_name(rego_path=policy_path)
                    target_type = detect_target_type_pattern(policy_path=policy_path)
                    is_target_type, eval_result = self.eval_single_policy(
                        rego_path=policy_path,
                        input_type=input_type,
                        input_data=single_input_data,
                        external_data_path=external_data_path,
                    )
                    result.add_single_result(
                        eval_result=eval_result,
                        is_target_type=is_target_type,
                        policy_name=policy_name,
                        target_type=target_type,
                        obj=single_input_data.object,
                        filepath=filepath,
                        lines=lines,
                    )

        return result, runner_jobdata_str

    def eval_single_policy(self, rego_path: str, input_type: str, input_data: PolicyInput, external_data_path: str) -> tuple[bool, str]:
        if not match_target_type(target_type=input_type, rego_path=rego_path):
            return False, {}
        if input_type == "task":
            task = input_data.task
            if not match_target_module(task.module_fqcn, rego_path):
                return True, {}
        input_data_str = input_data.to_json()
        result = eval_opa_policy(
            rego_path=rego_path,
            input_data=input_data_str,
            external_data_path=external_data_path,
        )
        return True, result


@dataclass
class ResultFormatter(object):
    isatty: bool = None
    term_width: int = None

    def __post_init__(self):
        if self.isatty is None:
            self.isatty = sys.stdout.isatty()
        if self.term_width is None:
            self.term_width = os.get_terminal_size().columns
        return

    def print(self, result: EvaluationResult):
        ng_targets = []
        for f in result.files:
            filepath = f.path
            for p in f.policies:
                for t in p.targets:
                    if t.result == ResultType.NG:
                        detail = {
                            "type": p.target_type,
                            "name": t.name,
                            "policy_name": p.policy_name,
                            "filepath": filepath,
                            "lines": CodeBlock.dict2str(t.lines),
                            "message": t.message,
                        }
                        ng_targets.append(detail)
        headers = []
        violation_per_type = {}
        for d in ng_targets:
            _type = d.get("type", "")
            _type_up = _type.upper()
            name = d.get("name", "")
            policy_name = d.get("policy_name", "")
            filepath = d.get("filepath", "")
            lines = d.get("lines", "")
            message = d.get("message", "").strip()
            _list = violation_per_type.get(_type, [])
            pattern = f"{_type} {name} {filepath} {lines}"
            if pattern not in _list:
                violation_per_type[_type] = _list + [pattern]

            file_info = f"{filepath} {lines}"
            if self.isatty:
                file_info = f"\033[93m{file_info}\033[00m"
            header = f"{_type_up} [{name}] {file_info} ".ljust(self.term_width, "*")
            if header not in headers:
                print(header)
                headers.append(header)

            flag = "NG"
            if self.isatty:
                flag = f"\033[91m{flag}\033[00m"
                message = f"\033[90m{message}\033[00m"
            print(f"... {policy_name} {flag}")
            print(f"    {message}")
            print("")
        print("-" * self.term_width)
        print("SUMMARY")
        total_files = result.summary.files.get("total", 0)
        ok_files = result.summary.files.get("OK", 0)
        ng_files = result.summary.files.get("NG", 0)
        total_label = "Total files"
        ok_label = "OK"
        ng_label = "NG"
        if self.isatty:
            total_label = f"\033[92m{total_label}\033[00m"
            ok_label = f"\033[96m{ok_label}\033[00m"
            ng_label = f"\033[91m{ng_label}\033[00m"
        print(f"... {total_label}: {total_files}, {ok_label}: {ok_files}, {ng_label}: {ng_files}")
        print("")
        count_str = ""
        for _type, _list in violation_per_type.items():
            count = len(_list)
            plural = ""
            if count > 1:
                plural = "s"
            count_str = f"{count_str}, {count} {_type}{plural}"
        if count_str:
            count_str = count_str[2:]
            violation_str = f"Violations are detected! in {count_str}"
            if self.isatty:
                violation_str = f"\033[91m{violation_str}\033[00m"
            print(violation_str)
        else:
            violation_str = "No violations are detected"
            if self.isatty:
                violation_str = f"\033[96m{violation_str}\033[00m"
            print(violation_str)
        print("")
