import os
import sys
import re
import glob
import tempfile
import jsonpickle
import shutil
from dataclasses import dataclass, field
from typing import List, Union
from ansible.executor.task_result import TaskResult

from ansible_policy.rego_data import (
    Task,
    Play,
    Variables,
    Event,
    APIRequest,
    PolicyInput,
    load_input_from_jobdata,
    load_input_from_project_dir,
    load_input_from_task_result,
    load_input_from_event,
    load_input_from_rest_data,
    process_input_data_with_external_data,
)
from ansible_policy.policybook.transpiler import PolicyTranspiler
from ansible_policy.utils import (
    init_logger,
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

default_policy_install_dir = "/tmp/ansible-policy/installed_policies"

EvalTypeJobdata = "jobdata"
EvalTypeProject = "project"
EvalTypeTaskResult = "task_result"
EvalTypeRest = "rest"
EvalTypeEvent = "event"

FORMAT_PLAIN = "plain"
FORMAT_EVENT_STREAM = "event_stream"
FORMAT_REST = "rest"
FORMAT_JSON = "json"
supported_formats = [FORMAT_PLAIN, FORMAT_EVENT_STREAM, FORMAT_REST, FORMAT_JSON]


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

        logger.debug(f"Installing policies `{self.name}` to `{target_dir}`")

        policybook_dir = None
        if self.type == "path":
            policybook_dir = self.source
        elif self.type == "galaxy":
            # Do not install policies from Galaxy
            pass
        else:
            raise ValueError(f"`{self.type}` is not a supported policy type")

        if policybook_dir:
            tmp_dir = tempfile.TemporaryDirectory()
            p_transpiler = PolicyTranspiler(tmp_dir=tmp_dir)
            p_transpiler.run(policybook_dir, target_dir)

        return policybook_dir


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
        elif "begin" in line_dict:
            block = cls()
            block.begin = line_dict["begin"]
            return block

        raise ValueError(f"failed to construct a CodeBlock from the dict `{line_dict}`")

    def __repr__(self):
        if not isinstance(self.begin, int):
            raise ValueError("`begin` is not found for this code block")

        if self.begin is not None and self.end is not None:
            return f"L{self.begin}-{self.end}"
        elif self.begin is not None:
            return f"L{self.begin}"
        else:
            return ""

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
        yml_policy_pattern_1 = os.path.join(policy_dir, "**", "policies/*.yml")
        yml_policy_pattern_2 = os.path.join(policy_dir, "**", "extensions/policy/*/*.yml")
        found_files = []
        found_files_1 = glob.glob(pathname=yml_policy_pattern_1, recursive=True)
        if found_files_1:
            found_files.extend(found_files_1)
        found_files_2 = glob.glob(pathname=yml_policy_pattern_2, recursive=True)
        if found_files_2:
            found_files.extend(found_files_2)
        return found_files

    def run(self, yml_policy_files: list):
        for yml_policy_path in yml_policy_files:
            dst_path = os.path.splitext(yml_policy_path)[0] + ".rego"
            transpile_yml_policy(src=yml_policy_path, dst=dst_path)


class ValidationType:
    SUCCESS = True
    FAILURE = False
    NONE = None

    @staticmethod
    def from_eval_result(eval_result: dict, is_target_type: bool):
        if not is_target_type:
            return ValidationType.NONE

        eval_result_value = eval_result.get("value", {})
        violation = False
        if "deny" in eval_result_value:
            if eval_result_value["deny"]:
                violation = True
        elif "allow" in eval_result_value:
            if not eval_result_value["allow"]:
                violation = True
        elif "warn" in eval_result_value:
            if eval_result_value["warn"]:
                violation = True
        elif "info" in eval_result_value:
            if eval_result_value["info"]:
                violation = True
        elif "ignore" in eval_result_value:
            if not eval_result_value["ignore"]:
                violation = True
        if violation:
            return ValidationType.FAILURE
        else:
            return ValidationType.SUCCESS


class ActionType:
    DENY = "deny"
    ALLOW = "allow"
    INFO = "info"
    WARN = "warn"
    IGNORE = "ignore"
    NONE = None

    @staticmethod
    def from_eval_result(eval_result: dict, is_target_type: bool):
        if not is_target_type:
            return ActionType.NONE

        eval_result_value = eval_result.get("value", {})
        if "deny" in eval_result_value:
            return ActionType.DENY
        elif "allow" in eval_result_value:
            return ActionType.ALLOW
        elif "info" in eval_result_value:
            return ActionType.INFO
        elif "warn" in eval_result_value:
            return ActionType.WARN
        elif "ignore" in eval_result_value:
            return ActionType.IGNORE
        else:
            return ActionType.NONE


@dataclass
class TargetResult(object):
    name: str = None
    lines: dict = field(default_factory=dict)
    validated: bool = None
    action_type: str = ""
    message: str = None


@dataclass
class PolicyResult(object):
    policy_name: str = None
    target_type: str = None
    violation: bool = False
    targets: List[TargetResult] = field(default_factory=list)

    def add_target_result(self, obj: any, lines: dict, validated: bool, message: str, action_type: str = "block"):
        target_name = getattr(obj, "name", None)
        target = TargetResult(name=target_name, lines=lines, validated=validated, message=message, action_type=action_type)
        if isinstance(validated, bool) and not validated and action_type == "block":
            self.violation = True
        self.targets.append(target)


@dataclass
class FileResult(object):
    path: str = None
    violation: bool = False
    policies: List[PolicyResult] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

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
        validated = ValidationType.from_eval_result(eval_result=eval_result, is_target_type=is_target_type)
        action_type = ActionType.from_eval_result(eval_result=eval_result, is_target_type=is_target_type)
        message = eval_result.get("message")
        if not policy_result:
            policy_result = PolicyResult(
                policy_name=policy_name,
                target_type=target_type,
            )
            need_append = True
        if is_target_type:
            policy_result.add_target_result(obj=obj, lines=lines, validated=validated, message=message, action_type=action_type)
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
            "validated": total_files - violation_files,
            "not_validated": violation_files,
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
        metadata: dict = {},
    ):
        file_result = self.get_file_result(filepath=filepath)
        need_append = False
        if not file_result:
            file_result = FileResult(
                path=filepath,
                metadata=metadata,
            )
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
    policy_dir: str = ""
    root_dir: str = ""
    need_cleanup: bool = False

    patterns: List[PolicyPattern] = field(default_factory=list)
    sources: List[Source] = field(default_factory=list)

    def __post_init__(self):
        validate_opa_installation()

        if self.config_path:
            cfg = Config.load(filepath=self.config_path)
            self.patterns = cfg.policy.patterns
            self.sources = cfg.source.sources
        elif self.policy_dir:
            policy_name = "policy"
            pattern = PolicyPattern(name=policy_name, enabled=True)
            self.patterns.append(pattern)
            source = Source(name=policy_name, source=self.policy_dir, type="path")
            self.sources.append(source)

        if not self.root_dir:
            tmp_dir = tempfile.TemporaryDirectory()
            self.root_dir = tmp_dir.name
            self.need_cleanup = True

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

    def __del__(self):
        if self.need_cleanup and self.root_dir and os.path.exists(self.root_dir):
            try:
                os.remove(self.root_dir)
            except Exception:
                pass

    def list_enabled_policies(self):
        policy_dir = self.root_dir
        rego_policy_pattern_1 = os.path.join(policy_dir, "**", "policies/*.rego")
        found_files_1 = glob.glob(pathname=rego_policy_pattern_1, recursive=True)
        rego_policy_pattern_2 = os.path.join(policy_dir, "**", "extensions/policy/*/*.rego")
        found_files_2 = glob.glob(pathname=rego_policy_pattern_2, recursive=True)
        found_files = []
        if found_files_1:
            found_files.extend(found_files_1)
        if found_files_2:
            found_files.extend(found_files_2)
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

    def run(
        self,
        eval_type: str = "project",
        project_dir: str = "",
        target_data: dict = None,
        task_result: TaskResult = None,
        event: Event = None,
        rest_request: APIRequest = None,
        external_data_path: str = "",
        variables_path: str = "",
    ):
        policy_files = self.list_enabled_policies()
        logger.debug(f"policy_files: {policy_files}")
        if not policy_files:
            logger.warning("No policies are loaded!")

        variables = None
        if variables_path:
            variables = self.load_variables(variables_path=variables_path)

        if eval_type == EvalTypeJobdata:
            input_data_dict, _ = load_input_from_jobdata(jobdata=target_data)
        elif eval_type == EvalTypeProject:
            input_data_dict = load_input_from_project_dir(project_dir=project_dir, variables=variables)
        elif eval_type == EvalTypeTaskResult:
            input_data_dict = load_input_from_task_result(task_result=task_result)
        elif eval_type == EvalTypeEvent:
            _event = target_data
            if event:
                _event = event
            input_data_dict = load_input_from_event(event=_event)
        elif eval_type == EvalTypeRest:
            _rest_data = target_data
            if rest_request:
                _rest_data = rest_request
            input_data_dict = load_input_from_rest_data(rest_data=_rest_data)
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
            data_num = len(input_data_per_type)
            logger.debug(f"len(input_data_per_type): {data_num}")
            for single_input_data in input_data_per_type:
                obj = single_input_data.object
                filepath = "__no_filepath__"
                if hasattr(obj, "filepath"):
                    filepath = getattr(obj, "filepath")
                    if filepath == "__in_memory__":
                        filepath = project_dir
                    elif project_dir:
                        filepath = os.path.join(project_dir, filepath)

                lines = None
                body = ""
                metadata = {}
                if eval_type == EvalTypeEvent:
                    lines = {
                        "begin": obj.line,
                        "end": None,
                    }
                    filepath = obj.uuid
                    metadata = obj.__dict__
                elif eval_type == EvalTypeRest:
                    pass
                else:
                    with open(filepath, "r") as f:
                        body = f.read()
                    if input_type in ["task", "play"]:
                        _identifier = LineIdentifier()
                        block = _identifier.find_block(body=body, obj=obj)
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
                        obj=obj,
                        filepath=filepath,
                        lines=lines,
                        metadata=metadata,
                    )

        return result

    def eval_single_policy(self, rego_path: str, input_type: str, input_data: PolicyInput, external_data_path: str) -> tuple[bool, str]:
        target_type = input_type
        if input_type == "task_result":
            target_type = "task"
        if not match_target_type(target_type=target_type, rego_path=rego_path):
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

    def load_variables(self, variables_path: str):
        return Variables.from_variables_file(path=variables_path)


@dataclass
class ResultFormatter(object):
    format_type: str = None
    isatty: bool = None
    term_width: int = None
    base_dir: str = ""

    def __post_init__(self):
        if self.format_type is None or self.format_type not in supported_formats:
            raise ValueError(f"`format_type` must be one of {supported_formats}, " "but received {self.format_type}")
        if self.isatty is None:
            self.isatty = sys.stdout.isatty()
        if self.term_width is None:
            self.term_width = shutil.get_terminal_size().columns
        return

    def print(self, result: EvaluationResult):
        if self.format_type == FORMAT_EVENT_STREAM:
            self.print_event_stream(result)
        elif self.format_type == FORMAT_JSON:
            self.print_json(result)
        elif self.format_type == FORMAT_REST:
            self.print_rest(result)
        elif self.format_type == FORMAT_PLAIN:
            self.print_plain(result)

    def print_event_stream(self, result: EvaluationResult):
        if not result.files:
            return
        file_result = result.files[0]
        if not file_result.policies:
            return

        policy_result = file_result.policies[0]
        if not policy_result.targets:
            return
        target_result = policy_result.targets[0]

        task_path = file_result.metadata.get("task_path", "")

        event_type = target_result.name
        _uuid = file_result.path
        short_uuid = _uuid[:4] + "..." + _uuid[-4:]
        file_info = task_path
        # if base_dir is provided, shorten the filepath to be shown when possible
        if self.base_dir:
            file_info = self.shorten_filepath(file_info)
        file_info = f"\033[93m{file_info}\033[00m"
        event_name = f"{event_type} {short_uuid}"
        _violated = "\033[91mViolation\033[00m" if file_result.violation else "\033[96mPass\033[00m"
        _msg = ""
        if policy_result.violation:
            _msg += target_result.message.strip()
        max_message_length = 120
        if len(_msg) > max_message_length:
            _msg = _msg[:max_message_length] + "..."
        if _msg:
            _msg = f"\n    \033[90m{_msg}\033[00m"
        _line = f"Event [{event_name}] {file_info} {_violated} {_msg}"
        print(_line)

    def print_rest(self, result: EvaluationResult):
        if not result.files:
            return
        file_result = result.files[0]
        if not file_result.policies:
            return

        policy_result = None
        target_result = None
        for p_res in file_result.policies:
            if p_res.targets:
                policy_result = p_res
                target_result = p_res.targets[0]
        if not policy_result or not target_result:
            return

        policy_name = policy_result.policy_name

        _violated = "\033[91mViolation\033[00m" if file_result.violation else "\033[96mPass\033[00m"
        _msg = ""
        if policy_result.violation:
            _msg += target_result.message.strip()
        max_message_length = 120
        if len(_msg) > max_message_length:
            _msg = _msg[:max_message_length] + "..."
        if _msg:
            _msg = f"\033[90m{_msg}\033[00m"
        _line = f"REST [{policy_name}] {_violated} {_msg}"
        print(_line)

    def print_json(self, result: EvaluationResult):
        json_str = jsonpickle.encode(
            result,
            unpicklable=False,
            make_refs=False,
            separators=(",", ":"),
        )
        print(json_str)

    def print_plain(self, result: EvaluationResult):
        not_validated_targets = []
        for f in result.files:
            filepath = f.path
            for p in f.policies:
                for t in p.targets:
                    if isinstance(t.validated, bool) and not t.validated:
                        lines = (None,)
                        if t.lines:
                            lines = CodeBlock.dict2str(t.lines)
                        detail = {
                            "type": p.target_type,
                            "name": t.name,
                            "policy_name": p.policy_name,
                            "filepath": filepath,
                            "lines": lines,
                            "message": t.message,
                            "action_type": t.action_type,
                        }
                        not_validated_targets.append(detail)
        headers = []
        violation_per_type = {}
        warning_per_type = {}
        info_per_type = {}
        for d in not_validated_targets:
            _type = d.get("type", "")
            _type_up = _type.upper()
            name = d.get("name", "")
            policy_name = d.get("policy_name", "")
            filepath = d.get("filepath", "")
            if self.base_dir:
                filepath = self.shorten_filepath(filepath)
            lines = d.get("lines", "")
            message = d.get("message", "").strip()
            pattern = f"{_type} {name} {filepath} {lines}"
            if d["action_type"] == "deny" or d["action_type"] == "allow":
                _list = violation_per_type.get(_type, [])
                if pattern not in _list:
                    violation_per_type[_type] = _list + [pattern]
            if d["action_type"] == "warn":
                _list = warning_per_type.get(_type, [])
                if pattern not in _list:
                    warning_per_type[_type] = _list + [pattern]
            if d["action_type"] == "info":
                _list = info_per_type.get(_type, [])
                if pattern not in _list:
                    info_per_type[_type] = _list + [pattern]

            file_info = f"{filepath} {lines}"
            if self.isatty:
                file_info = f"\033[93m{file_info}\033[00m"
            header = f"{_type_up} [{name}] {file_info} ".ljust(self.term_width, "*")
            if header not in headers:
                print(header)
                headers.append(header)

            if d["action_type"] == "deny" or d["action_type"] == "allow":
                flag = "Not Validated"
                if self.isatty:
                    flag = f"\033[91m{flag}\033[00m"
                    message = f"\033[90m{message}\033[00m"
            elif d["action_type"] == "warn":
                flag = "Warning"
                if self.isatty:
                    flag = f"\033[93m{flag}\033[00m"
                    message = f"\033[90m{message}\033[00m"
            elif d["action_type"] == "info":
                flag = "Info"
                if self.isatty:
                    flag = f"\033[92m{flag}\033[00m"
                    message = f"\033[90m{message}\033[00m"
            print(f"... {policy_name} {flag}")
            print(f"    {message}")
            print("")
        print("-" * self.term_width)
        print("SUMMARY")
        total_files = result.summary.files.get("total", 0)
        valid_files = result.summary.files.get("validated", 0)
        not_valid_files = result.summary.files.get("not_validated", 0)
        total_label = "Total files"
        valid_label = "Validated"
        not_valid_label = "Not Validated"
        if self.isatty:
            total_label = f"\033[92m{total_label}\033[00m"
            valid_label = f"\033[96m{valid_label}\033[00m"
            not_valid_label = f"\033[91m{not_valid_label}\033[00m"
        print(f"... {total_label}: {total_files}, {valid_label}: {valid_files}, {not_valid_label}: {not_valid_files}")
        print("")
        violation_count_str = ""
        warn_count_str = ""
        info_count_str = ""
        for _type, _list in violation_per_type.items():
            count = len(_list)
            plural = ""
            if count > 1:
                plural = "s"
            violation_count_str = f"{violation_count_str}, {count} {_type}{plural}"
        for _type, _list in warning_per_type.items():
            count = len(_list)
            plural = ""
            if count > 1:
                plural = "s"
            warn_count_str = f"{warn_count_str}, {count} {_type}{plural}"
        for _type, _list in info_per_type.items():
            count = len(_list)
            plural = ""
            if count > 1:
                plural = "s"
            info_count_str = f"{info_count_str}, {count} {_type}{plural}"
        if violation_count_str:
            violation_count_str = violation_count_str[2:]
            violation_str = f"Violations are detected! in {violation_count_str}"
            if self.isatty:
                violation_str = f"\033[91m{violation_str}\033[00m"
            print(violation_str)
        if warn_count_str:
            warn_count_str = warn_count_str[2:]
            warn_str = f"Warnings messages on {warn_count_str}"
            if self.isatty:
                warn_str = f"\033[93m{warn_str}\033[00m"
            print(warn_str)
        if info_count_str:
            info_count_str = info_count_str[2:]
            info_str = f"Info messages on {info_count_str}"
            if self.isatty:
                info_str = f"\033[92m{info_str}\033[00m"
            print(info_str)
        if not violation_count_str and not warn_count_str and not info_count_str:
            violation_str = "No violations are detected"
            if self.isatty:
                violation_str = f"\033[96m{violation_str}\033[00m"
            print(violation_str)
        print("")

    def shorten_filepath(self, filepath: str):
        _base_dir_prefix = self.base_dir
        if _base_dir_prefix[-1] != "/":
            _base_dir_prefix += "/"
        if filepath.startswith(_base_dir_prefix):
            filepath = filepath[len(_base_dir_prefix) :]
        return filepath
