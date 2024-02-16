import os
import re
import glob
import tempfile
import shutil
from dataclasses import dataclass, field
from typing import List

from ansible_gatekeeper.rego_data import (
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
    get_rego_main_package_name,
    validate_opa_installation,
    eval_opa_policy,
    match_target_module,
    match_target_type,
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
class Transpiler(object):
    def search_target(self, policy_dir: str):
        yml_policy_pattern = os.path.join(policy_dir, "**", "policies/*.yml")
        found_files = glob.glob(pathname=yml_policy_pattern, recursive=True)
        return found_files

    def run(self, yml_policy_files: list):
        for yml_policy_path in yml_policy_files:
            dst_path = os.path.splitext(yml_policy_path)[0] + ".rego"
            transpile_yml_policy(src=yml_policy_path, dst=dst_path)


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

        results = {}
        for input_type in input_data_dict:
            input_data_per_type = input_data_dict[input_type]
            for single_input_data in input_data_per_type:
                result_per_input = {}
                for policy_path in policy_files:
                    policy_name = get_rego_main_package_name(rego_path=policy_path)
                    is_target_type, rego_out = self.eval_single_policy(
                        rego_path=policy_path,
                        input_type=input_type,
                        input_data=single_input_data,
                        external_data_path=external_data_path,
                    )
                    result_per_input[policy_name] = {
                        "rego_out": rego_out,
                        "is_target_type": is_target_type,
                    }

                if input_type not in results:
                    results[input_type] = []
                results[input_type].append(
                    {
                        "policy_name": policy_name,
                        "type": input_type,
                        "object": single_input_data.object,
                        "result": result_per_input,
                    }
                )
        return results, runner_jobdata_str

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
