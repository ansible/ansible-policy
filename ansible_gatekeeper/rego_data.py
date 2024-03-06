import os
import sys
import copy
import tempfile
import jsonpickle
import json
import yaml
from dataclasses import dataclass, field
from typing import List, Dict
from ansible.executor.task_result import TaskResult as AnsibleTaskResult
from ansible.playbook.task import Task as AnsibleTask
from ansible.parsing.yaml.objects import AnsibleUnicode

from ansible_gatekeeper.utils import (
    get_module_name_from_task,
    load_external_data,
    prepare_project_dir_from_runner_jobdata,
    embed_module_info_with_galaxy,
)

from ansible_scan_core.scanner import AnsibleScanner
from ansible_scan_core.models import (
    BecomeInfo,
    File as CoreFile,
    Task as CoreTask,
    Play as CorePlay,
    TaskFile as CoreTaskFile,
    Role as CoreRole,
    Playbook as CorePlaybook,
    ScanResult,
    VariableContainer,
)
from ansible_scan_core.utils import extract_var_parts


scanner = AnsibleScanner(silent=True)


InputTypeTask = "task"
InputTypePlay = "play"
InputTypeRole = "role"
InputTypeProject = "project"
InputTypeTaskResult = "task_result"


@dataclass
class Variables(object):
    # from scan results
    task_vars: dict = field(default_factory=dict)
    play_vars: dict = field(default_factory=dict)
    role_vars: dict = field(default_factory=dict)
    role_defaults: dict = field(default_factory=dict)

    # from callback objects
    extra_vars: dict = field(default_factory=dict)
    facts: dict = field(default_factory=dict)
    # non persistent facts such as registered vars / set facts
    np_facts: dict = field(default_factory=dict)

    @staticmethod
    def from_variables_file(path: str):
        data = None
        with open(path, "r") as f:
            data = json.load(f)
        if not data:
            return Variables()
        if not isinstance(data, dict):
            raise TypeError(f"variables file contents must be a dict, but detected `{type(data)}`")
        return Variables.from_json(data=data)

    @staticmethod
    def from_json(data: dict):
        v = Variables()
        for key, val in data.items():
            if hasattr(v, key):
                setattr(v, key, val)
        return v


@dataclass
class RuntimeData(object):
    extra_vars: dict = field(default_factory=dict)
    env_vars: dict = field(default_factory=dict)
    inventory: dict = field(default_factory=dict)

    @staticmethod
    def load(dir: str):
        rd = RuntimeData()
        rd.extra_vars = rd.load_file_data(os.path.join(dir, "env/extravars"))
        rd.env_vars = rd.load_file_data(os.path.join(dir, "env/envvars"))
        rd.inventory = rd.load_file_data(os.path.join(dir, "inventory/hosts"))
        return rd

    def load_file_data(self, path: str):
        data = {}
        if os.path.exists(path):
            with open(path, "r") as file:
                try:
                    data = yaml.safe_load(file)
                except Exception:
                    pass
        return data


def get_all_set_vars(project: ScanResult, common_vars: dict = None):
    variables = {}
    for tree in project.trees:
        entrypoint = tree.items[0].spec
        entrypoint_key = entrypoint.key
        all_vars_per_tree = VariableContainer.find_all_set_vars(tree)
        all_vars_per_tree.update(common_vars)
        variables[entrypoint_key] = all_vars_per_tree
    return variables


def load_input_from_jobdata(jobdata_path: str = ""):
    runner_jobdata_str = ""
    if jobdata_path:
        with open(jobdata_path, "r") as file:
            runner_jobdata_str = file.read()
    else:
        for line in sys.stdin:
            runner_jobdata_str += line

    workdir = tempfile.TemporaryDirectory()
    prepare_project_dir_from_runner_jobdata(
        jobdata=runner_jobdata_str,
        workdir=workdir.name,
    )
    policy_input = make_policy_input_with_scan(target_path=workdir.name)
    workdir.cleanup()
    return policy_input, runner_jobdata_str


def load_input_from_project_dir(project_dir: str = "", variables: Variables = None):
    policy_input = make_policy_input_with_scan(target_path=project_dir, variables=variables)
    return policy_input


def load_input_from_task_result(task_result: AnsibleTaskResult = None):
    _task_result = TaskResult.from_ansible_object(object=task_result)
    policy_input = make_policy_input_for_task_result(task_result=_task_result)
    return policy_input


def scan_project(
    input_types: List[str],
    yaml_str: str = "",
    project_dir: str = "",
    metadata: dict = None,
    runtime_data: RuntimeData = None,
    variables: Variables = None,
    output_dir: str = "",
):
    _metadata = {}
    if metadata:
        _metadata = metadata

    project = None
    if yaml_str:
        project = scanner.run(
            raw_yaml=yaml_str,
            source=_metadata,
            output_dir=output_dir,
        )
    elif project_dir:
        project = scanner.run(
            target_dir=project_dir,
            source=_metadata,
            output_dir=output_dir,
        )

    if not project:
        raise ValueError("failed to scan the target project; project is None")

    base_input_list = PolicyInput.from_scan_result(
        project=project,
        runtime_data=runtime_data,
        variables=variables,
        input_type=InputTypeProject,
    )
    base_input = base_input_list[0]

    policy_input = {}
    for input_type in input_types:
        policy_input_per_type = PolicyInput.from_scan_result(
            project=project,
            runtime_data=runtime_data,
            variables=variables,
            input_type=input_type,
            base_input=base_input,
        )
        policy_input[input_type] = policy_input_per_type

    if not policy_input:
        raise ValueError("failed to scan the target project; policy_input is None")

    return policy_input


@dataclass
class File(object):
    type: str = "file"
    name: str = ""
    key: str = ""
    local_key: str = ""
    role: str = ""
    collection: str = ""

    body: str = ""
    # data: any = None
    encrypted: bool = False
    error: str = ""
    label: str = ""
    filepath: str = ""

    data: dict = field(default_factory=dict)

    @classmethod
    def from_object(cls, obj: CoreFile):
        new_obj = cls()
        if hasattr(obj, "__dict__"):
            for k, v in obj.__dict__.items():
                if hasattr(new_obj, k):
                    setattr(new_obj, k, v)

        try:
            new_obj.data = json.loads(obj.data)
        except Exception:
            new_obj.data = None
        return new_obj


@dataclass
class Task(object):
    type: str = "task"
    key: str = ""
    name: str = ""

    module: str = ""
    index: int = -1
    play_index: int = -1
    filepath: str = ""

    role: str = ""
    collection: str = ""
    become: BecomeInfo = None
    variables: dict = field(default_factory=dict)
    module_defaults: dict = field(default_factory=dict)
    registered_variables: dict = field(default_factory=dict)
    set_facts: dict = field(default_factory=dict)
    loop: dict = field(default_factory=dict)
    options: dict = field(default_factory=dict)
    module_options: dict = field(default_factory=dict)
    executable: str = ""
    executable_type: str = ""
    collections_in_play: list = field(default_factory=list)

    yaml_lines: str = ""
    line_num_in_file: list = field(default_factory=list)  # [begin, end]

    # FQCN for Module and Role. Or a file path for TaskFile.  resolved later
    resolved_name: str = ""
    # candidates of resovled_name
    possible_candidates: list = field(default_factory=list)

    # embed these data when module/role/taskfile are resolved
    module_info: dict = field(default_factory=dict)
    include_info: dict = field(default_factory=dict)

    module_fqcn: str = ""

    @classmethod
    def from_object(cls, obj: CoreTask, proj: ScanResult):
        new_obj = cls()
        if hasattr(obj, "__dict__"):
            for k, v in obj.__dict__.items():
                if hasattr(new_obj, k):
                    setattr(new_obj, k, v)

        module_fqcn, _ = get_module_name_from_task(task=obj)
        new_obj.module_fqcn = module_fqcn

        return new_obj


@dataclass
class Play(object):
    type: str = "play"
    name: str = ""
    filepath: str = ""
    index: int = -1
    key: str = ""
    local_key: str = ""

    role: str = ""
    collection: str = ""
    import_module: str = ""
    import_playbook: str = ""
    pre_tasks: list = field(default_factory=list)
    tasks: list = field(default_factory=list)
    post_tasks: list = field(default_factory=list)
    handlers: list = field(default_factory=list)
    # not actual Role, but RoleInPlay defined in this playbook
    roles: list = field(default_factory=list)
    module_defaults: dict = field(default_factory=dict)
    options: dict = field(default_factory=dict)
    collections_in_play: list = field(default_factory=list)
    become: BecomeInfo = None
    variables: dict = field(default_factory=dict)
    vars_files: list = field(default_factory=list)

    task_loading: dict = field(default_factory=dict)

    @classmethod
    def from_object(cls, obj: CorePlay, proj: ScanResult):
        new_obj = cls()
        if hasattr(obj, "__dict__"):
            for k, v in obj.__dict__.items():
                if hasattr(new_obj, k):
                    setattr(new_obj, k, v)

        tasks = proj.get_tasks_in_play(play=obj)
        new_obj.tasks = [Task.from_object(task, proj) for task in tasks]

        return new_obj


@dataclass
class Playbook(object):
    type: str = "playbook"
    key: str = ""
    name: str = ""
    filepath: str = ""
    yaml_lines: str = ""
    role: str = ""
    collection: str = ""
    play_keys: list = field(default_factory=list)
    variables: dict = field(default_factory=dict)
    options: dict = field(default_factory=dict)

    tasks: List[Task] = field(default_factory=list)
    plays: List[Play] = field(default_factory=list)

    @classmethod
    def from_object(cls, obj: CorePlaybook, proj: ScanResult):
        new_obj = cls()
        if hasattr(obj, "__dict__"):
            for k, v in obj.__dict__.items():
                if k == "plays":
                    setattr(new_obj, "play_keys", v)
                elif hasattr(new_obj, k):
                    setattr(new_obj, k, v)

        tasks = proj.get_tasks_in_playbook(playbook=obj)
        new_obj.tasks = [Task.from_object(task, proj) for task in tasks]

        plays = proj.get_plays(playbook=obj)
        new_obj.plays = [Play.from_object(play, proj) for play in plays]

        return new_obj


@dataclass
class TaskFile(object):
    type: str = "taskfile"
    key: str = ""
    name: str = ""
    filepath: str = ""
    # tasks: list = field(default_factory=list)
    role: str = ""
    collection: str = ""
    yaml_lines: str = ""
    variables: dict = field(default_factory=dict)
    module_defaults: dict = field(default_factory=dict)
    options: dict = field(default_factory=dict)
    task_loading: dict = field(default_factory=dict)

    tasks: List[Task] = field(default_factory=list)

    @classmethod
    def from_object(cls, obj: CoreTaskFile, proj: ScanResult):
        new_obj = cls()
        if hasattr(obj, "__dict__"):
            for k, v in obj.__dict__.items():
                if hasattr(new_obj, k):
                    setattr(new_obj, k, v)

        tasks = proj.get_tasks_in_taskfile(taskfile=obj)
        new_obj.tasks = [Task.from_object(task, proj) for task in tasks]

        return new_obj


@dataclass
class Role(object):
    type: str = "role"
    key: str = ""
    name: str = ""
    filepath: str = ""
    fqcn: str = ""
    metadata: dict = field(default_factory=dict)
    collection: str = ""
    playbooks: list = field(default_factory=list)
    # taskfiles: list = field(default_factory=list)
    handlers: list = field(default_factory=list)
    modules: list = field(default_factory=list)
    dependency: dict = field(default_factory=dict)
    requirements: dict = field(default_factory=dict)
    ari_source: str = ""  # collection/scm repo/galaxy

    default_variables: dict = field(default_factory=dict)
    variables: dict = field(default_factory=dict)
    # key: loop_var (default "item"), value: list/dict of item value
    loop: dict = field(default_factory=dict)
    options: dict = field(default_factory=dict)

    # key: filepath, value: TaskFile object
    taskfiles: Dict[str, TaskFile] = field(default_factory=dict)

    @classmethod
    def from_object(cls, obj: CoreRole, proj: ScanResult):
        new_obj = Role()
        if hasattr(obj, "__dict__"):
            for k, v in obj.__dict__.items():
                if hasattr(new_obj, k):
                    setattr(new_obj, k, v)

        taskfiles = proj.get_taskfiles_in_role(role=obj)
        new_obj.taskfiles = {taskfile.filepath: TaskFile.from_object(obj=taskfile, proj=proj) for taskfile in taskfiles}

        return new_obj


@dataclass
class Project(object):
    type: str = "project"
    key: str = ""
    name: str = ""
    filepath: str = ""
    # if set, this repository is a collection repository
    my_collection_name: str = ""
    playbooks: list = field(default_factory=list)
    roles: list = field(default_factory=list)
    # for playbook scan
    target_playbook_path: str = ""
    # for taskfile scan
    target_taskfile_path: str = ""
    requirements: dict = field(default_factory=dict)
    installed_collections_path: str = ""
    installed_collections: list = field(default_factory=list)
    installed_roles_path: str = ""
    installed_roles: list = field(default_factory=list)
    modules: list = field(default_factory=list)
    taskfiles: list = field(default_factory=list)
    inventories: list = field(default_factory=list)
    files: list = field(default_factory=list)
    version: str = ""

    @classmethod
    def from_object(cls, obj: ScanResult):
        new_obj = cls()
        if hasattr(obj, "__dict__"):
            for k, v in obj.__dict__.items():
                if hasattr(new_obj, k):
                    setattr(new_obj, k, v)
        return new_obj


@dataclass
class TaskResult(AnsibleTaskResult):
    filepath: str = ""

    _host: any = None
    _task: any = None
    _result: any = None
    _task_fields: any = None

    @staticmethod
    def from_ansible_object(object: AnsibleTaskResult):
        task_result = TaskResult()
        for key, val in object.__dict__.items():
            if hasattr(task_result, key):
                setattr(task_result, key, val)

        task = task_result._task
        assert isinstance(task, AnsibleTask)
        filepath = task.name._data_source
        task_result.filepath = filepath
        return task_result


@dataclass
class PolicyInput(object):
    type: str = ""
    source: dict = field(default_factory=dict)
    project: any = None
    playbooks: dict = field(default_factory=dict)
    taskfiles: dict = field(default_factory=dict)
    roles: dict = field(default_factory=dict)

    task: Task = None
    play: Play = None
    role: Role = None
    task_result: TaskResult = None

    vars_files: dict = field(default_factory=dict)

    extra_vars: dict = field(default_factory=dict)

    variables: dict = field(default_factory=dict)

    # TODO: imeplement attrs below
    # modules
    # files
    # others?

    @staticmethod
    def from_scan_result(project: ScanResult, runtime_data: RuntimeData = None, variables: Variables = None, input_type: str = "", base_input=None):
        if input_type == InputTypeTask:
            if not base_input:
                base_input_list = PolicyInput.from_scan_result(project=project, runtime_data=runtime_data, variables=variables)
                base_input = base_input_list[0]
            tasks = []
            for playbook in base_input.playbooks.values():
                tasks.extend(playbook.tasks)
            for taskfile in base_input.taskfiles.values():
                tasks.extend(taskfile.tasks)
            for role in base_input.roles.values():
                for taskfile in role.taskfiles.values():
                    tasks.extend(taskfile.tasks)
            p_input_list = []
            for task in tasks:
                p_input = copy.deepcopy(base_input)
                p_input.type = InputTypeTask
                p_input.task = task
                p_input_list.append(p_input)
            return p_input_list
        elif input_type == InputTypePlay:
            if not base_input:
                base_input_list = PolicyInput.from_scan_result(project=project, runtime_data=runtime_data)
                base_input = base_input_list[0]
            plays = []
            for playbook in base_input.playbooks.values():
                plays.extend(playbook.plays)
            p_input_list = []
            for play in plays:
                p_input = copy.deepcopy(base_input)
                p_input.type = InputTypePlay
                p_input.play = play
                p_input_list.append(p_input)
            return p_input_list
        elif input_type == InputTypeRole:
            if not base_input:
                base_input_list = PolicyInput.from_scan_result(project=project, runtime_data=runtime_data)
                base_input = base_input_list[0]
            roles = []
            for role in base_input.roles.values():
                roles.extend(role)
            p_input_list = []
            for role in roles:
                p_input = copy.deepcopy(base_input)
                p_input.type = InputTypeRole
                p_input.role = role
                p_input_list.append(p_input)
            return p_input_list
        else:
            p_input = PolicyInput()
            p_input.type = InputTypeProject
            p_input.source = project.source
            p_input.playbooks = {playbook.filepath: Playbook.from_object(obj=playbook, proj=project) for playbook in project.playbooks}
            p_input.taskfiles = {taskfile.filepath: TaskFile.from_object(obj=taskfile, proj=project) for taskfile in project.taskfiles}
            p_input.roles = {role.filepath: Role.from_object(obj=role, proj=project) for role in project.roles}
            if project.projects:
                p_input.project = project.projects[0]

            files = {}
            for file in project.files:
                files[file.filepath] = File.from_object(obj=file)
            p_input.vars_files = files

            if runtime_data:
                p_input.extra_vars = runtime_data.extra_vars

            _common_vars = {}
            for file in p_input.vars_files.values():
                if file.data:
                    _common_vars.update(file.data)

            if p_input.extra_vars:
                _common_vars.update(p_input.extra_vars)

            set_variables_for_all_trees = get_all_set_vars(project=project, common_vars=_common_vars)
            set_variables = {}
            for set_vars_per_tree in set_variables_for_all_trees.values():
                if isinstance(set_vars_per_tree, dict) and set_vars_per_tree:
                    set_variables.update(set_vars_per_tree)

            if variables:
                if variables.extra_vars:
                    set_variables.update(variables.extra_vars)
            p_input.variables = set_variables

            return [p_input]

    @staticmethod
    def from_task_result(task_result: TaskResult):
        if not isinstance(task_result, TaskResult):
            raise TypeError(f"`task_result` must be a TaskResult object, but received {type(task_result)}")
        task = task_result._task
        parent = task._parent
        play = parent._play
        variable_manager = play._variable_manager
        # fact_cache = variable_manager._fact_cache
        extra_vars = variable_manager._extra_vars
        # plugin = fact_cache._plugin
        # facts = plugin._cache
        # np_fact_cache = variable_manager._nonpersistent_fact_cache
        variables = {}
        _extra_vars = task_result_vars2dict(extra_vars)
        variables.update(_extra_vars)

        p_input = PolicyInput()
        p_input.type = InputTypeTaskResult
        p_input.task_result = task_result
        p_input.variables = variables
        return [p_input]

    def to_object_json(self, **kwargs):
        kwargs["value"] = self
        kwargs["make_refs"] = False
        kwargs["separators"] = (",", ":")
        return jsonpickle.encode(**kwargs)

    def to_json(self, **kwargs):
        data = {}
        try:
            if self.type == InputTypeTask:
                task_data_block = yaml.safe_load(self.task.yaml_lines)
                if task_data_block:
                    data = task_data_block[0]
                    data = recursive_resolve_variable(data, self.variables)
            elif self.type == InputTypePlay:
                data = self.play.options
            elif self.type == InputTypeTaskResult:
                module_options = task_fields2module_options(self.task_result._task_fields)
                data.update(module_options)
                data = recursive_resolve_variable(data, self.variables)
                data["variables"] = self.variables
        except Exception:
            pass
        data["_agk"] = self
        kwargs["value"] = data
        kwargs["unpicklable"] = False
        kwargs["make_refs"] = False
        kwargs["separators"] = (",", ":")
        return jsonpickle.encode(**kwargs)

    @staticmethod
    def from_object_json(json_str: str = "", fpath: str = ""):
        if not json_str and fpath:
            with open(fpath, "r") as file:
                json_str = file.read()

        p_input = jsonpickle.decode(json_str)
        if not isinstance(p_input, PolicyInput):
            raise ValueError(f"a decoded object is not a PolicyInput, but {type(p_input)}")
        return p_input

    @property
    def object(self):
        obj = getattr(self, self.type, None)
        return obj


def task_fields2module_options(task_fields: dict):
    task_action = task_fields.get("action", None)
    if not task_action:
        return {}
    if isinstance(task_action, AnsibleUnicode):
        task_action = str(task_action)

    module_args = task_fields.get("args", {})
    if not module_args or not isinstance(module_args, dict):
        return {task_action: {}}

    module_options = {}
    for key, val in module_args.items():
        if isinstance(val, AnsibleUnicode):
            val = str(val)
        module_options[key] = val
    return {task_action: module_options}


def recursive_resolve_single_var(txt: str, variables: dict):
    if not isinstance(txt, str):
        return txt

    if "{{" not in txt:
        return txt

    var_names = extract_var_parts(txt)
    resolved_txt = txt
    for var_name, var_details in var_names.items():
        var_original_txt = var_details["original"]
        if var_original_txt not in txt:
            continue

        if var_name not in variables:
            continue

        resolved_value = variables[var_name]
        if isinstance(resolved_value, list):
            if len(resolved_value) == 1:
                if txt == var_original_txt:
                    resolved_txt = resolved_value[0]
                else:
                    resolved_var_str = f"{resolved_value[0]}"
                    resolved_txt = txt.replace(var_original_txt, resolved_var_str)
            else:
                resolved_txt = []
                for single_val in resolved_value:
                    _resolved = None
                    if txt == var_original_txt:
                        _resolved = single_val
                    else:
                        resolved_var_str = f"{single_val}"
                        _resolved = txt.replace(var_original_txt, resolved_var_str)
                    resolved_txt.append(_resolved)
        else:
            if txt == var_original_txt:
                resolved_txt = resolved_value
            else:
                resolved_var_str = f"{resolved_value}"
                resolved_txt = txt.replace(var_original_txt, resolved_var_str)

        if type(txt) == type(resolved_txt) and txt == resolved_txt:
            continue

        if isinstance(resolved_txt, (str, list)):
            resolved_txt = recursive_resolve_single_var(resolved_txt, variables)
    return resolved_txt


# TODO: support resolution for variables without bracket (e.g. `when: foo == "bar"`)
def recursive_resolve_variable(data: any, variables: dict, datapath: str = ""):
    if not data:
        return data

    if not variables:
        return data

    newdata = None
    if isinstance(data, dict):
        newdata = {}
        for key, val in data.items():
            _datapath = f"{datapath}.{key}"
            newval = recursive_resolve_variable(val, variables, _datapath)
            newdata[key] = newval
    elif isinstance(data, list):
        newdata = []
        for i, val in enumerate(data):
            _datapath = f"{datapath}.{i}"
            newval = recursive_resolve_variable(val, variables, _datapath)
            newdata.append(newval)
    elif isinstance(data, str):
        newdata = recursive_resolve_single_var(data, variables)
    else:
        newdata = data
    return newdata


def task_result_vars2dict(task_result_vars: dict):
    key_value = {}
    for key, arg_val in task_result_vars.items():
        val = arg_val
        if isinstance(arg_val, AnsibleUnicode):
            val = str(arg_val)
        key_value[key] = val
    return key_value


def process_input_data_with_external_data(input_type: str, input_data: PolicyInput, external_data_path: str):
    galaxy = load_external_data(ftype="galaxy", fpath=external_data_path)

    if input_type == InputTypeTask:
        task = input_data.task
        embed_module_info_with_galaxy(task=task, galaxy=galaxy)
    else:
        # set `task.module_fqcn` by using galaxy FQCN list
        for filename, playbook in input_data.playbooks.items():
            for task in playbook.tasks:
                embed_module_info_with_galaxy(task=task, galaxy=galaxy)

        for filename, taskfile in input_data.taskfiles.items():
            for task in taskfile.tasks:
                embed_module_info_with_galaxy(task=task, galaxy=galaxy)

        for role_name, role in input_data.roles.items():
            for filename, taskfile in role.taskfiles.items():
                for task in taskfile.tasks:
                    embed_module_info_with_galaxy(task=task, galaxy=galaxy)

    return input_data


# make policy input data by scanning target project
def make_policy_input_with_scan(target_path: str, metadata: dict = {}, variables: Variables = None) -> Dict[str, List[PolicyInput]]:
    fpath = ""
    dpath = ""
    if os.path.isfile(target_path):
        fpath = os.path.abspath(target_path)
    else:
        dpath = os.path.abspath(target_path)

    runtime_data = RuntimeData.load(dir=target_path)

    kwargs = dict(
        input_types=[
            InputTypeTask,
            InputTypePlay,
            InputTypeRole,
        ],
        metadata=metadata,
        runtime_data=runtime_data,
        variables=variables,
    )
    if fpath:
        yaml_str = ""
        with open(fpath, "r") as file:
            yaml_str = file.read()
        kwargs["yaml_str"] = yaml_str
    elif dpath:
        kwargs["project_dir"] = dpath
    else:
        raise ValueError(f"`{target_path}` does not exist")
    policy_input = scan_project(**kwargs)

    return policy_input


def make_policy_input_for_task_result(task_result: TaskResult = None) -> Dict[str, List[PolicyInput]]:
    policy_input_task_result = PolicyInput.from_task_result(task_result=task_result)
    policy_input = {
        "task_result": policy_input_task_result,
    }
    return policy_input
