import os
import sys
import copy
import tempfile
import jsonpickle
import json
import yaml
from dataclasses import dataclass, field
from typing import List, Dict

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
    TaskFile as CoreTaskFile,
    Role as CoreRole,
    Playbook as CorePlaybook,
    ScanResult,
    VariableContainer,
)


scanner = AnsibleScanner(silent=True)


InputTypeTask = "task"
InputTypeProject = "project"


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
    policy_input = make_policy_input(target_path=workdir.name)
    workdir.cleanup()
    return policy_input, runner_jobdata_str


def load_input_from_project_dir(project_dir: str = ""):
    policy_input = make_policy_input(target_path=project_dir)
    return policy_input


def scan_project(
    input_type: str, yaml_str: str = "", project_dir: str = "", metadata: dict = None, runtime_data: RuntimeData = None, output_dir: str = ""
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

    if input_type == InputTypeProject:
        policy_input = PolicyInput.from_scan_result(project=project, runtime_data=runtime_data)
    elif input_type == InputTypeTask:
        policy_input = PolicyInput.from_scan_result(project=project, runtime_data=runtime_data, input_type=InputTypeTask)

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
class Playbook(object):
    type: str = "playbook"
    key: str = ""
    name: str = ""
    filepath: str = ""
    yaml_lines: str = ""
    role: str = ""
    collection: str = ""
    plays: list = field(default_factory=list)
    variables: dict = field(default_factory=dict)
    options: dict = field(default_factory=dict)

    tasks: List[Task] = field(default_factory=list)

    @classmethod
    def from_object(cls, obj: CorePlaybook, proj: ScanResult):
        new_obj = cls()
        if hasattr(obj, "__dict__"):
            for k, v in obj.__dict__.items():
                if hasattr(new_obj, k):
                    setattr(new_obj, k, v)

        tasks = proj.get_tasks_in_playbook(playbook=obj)
        new_obj.tasks = [Task.from_object(task, proj) for task in tasks]

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
class PolicyInput(object):
    source: dict = field(default_factory=dict)
    project: any = None
    playbooks: dict = field(default_factory=dict)
    taskfiles: dict = field(default_factory=dict)
    roles: dict = field(default_factory=dict)

    task: Task = None

    vars_files: dict = field(default_factory=dict)

    extra_vars: dict = field(default_factory=dict)

    variables: dict = field(default_factory=dict)

    # TODO: imeplement attrs below
    # modules
    # files
    # others?

    @staticmethod
    def from_scan_result(project: ScanResult, runtime_data: RuntimeData = None, input_type: str = ""):
        if input_type == InputTypeTask:
            base_input_list = PolicyInput.from_scan_result(project=project, runtime_data=runtime_data)
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
                p_input.task = task
                p_input_list.append(p_input)
            return p_input_list
        else:
            p_input = PolicyInput()
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

            variables = get_all_set_vars(project=project, common_vars=_common_vars)
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
            task_data_block = yaml.safe_load(self.task.yaml_lines)
            if task_data_block:
                data = task_data_block[0]
        except Exception:
            pass
        data["_agk"] = self
        kwargs["value"] = data
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
def make_policy_input(target_path: str, metadata: dict = {}) -> List[PolicyInput]:
    fpath = ""
    dpath = ""
    if os.path.isfile(target_path):
        fpath = os.path.abspath(target_path)
    else:
        dpath = os.path.abspath(target_path)

    runtime_data = RuntimeData.load(dir=target_path)

    policy_input = None
    if fpath:
        yaml_str = ""
        with open(fpath, "r") as file:
            yaml_str = file.read()
        policy_input = scan_project(input_type=InputTypeTask, yaml_str=yaml_str, metadata=metadata, runtime_data=runtime_data)
    elif dpath:
        policy_input = scan_project(input_type=InputTypeTask, project_dir=dpath, metadata=metadata, runtime_data=runtime_data)
    else:
        raise ValueError(f"`{target_path}` does not exist")

    return policy_input
