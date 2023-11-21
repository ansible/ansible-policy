import os
import jsonpickle
from dataclasses import dataclass, field
from typing import List, Dict

from ansible_gatekeeper.utils import get_module_name_from_task
from sage_scan.pipeline import SagePipeline
from sage_scan.models import (
    BecomeInfo,
    Task as SageTask,
    TaskFile as SageTaskFile,
    Role as SageRole,
    Project as SageObjProject,
    Playbook as SagePlaybook,
    SageProject,
)
from sage_scan.process.utils import (
    get_tasks_in_playbook,
    get_tasks_in_taskfile,
    get_taskfiles_in_role,
)


sage_pipeline = SagePipeline(silent=True)


_util_rego_path = os.path.join(os.path.dirname(__file__), "rego/utils.rego")
_util_rego = ""
with open(_util_rego_path, "r") as util_rego_file:
    _util_rego = util_rego_file.read()


@dataclass
class PolicyInput(object):
    source: dict = field(default_factory=dict)
    project: any = None
    playbooks: dict = field(default_factory=dict)
    taskfiles: dict = field(default_factory=dict)
    roles: dict = field(default_factory=dict)
    # TODO: imeplement attrs below
    # modules
    # files
    # others?

    def from_sage_project(project: SageProject):
        p_input = PolicyInput()
        p_input.source = project.source
        p_input.playbooks = {
            playbook.filepath: Playbook.from_sage_object(obj=playbook, proj=project)
            for playbook in project.playbooks
        }
        p_input.taskfiles = {
            taskfile.filepath: TaskFile.from_sage_object(obj=taskfile, proj=project)
            for taskfile in project.taskfiles
        }
        p_input.roles = {
            role.filepath: Role.from_sage_object(obj=role, proj=project)
            for role in project.roles
        }
        if project.projects:
            p_input.project = project.projects[0]
        return p_input
            

    def to_json(self, **kwargs):
        kwargs["value"] = self
        kwargs["make_refs"] = False
        kwargs["separators"] = (',', ':')
        return jsonpickle.encode(**kwargs)


    @staticmethod
    def from_json(json_str: str="", fpath: str=""):
        if not json_str and fpath:
            with open(fpath, "r") as file:
                json_str = file.read()

        p_input = jsonpickle.decode(json_str)
        if not isinstance(p_input, PolicyInput):
            raise ValueError(f"a decoded object is not a PolicyInput, but {type(p_input)}")
        return p_input
    

# make policy input data by scanning target project
def make_policy_input(target_path: str, metadata: dict={}) -> dict:
    fpath = ""
    dpath = ""
    if os.path.isfile(target_path):
        fpath = os.path.abspath(target_path)
    else:
        dpath = os.path.abspath(target_path)
    
    policy_input = None
    if fpath:
        yaml_str = ""
        with open(fpath, "r") as file:
            yaml_str = file.read()
        policy_input = scan_project(yaml_str=yaml_str, metadata=metadata)
    elif dpath:
        policy_input = scan_project(project_dir=dpath, metadata=metadata)
    else:
        raise ValueError(f"`{target_path}` does not exist")
    
    return policy_input


def scan_project(yaml_str: str="", project_dir: str="", metadata: dict=None, output_dir: str=""):
    _metadata = {}
    if metadata:
        _metadata = metadata
    
    project = None
    if yaml_str:
        project = sage_pipeline.run(
            raw_yaml=yaml_str,
            source=_metadata,
            output_dir=output_dir,
        )
    elif project_dir:
        project = sage_pipeline.run(
            target_dir=project_dir,
            source=_metadata,
            output_dir=output_dir,
        )
    
    if not project:
        raise ValueError("failed to scan the target project; project is None")

    policy_input = PolicyInput.from_sage_project(project=project)
    if not policy_input:
        raise ValueError("failed to scan the target project; policy_input is None")
    
    policy_input_json = policy_input.to_json()
    return policy_input_json


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
    def from_sage_object(cls, obj: SageTask):
        new_obj = Task()
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
    def from_sage_object(cls, obj: SagePlaybook, proj: SageProject):
        new_obj = Playbook()
        if hasattr(obj, "__dict__"):
            for k, v in obj.__dict__.items():
                if hasattr(new_obj, k):
                    setattr(new_obj, k, v)

        tasks = get_tasks_in_playbook(playbook=obj, project=proj)
        new_obj.tasks = [Task.from_sage_object(task) for task in tasks]

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
    def from_sage_object(cls, obj: SageTaskFile, proj: SageProject):
        new_obj = TaskFile()
        if hasattr(obj, "__dict__"):
            for k, v in obj.__dict__.items():
                if hasattr(new_obj, k):
                    setattr(new_obj, k, v)

        tasks = get_tasks_in_taskfile(taskfile=obj, project=proj)
        new_obj.tasks = [Task.from_sage_object(task) for task in tasks]

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
    def from_sage_object(cls, obj: SageRole, proj: SageProject):
        new_obj = Role()
        if hasattr(obj, "__dict__"):
            for k, v in obj.__dict__.items():
                if hasattr(new_obj, k):
                    setattr(new_obj, k, v)

        sage_taskfiles = get_taskfiles_in_role(role=obj, project=proj)
        new_obj.taskfiles = {
            sage_taskfile.filepath: TaskFile.from_sage_object(obj=sage_taskfile, proj=proj)
            for sage_taskfile in sage_taskfiles
        }

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
    def from_sage_object(cls, obj: SageObjProject):
        new_obj = Role()
        if hasattr(obj, "__dict__"):
            for k, v in obj.__dict__.items():
                if hasattr(new_obj, k):
                    setattr(new_obj, k, v)
        return new_obj