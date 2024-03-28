import json
import argparse
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from ansible_gatekeeper.models import (
    PolicyEvaluator,
    EvalTypeEvent,
    ResultFormatter,
    FORMAT_EVENT_STREAM,
)
from ansible_gatekeeper.rego_data import Event


def is_job_event_file(path: str) -> bool:
    return "/job_events/" in path and path.endswith(".json") and not path.endswith("-partial.json")


class RunnerEventHandler(FileSystemEventHandler):
    def __init__(self, policy_dir: str):
        self.evaluator = PolicyEvaluator(policy_dir=policy_dir)
        self.formatter = ResultFormatter(format_type=FORMAT_EVENT_STREAM)

    def on_moved(self, event):
        if event.is_directory:
            return

        dest_path = event.dest_path
        if not is_job_event_file(dest_path):
            return

        job_event_json = None
        with open(dest_path, "r") as f:
            job_event_json = json.load(f)
        if not job_event_json:
            return

        job_event = Event.from_ansible_jobevent(event=job_event_json)
        eval_result = self.evaluator.run(
            eval_type=EvalTypeEvent,
            event=job_event,
        )
        self.formatter.print(result=eval_result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TODO")
    parser.add_argument("--runner-dir", help="path to a directory for ansible-runner to output job events")
    parser.add_argument("--policy-dir", help="path to a directory containing policies to be evaluated")
    args = parser.parse_args()

    observer = Observer()
    event_handler = RunnerEventHandler(policy_dir=args.policy_dir)

    observer.schedule(event_handler, path=args.runner_dir, recursive=True)
    observer.start()

    print(f"Watching Job event files under `{args.runner_dir}`")

    try:
        while True:
            pass
    except KeyboardInterrupt:
        observer.stop()

    observer.join()
