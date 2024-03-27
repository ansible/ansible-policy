import sys
import json
import argparse
from ansible_gatekeeper.models import (
    PolicyEvaluator,
    ResultFormatter,
    FORMAT_EVENT_STREAM,
)


def load_event():
    for line in sys.stdin:
        yield json.loads(line)


def main():
    parser = argparse.ArgumentParser(description="TODO")
    parser.add_argument("--policy-dir", help="path to a directory containing policies to be evaluated")
    args = parser.parse_args()

    evaluator = PolicyEvaluator(policy_dir=args.policy_dir)
    formatter = ResultFormatter(format_type=FORMAT_EVENT_STREAM)
    for event in load_event():
        result = evaluator.run(
            eval_type="event",
            event=event,
        )
        formatter.print(result)


if __name__ == "__main__":
    main()
