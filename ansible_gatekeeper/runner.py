import sys
from ansible_gatekeeper.eval import eval
from ansible_gatekeeper.utils import parse_runner_jobdata


def main():

    runner_jobdata_str = ""
    for line in sys.stdin:
        runner_jobdata_str += line

    parsed = parse_runner_jobdata(jobdata=runner_jobdata_str)
    filepath = parsed.get("filepath")
    print(filepath)


if __name__ == "__main__":
    main()