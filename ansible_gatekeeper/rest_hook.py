import logging
import jsonpickle
import argparse
from flask import Flask, request
from ansible_gatekeeper.models import (
    PolicyEvaluator,
    EvalTypeRest,
    ResultFormatter,
    FORMAT_REST,
)


app = Flask(__name__)

log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)
app.logger.disabled = True
log.disabled = True

parser = argparse.ArgumentParser(description="TODO")
parser.add_argument("--policy-dir", help="path to a directory containing policies to be evaluated")
args = parser.parse_args()

evaluator = PolicyEvaluator(policy_dir=args.policy_dir)
formatter = ResultFormatter(format_type=FORMAT_REST)


@app.route("/", methods=["GET", "POST"])
def index():
    data = {}
    headers = {}
    for key, val in request.headers.items():
        headers[key] = val
    data["headers"] = headers
    data["path"] = request.path
    data["method"] = request.method
    data["data"] = request.json if request.mimetype == "application/json" else None

    print("[DEBUG] Received POST data:", data["data"])

    result = evaluator.run(
        eval_type=EvalTypeRest,
        target_data=data,
    )
    formatter.print(result=result)

    return jsonpickle.encode(result, make_refs=False)


if __name__ == "__main__":
    app.run(debug=True)
