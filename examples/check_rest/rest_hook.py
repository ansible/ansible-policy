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
from ansible_gatekeeper.rego_data import APIRequest


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

    headers = {}
    for key, val in request.headers.items():
        headers[key] = val
    query_params = None
    if request.args:
        query_params = {}
        for key, val in request.args.items():
            query_params[key] = val
    post_data = request.json if request.mimetype == "application/json" else None
    rest_request = APIRequest(
        headers=headers,
        path=request.path,
        method=request.method,
        query_params=query_params,
        post_data=post_data,
    )

    print("[DEBUG] Received POST data:", post_data)
    result = evaluator.run(
        eval_type=EvalTypeRest,
        rest_request=rest_request,
    )
    formatter.print(result=result)

    return jsonpickle.encode(result, make_refs=False)


if __name__ == "__main__":
    app.run(debug=True)
