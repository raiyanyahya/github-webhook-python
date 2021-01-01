import logging
from flask import Flask, request
import hmac
from hashlib import sha1
from os import getenv

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

headers = {"Access-Control-Allow-Origin": "*", "Content-Type": "application/json"}

webhook_secret = getenv("github_webhook_secret")


def remove_repo_event(webhook_data):
    logging.info(
        "remove repo event triggered for repo %s "
        % webhook_data["repositories_removed"][0]["full_name"]
    )
    return


def add_repo_event(webhook_data):
    logging.info(
        "add repo event triggered for repo %s "
        % webhook_data["repositories_added"][0]["full_name"]
    )
    return


def push_repo_event(webhook_data):
    logging.info(
        "push repo event triggered for repo %s "
        % webhook_data["repository"]["full_name"],
    )
    return


def verify_signature(signature, body):
    try:
        secret = webhook_secret.encode()
        expected_signature = "sha1=" + hmac.new(secret, body, sha1).hexdigest()
    except Exception as e:
        logging.error("Exception caught when verifying signature ", str(e))
        return False
    return hmac.compare_digest(signature, expected_signature)


@app.route("/", methods=["POST"])
def github_webhook():
    if (
        request.method != "POST"
        or not request.headers.get("X-Github-Event")
        or not request.headers.get("X-Hub-Signature")
    ):
        logging.error("Mandatory headers or method type not post")
        return "UNAUTHORIZED", 403, headers
    if not verify_signature(request.headers.get("X-Hub-Signature"), request.data):
        logging.error("Signature verification failed")
        return "UNAUTHORIZED", 401, headers
    if (
        request.headers.get("X-Github-Event") != "push"
        and request.headers.get("X-Github-Event") != "installation_repositories"
    ):
        logging.error(
            "Unknown event from github  %s " % request.headers.get("X-Github-Event")
        )
        return "UNAUTHORIZED", 403, headers
    webhook_data = request.json
    if request.headers.get("X-Github-Event") == "push":
        push_repo_event(webhook_data)
    else:
        if webhook_data["action"] == "removed":
            remove_repo_event(webhook_data)
        elif webhook_data["action"] == "added":
            add_repo_event(webhook_data)
        else:
            logging.info("Unknown event received for ", webhook_data)
            return "UNKNOWN", 404, headers
    return "OK", 200, headers


if __name__ == "__main__":
    app.run(debug=True)
