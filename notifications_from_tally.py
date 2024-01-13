import base64
import hashlib
import hmac
import json
import socket

from flask import Flask, abort, request
from loguru import logger

webhook_server = Flask(__name__)
SECRET_KEY = "Your secret key there"


# Send JSON notification to socket
def send_notification(data):
    logger.debug(f"Send notif! {data}")
    host = "127.0.0.1"
    port = 8888

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))
        encoded_data = json.dumps(data).encode()
        client_socket.sendall(encoded_data)


# Extract needed data from huge JSON
def extract_json_to_message(json_data):
    requestor = json_data["data"]["fields"][0]["value"]
    task_name = json_data["data"]["fields"][1]["value"]
    task_description = json_data["data"]["fields"][2]["value"]
    place = json_data["data"]["fields"][9]["value"]
    due = json_data["data"]["fields"][8]["value"]
    time = json_data["data"]["fields"][7]["value"]
    phone = json_data["data"]["fields"][11]["value"]
    link = json_data["data"]["fields"][10]["value"]
    file = json_data["data"]["fields"][12]["value"]

    # There is multiple choice here,
    # so we check the selected value with all possible
    priority_id = json_data["data"]["fields"][5]["value"][0]
    priority_text = next(
        (
            option["text"]
            for option in json_data["data"]["fields"][5]["options"]
            if option["id"] == priority_id
        ),
        None,
    )

    category_id = json_data["data"]["fields"][6]["value"][0]
    category_text = next(
        (
            option["text"]
            for option in json_data["data"]["fields"][6]["options"]
            if option["id"] == category_id
        ),
        None,
    )

    # Build a message depending on what values ​​are available
    message = f"⚠️ <b>Новая заявка!</b> ⚠️ \n👤 {requestor}\n\n✉️ {task_name}"

    if task_description:
        message += f"\n{task_description}"
    message += f"\n\n{category_text} | {priority_text}"
    if due:
        message += f"\n📆 {due}"
        if time:
            message += f" | ⏰ <strong>{time}</strong>"
    elif time:
        message += f"\n⏰ <strong>{time}</strong>"
    if place:
        message += f"\n🌋 {place}"
    if phone:
        message += f"\n☎️ {phone}"
    if file:
        message += "\n💾 <b>Прикреплён файл!</b>"
    if link:
        message += f"\n🔗 {link}"

    return message


def verify_webhook(data, hmac_header):
    # Calculate HMAC
    digest = hmac.new(
        SECRET_KEY.encode("utf-8"), data, digestmod=hashlib.sha256
    ).digest()
    computed_hmac = base64.b64encode(digest)

    return hmac.compare_digest(computed_hmac, hmac_header.encode("utf-8"))


@webhook_server.route("/tally", methods=["POST"])
def webhook():
    # Get raw body
    data = request.get_data()
    # Compare HMACs
    verified = verify_webhook(data, request.headers.get("tally-signature"))

    if not verified:
        logger.debug("Something wrong!")
        abort(401)

    message = extract_json_to_message(request.get_json())
    send_notification({"tally": message})
    return ("", 200)


if __name__ == "__main__":
    webhook_server.run()
