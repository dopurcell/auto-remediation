import json
import os
import subprocess
import boto3
import requests


def log(s):
    if os.environ['DEBUG']:
        print(s)

# Mapping of account number to AWS CLI profile. This is used to run each remediation with the appropriate profile


account_number_to_profile = {
}

sqs = boto3.resource('sqs')
queue = sqs.get_queue_by_name(QueueName=os.environ['SQS_QUEUE_NAME'])

# Read all queue messages
all_messages = []
message_batch = queue.receive_messages(MaxNumberOfMessages=10)

while len(message_batch) > 0:
    all_messages.extend(message_batch)
    message_batch = queue.receive_messages(MaxNumberOfMessages=10)
for message in all_messages:
    try:
        alert_info = json.loads(message.body)
        log(f'processing alert: {alert_info}')
    except json.JSONDecodeError as e:
        print(f'Can\'t parse queue message: {e.msg}')
        continue
    alert_id = alert_info['alertId']
    account_id = alert_info['account']['id']
    log(f'alert id: {alert_id}, account id: {account_id}')
    if 'remediable' in alert_info['metadata'] and alert_info['metadata']['remediable'] is False:
        log(f'Remediation is not supported for the alert: {alert_id}')
        continue
    try:
        log(f'getting remediation steps for the alert')
        r = requests.post(
            verify=False,
            url=f'{os.environ["API_ENDPOINT"]}/api/v1/permission/alert/remediation',
            data=json.dumps({
                "alerts": [
                    alert_id
                ]
            }),
            headers={
                'x-redlock-auth': os.environ['AUTH_KEY'],
                'Content-Type': 'application/json'
            }
        )
    except requests.exceptions.RequestException as e:
        print(f'Can\'t make request to the remediation api: {e.strerror}')
        continue
    if r.status_code != 200:
        print(f'Error from the remediation API for the alert id: {alert_id}')
        continue
    cli_commands = r.json()['alertIdVsCliScript'][alert_id]
    log(f'cli commands: {cli_commands}')
    try:
        log(f'running the CLI commands')
        aws_cli = subprocess.Popen(
            cli_commands,
            env=dict(os.environ, AWS_PROFILE=account_number_to_profile.get(account_id)),
            shell=True
        )
    except OSError as e:
        print(f'Can\'t run cli commands: {e.strerror}')
        continue
    aws_cli.communicate()
    if aws_cli.returncode != 0:
        print(f'Can\'t run cli commands: {cli_commands}')
        continue
    log("Deleting message")
    message.delete()
