import json
import boto3
import logging
import os
import urllib.request
import time
import datetime
from jose import jwk, jwt
from jose.utils import base64url_decode
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key

aws_environment = os.environ['AWSENV']

if aws_environment == "AWS_SAM_LOCAL":
    client = boto3.client('dynamodb', endpoint_url="http://docker.for.mac.localhost:8000")
    dynamodb = boto3.resource('dynamodb', endpoint_url="http://docker.for.mac.localhost:8000")
elif aws_environment == "AWS_SAM_LOCAL_UNITTEST":
    client = boto3.client('dynamodb', endpoint_url="http://localhost:8000")
    dynamodb = boto3.resource('dynamodb', endpoint_url="http://localhost:8000")
else:
    client = boto3.client('dynamodb')
    dynamodb = boto3.resource('dynamodb')

table_name ='TagesdashboardTasks'
table = dynamodb.Table(table_name)
logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)

#TODO Move to Config file
region = 'eu-central-1'
userpool_id = os.environ['USERPOOL']
app_client_id = os.environ['CLIENT_ID']
keys_url = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(region, userpool_id)
with urllib.request.urlopen(keys_url) as f:
    response = f.read()
keys = json.loads(response.decode('utf-8'))['keys']

def lambda_handler(event, context):
    access_token_header = event['headers'].get('Authorization', None)
    if access_token_header is None:
        return json_response(400, {
            "status": "BadRequest",
            "message": "No auth token found."
        })
    access_token_header = access_token_header.split(' ')
    if len(access_token_header) != 2 or access_token_header[0] != 'Bearer':
        return json_response(400, {
            "status": "BadRequest",
            "message": "Invalid auth token."
        })
    access_token = access_token_header[1]
    headers = jwt.get_unverified_headers(access_token)
    kid = headers['kid']
    key_index = -1
    for i in range(len(keys)):
        if kid == keys[i]['kid']:
            key_index = i
            break
    if key_index == -1:
        return json_response(500, {
            'status': 'ServerSideError',
            'message': 'JWT public key not found'
        })
    public_key = jwk.construct(keys[key_index])
    message, encoded_signature = str(access_token).rsplit('.', 1)
    decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
    if not public_key.verify(message.encode('utf-8'), decoded_signature):
        return json_response(500, {
            'status': 'ServerSideError',
            'message': 'JWT Signature verification failed'
        })
    claims = jwt.get_unverified_claims(access_token)
    if time.time() > claims['exp']:
        return json_response(400, {
            'status': 'BadRequest',
            'message': 'JWT token expired'
        })
    if claims['aud'] != app_client_id:
        return json_response(400, {
            'status': 'BadRequest',
            'message': 'JWT token not issued for this audience'
        })
    
    assignee = claims.get('cognito:username', None)
    if assignee is None:
        return json_response(400, {
            'status': 'BadRequest',
            'message': 'No Cognito user found in JWT'
        })

    try:
        response = table.query(KeyConditionExpression=Key("Assignee").eq(assignee))["Items"]
        response_body = []
        for item in response:
            response_body.append({
                "Id": item["Id"],
                "Summary": item["Summary"],
                "CreateTime": datetime.datetime.fromtimestamp(float(item["CreateTime"])).strftime('%d %b %Y %H:%M:%S'),
                "DueDate": datetime.datetime.fromtimestamp(float(item["DueDate"])).strftime('%d %b %Y %H:%M:%S'),
                "Status": item["Status"]
            })
        return json_response(200, {
                "tasks": response_body
        })
    except ClientError as err:
        LOGGER.error("Could not fetch from table %s.  Reason:  %s:  %s", table_name,
                     err.response["Error"]["Code"],
                     err.response["Error"]["Message"])
        return json_response(500, None, True, err)
    
def json_response(code, body, isError=False, err=None):
    if isError:
        message = None
        errorCode = code
        if err is None:
            message = "Request Failed"
        else:
            errorCode = err.response["Error"]["Code"]
            message = err.response["Error"]["Message"]
        return {
            "statusCode": code,
            "body": {
                "status": "ERROR",
                "code": errorCode,
                "message": message
            }
        }
    return {
        "statusCode": code,
        "body": json.dumps(body)
    }