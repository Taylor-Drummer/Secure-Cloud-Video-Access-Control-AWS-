import json
import boto3
import base64
import datetime
import rsa

secretsmanager = boto3.client('secretsmanager')
cognito = boto3.client('cognito-idp')

USER_POOL_ID = "REPLACE_ME"
APPROVED_GROUP = "approved-viewers"
CLOUDFRONT_DOMAIN = "REPLACE_ME"
KEY_PAIR_ID = "REPLACE_ME"
SECRET_NAME = "video-portfolio-cloudfront-private-key"

def get_private_key():
    response = secretsmanager.get_secret_value(SecretId=SECRET_NAME)
    return response['SecretString']

def rsa_signer(message):
    private_key_pem = get_private_key()
    key = rsa.PrivateKey.load_pkcs1(private_key_pem.encode('utf8'))
    return rsa.sign(message, key, 'SHA-1')

def is_user_approved(username):
    try:
        response = cognito.admin_list_groups_for_user(
            Username=username,
            UserPoolId=USER_POOL_ID
        )
        group_names = [g['GroupName'] for g in response['Groups']]
        return APPROVED_GROUP in group_names
    except cognito.exceptions.UserNotFoundException:
        return False

def lambda_handler(event, context):
    params = event.get('queryStringParameters') or {}
    username = params.get('username')

    if not username:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Missing username parameter'})
        }

    approved = is_user_approved(username)

    if not approved:
        return {
            'statusCode': 403,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'result': 'DENIED',
                'username': username,
                'reason': 'User is not a member of approved-viewers group'
            })
        }

    expires = int((datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp())
    policy = {
        "Statement": [{
            "Resource": f"https://{CLOUDFRONT_DOMAIN}/video/*",
            "Condition": {
                "DateLessThan": {"AWS:EpochTime": expires}
            }
        }]
    }
    policy_json = json.dumps(policy, separators=(',', ':')).encode('utf8')
    signature = rsa_signer(policy_json)

    def url_safe_b64(data):
        return base64.b64encode(data).replace(b'+', b'-').replace(b'=', b'_').replace(b'/', b'~').decode('utf8')

    cookies = {
        'CloudFront-Policy': url_safe_b64(policy_json),
        'CloudFront-Signature': url_safe_b64(signature),
        'CloudFront-Key-Pair-Id': KEY_PAIR_ID
    }

    return {
        'statusCode': 200,
        'headers': {'Content-Type': 'application/json'},
        'body': json.dumps({
            'result': 'GRANTED',
            'username': username,
            'cookies': cookies,
            'video_url': f"https://{CLOUDFRONT_DOMAIN}/video/demo.mp4"
        })
    }