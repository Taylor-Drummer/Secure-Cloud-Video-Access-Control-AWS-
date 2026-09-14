Secure Cloud Video Access Control (AWS)

A serverless, identity-aware video delivery system that proves a private video can be securely gated behind real authentication and authorization, with zero third-party hosting platform, built entirely on native AWS services.

Live demo flow: click a link, log in, and get automatically granted or denied access based on group membership. No manual steps, no public files, no "unlisted link" security theater.

Note on placeholders: account ID, bucket name, domain names, and key material below are shown as XXXXXXXXXX placeholders. The private key used in this project has been rotated since the screenshots and build below were taken. The project itself has since been fully decommissioned, see the Teardown section at the bottom for the full process.

Architecture
User -> Cognito Hosted UI (login)
     -> callback.html (extracts token, calls API)
     -> API Gateway -> Lambda (checks Cognito group membership)
                     -> if approved: signs CloudFront cookie policy
     -> Browser stores signed cookie
     -> CloudFront (validates signature via Trusted Key Group)
     -> S3 (private, reachable only via CloudFront Origin Access Control)

(Screenshot: architecture diagram)

Screenshots
Before Authorization	After Authorization
(Screenshot: direct S3 URL, 403 Forbidden)	(Screenshot: video playing)
(Screenshot: CloudFront URL, no cookies, 403)	(Screenshot: DevTools showing 3 signed cookies)
Access Control Proof	Live Flow
(Screenshot: Cognito console, approved-viewers group, 2/3 users)	(Screenshot: one click login link)
	(Screenshot: Cognito Hosted UI login screen)
	(Screenshot: TLS certificate showing CloudFront)
Build Steps
1. Private S3 bucket

Storage layer. Public access fully blocked at the bucket level, this is the foundation everything else builds on.

bash
aws s3api create-bucket --bucket XXXXXXXXXX --region us-east-1
aws s3api put-public-access-block --bucket XXXXXXXXXX \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

Proof it worked: curl -I against the raw S3 URL returns 403 Forbidden, confirmed before CloudFront was even created.

2. CloudFront with Origin Access Control

CDN layer. An Origin Access Control (OAC) is the only entity allowed to read the bucket, not even the AWS console user can browse it directly.

bash
aws cloudfront create-origin-access-control --origin-access-control-config \
  Name=video-oac,SigningBehavior=always,SigningProtocol=sigv4,OriginAccessControlOriginType=s3

aws cloudfront create-distribution --distribution-config file://distribution-config.json

The bucket policy then trusts only this specific distribution, by ARN, not any CloudFront distribution:

json
{
  "Effect": "Allow",
  "Principal": { "Service": "cloudfront.amazonaws.com" },
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::XXXXXXXXXX/*",
  "Condition": {
    "StringEquals": { "AWS:SourceArn": "arn:aws:cloudfront::XXXXXXXXXX:distribution/XXXXXXXXXX" }
  }
}

Proof it worked: CloudFront URL returns 200 OK with x-cache: Miss from cloudfront, direct S3 URL still returns 403.

3. CloudFront Trusted Key Group, the actual lock

This is the layer that turns a public CDN URL into one that requires proof of authorization. An RSA key pair is generated, the public half is registered with CloudFront, and the distribution is updated to reject any request without a validly signed cookie.

bash
openssl genrsa -out private_key.pem 2048
openssl rsa -pubout -in private_key.pem -out public_key.pem

aws cloudfront create-public-key --public-key-config \
  Name=video-portfolio-key,CallerReference=XXXXXXXXXX,EncodedKey="$(cat public_key.pem)"

aws cloudfront create-key-group --key-group-config \
  Name=approved-viewers-keygroup,Items=XXXXXXXXXX

The distribution's cache behavior is then updated to require this key group:

json
"TrustedKeyGroups": { "Enabled": true, "Quantity": 1, "Items": ["XXXXXXXXXX"] }

Proof it worked: immediately after this change, the same CloudFront URL that worked in step 2 now returns 403 Forbidden, because no cookie exists yet. This is the correct, expected result, the lock is now live.

4. Cognito, identity and authorization

Identity layer. Self signup is disabled, only admin provisioned accounts exist. A group (approved-viewers) determines who is actually authorized, separate from who can log in.

bash
aws cognito-idp create-user-pool --pool-name video-portfolio-pool \
  --auto-verified-attributes email --username-attributes email \
  --admin-create-user-config AllowAdminCreateUserOnly=true

aws cognito-idp create-group --group-name approved-viewers --user-pool-id XXXXXXXXXX

aws cognito-idp admin-create-user --user-pool-id XXXXXXXXXX --username user@example.com \
  --user-attributes Name=email,Value=user@example.com Name=email_verified,Value=true \
  --message-action SUPPRESS

aws cognito-idp admin-add-user-to-group --user-pool-id XXXXXXXXXX \
  --username user@example.com --group-name approved-viewers

Three test identities were used to validate every outcome: an approved user, an existing but unapproved user, and a nonexistent user.

5. Lambda, the authorization decision

This is the bridge between who someone is, from Cognito, and whether they are allowed to see this, for CloudFront. Given a username, it checks group membership and, if approved, signs a time limited access policy using the private key.

python
def is_user_approved(username):
    try:
        response = cognito.admin_list_groups_for_user(Username=username, UserPoolId=USER_POOL_ID)
        return APPROVED_GROUP in [g['GroupName'] for g in response['Groups']]
    except cognito.exceptions.UserNotFoundException:
        return False

def lambda_handler(event, context):
    username = event.get('queryStringParameters', {}).get('username')
    if not is_user_approved(username):
        return {'statusCode': 403, 'body': json.dumps({'result': 'DENIED'})}

    # sign a CloudFront cookie policy valid for 1 hour
    signature = rsa_signer(policy_json)
    return {'statusCode': 200, 'body': json.dumps({'result': 'GRANTED', 'cookies': {...}})}

(Full source: lambda_function.py in this repo)

Proof it worked: three direct invokes. Approved user returned GRANTED with signed cookies, unapproved user returned DENIED, and a nonexistent user also returned DENIED, the same response by design, since the system never reveals whether an account exists.

6. API Gateway and front end

A minimal HTTP API exposes the Lambda to a browser, and two static pages complete the flow: index.html, the one click login link, and callback.html, which extracts the login token, calls the API, and sets the signed cookies.

bash
aws apigatewayv2 create-api --name video-portfolio-api --protocol-type HTTP \
  --target arn:aws:lambda:us-east-1:XXXXXXXXXX:function:video-portfolio-authorizer

aws lambda add-permission --function-name video-portfolio-authorizer \
  --statement-id apigateway-invoke --action lambda:InvokeFunction \
  --principal apigateway.amazonaws.com \
  --source-arn "arn:aws:execute-api:us-east-1:XXXXXXXXXX:XXXXXXXXXX/*/*"
javascript
// callback.html, core logic
fetch(API_URL + '?username=' + encodeURIComponent(username))
  .then(res => res.json())
  .then(data => {
    if (data.result === 'GRANTED') {
      document.cookie = 'CloudFront-Policy=' + data.cookies['CloudFront-Policy'] + '; path=/; secure';
      document.cookie = 'CloudFront-Signature=' + data.cookies['CloudFront-Signature'] + '; path=/; secure';
      document.cookie = 'CloudFront-Key-Pair-Id=' + data.cookies['CloudFront-Key-Pair-Id'] + '; path=/; secure';
      window.location.href = data.video_url;
    }
  });
Troubleshooting Log

Two real issues came up during the build. Both are the kind of thing no tutorial mentions, and both required actually reading the error rather than guessing.

Issue 1: RSA key format mismatch

Error:

ValueError: No PEM start marker "b'-----BEGIN RSA PRIVATE KEY-----'" found

Cause: OpenSSL generated the private key in PKCS8 format (-----BEGIN PRIVATE KEY-----), but Python's rsa library specifically requires the older PKCS1 format (-----BEGIN RSA PRIVATE KEY-----).

Fix:

bash
openssl rsa -in private_key.pem -traditional -out private_key_pkcs1.pem
aws secretsmanager update-secret --secret-id XXXXXXXXXX --secret-string file://private_key_pkcs1.pem

Verification: head -1 private_key_pkcs1.pem confirmed the correct header before re-testing.

Issue 2: Cookie domain scoping caused intermittent 403s

Symptom: Manually set cookies, added through DevTools, worked, but the automated login flow intermittently produced a 403 even for approved users. The Application tab showed duplicate cookies, one scoped to .domain.com with a leading dot, one to domain.com with none.

Cause: callback.html explicitly set domain=<cloudfront-domain> when writing cookies via JavaScript. Since the page was already being served from that exact domain, this created a second, differently scoped cookie that conflicted with CloudFront's signature validation.

Fix: Removed the explicit domain attribute entirely, letting the browser default to the current host, then invalidated the CloudFront cache to clear a stale cached version of the page:

bash
aws s3 cp callback.html s3://XXXXXXXXXX/public/callback.html --content-type text/html
aws cloudfront create-invalidation --distribution-id XXXXXXXXXX --paths "/public/callback.html"
Security Notes
No public self signup, all accounts are admin provisioned
Denied responses are identical whether a user does not exist or simply is not approved, this prevents account enumeration
The signing private key lives only in AWS Secrets Manager, never in code or version control
All access is time limited, a 1 hour signed policy window
Future Enhancements
Geo restriction: CloudFront's native geo restriction feature to allow U.S. only access
Access logging: CloudFront access logs to S3 for a full audit trail of every request, including geographic origin
Key rotation: scripted or scheduled rotation of the signing key pair
Auth flow upgrade: move from implicit OAuth flow to authorization code with PKCE for production grade hardening
Teardown and Deconstruction

This project was built as a proof of concept, not a standing production system, so full and verified deletion afterward matters just as much as the build itself. Leaving resources running after a demo has ended is both a needless cost and a needless attack surface. This section documents the exact sequence used to decommission everything, in the order it has to happen, since several of these resources depend on each other and cannot be deleted out of order.

Deletion order and why it matters

CloudFront has to be disabled before it can be deleted, and nothing that depends on it, like the trusted key group, can be removed while it is still attached to a live distribution. Lambda has to be detached from API Gateway's permission grant before either is cleanly gone. An IAM role cannot be deleted while it still has policies attached to it. Cognito's domain has to go before the user pool itself. S3 buckets cannot be deleted while anything is still inside them. The sequence below respects all of these dependencies.

Step by step

1. Disable CloudFront before deleting it.

bash
aws cloudfront get-distribution-config --id XXXXXXXXXX > final-config.json
# edit the config file, set "Enabled": false, save as final-config-disabled.json
aws cloudfront update-distribution --id XXXXXXXXXX \
  --distribution-config file://final-config-disabled.json --if-match XXXXXXXXXX
aws cloudfront get-distribution --id XXXXXXXXXX --query 'Distribution.Status' --output text

Wait until status shows Deployed, disabling is its own deploy cycle, then delete it using the new ETag returned by the update call.

bash
aws cloudfront delete-distribution --id XXXXXXXXXX --if-match XXXXXXXXXX

2. Remove the trusted key group and public key that supported it.

bash
aws cloudfront get-key-group --id XXXXXXXXXX
aws cloudfront delete-key-group --id XXXXXXXXXX --if-match XXXXXXXXXX

aws cloudfront get-public-key --id XXXXXXXXXX
aws cloudfront delete-public-key --id XXXXXXXXXX --if-match XXXXXXXXXX

3. Remove API Gateway and the Lambda function.

bash
aws apigatewayv2 delete-api --api-id XXXXXXXXXX
aws lambda delete-function --function-name video-portfolio-authorizer

4. Remove the secret, forcing immediate deletion rather than the default recovery window.

bash
aws secretsmanager delete-secret --secret-id video-portfolio-cloudfront-private-key \
  --force-delete-without-recovery

5. Remove the IAM role, detaching every attached policy first.

bash
aws iam delete-role-policy --role-name video-portfolio-lambda-role --policy-name SecretAccess
aws iam delete-role-policy --role-name video-portfolio-lambda-role --policy-name CognitoReadAccess
aws iam detach-role-policy --role-name video-portfolio-lambda-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
aws iam delete-role --role-name video-portfolio-lambda-role

6. Remove Cognito, the domain first, then the pool, which takes its users and groups with it.

bash
aws cognito-idp delete-user-pool-domain --domain XXXXXXXXXX --user-pool-id XXXXXXXXXX
aws cognito-idp delete-user-pool --user-pool-id XXXXXXXXXX

7. Empty and remove the S3 bucket.

bash
aws s3 rm s3://XXXXXXXXXX --recursive
aws s3api delete-bucket --bucket XXXXXXXXXX --region us-east-1
Verifying nothing was missed

Billing dashboards like Cost Explorer lag real usage by roughly 24 hours, so they confirm cost has stopped after the fact but are not a reliable real time check. The faster and more direct way to confirm a clean teardown is asking each service directly whether anything still exists.

bash
aws cloudfront list-distributions --query 'DistributionList.Items[].Id' --output text
aws s3api list-buckets --query 'Buckets[].Name' --output text
aws lambda list-functions --query 'Functions[].FunctionName' --output text
aws apigatewayv2 get-apis --query 'Items[].Name' --output text
aws cognito-idp list-user-pools --max-results 20 --query 'UserPools[].Name' --output text
aws iam list-roles --query 'Roles[].RoleName' --output text
aws secretsmanager list-secrets --query 'SecretList[].Name' --output text

A clean teardown means the project's names do not appear in any of these seven results. The IAM roles list will still show a handful of default, AWS managed service roles that exist on every account, those are not something any user creates and are expected to remain.

One additional note on billing visibility itself: IAM users and roles cannot see Cost Explorer or billing pages at all by default, regardless of which policies are attached to them. This is an account level setting, not an IAM permission. It has to be enabled by the root user, under Account settings, in a section called IAM User and Role Access to Billing Information. Attaching billing policies to a role does nothing until that root level toggle is turned on.

This project was fully decommissioned on September 13, 2026, following the sequence above, with zero resources left running.

Stack

Amazon S3, CloudFront (OAC, Trusted Key Groups), Cognito, Lambda (Python), API Gateway, Secrets Manager, IAM, AWS CLI

Content

PDF

aws cloudfront get-distribution-config --id $DIST_ID > current-config.json ~ $ cat current-config.json { "ETag": "E23ZP02F085DFQ", "DistributionConfig": { "CallerReference": "video-dist-1789183994", "Aliases": { "Quantity": 0 }, "DefaultRootObject

PASTED

aws cloudfront update-distribution \ > --id $DIST_ID \ > --distribution-config file://updated-config-2.json \ > --if-match $DIST_ETAG_2 { "ETag": "E3UN6WX5RRO2AG", "Distribution": { "Id": "E36PBEHOQ0C5FG", "ARN": "arn:aws:cloudfront::930628639096:distribution/E36PBEHOQ0

PASTED

lambda_function.py

89 lines

PY

callback.html

43 lines

HTML

index.html

12 lines

HTML
