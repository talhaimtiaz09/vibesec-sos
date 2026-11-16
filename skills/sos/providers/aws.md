# AWS

## What disappears first

| # | Source | Kept for | How to save it |
|---|---|---|---|
| 1 | **Running attacker resources** (EC2 miners, Lambdas) | Until someone terminates them | **Snapshot before stopping** (EBS snapshot / note instance IDs) |
| 2 | **Lambda / app logs in CloudWatch** | Log group setting (default: never expire, but check) | `aws logs filter-log-events` (below) |
| 3 | **RDS automated backups** | Usually 1-7 days | Take a manual snapshot now (asks first) |
| 4 | **CloudTrail Event history**: management events (who called which API) | **90 days**, per region, always on | `aws cloudtrail lookup-events` (below), in **every region used** |
| 5 | **S3 object reads, Lambda invokes** (data events) | **Not recorded** unless a trail with data events existed before | Note it as a limit |

Global services (IAM, STS, CloudFront) log to **us-east-1**. Check there even if you only use another region.

## Stop the bleeding (reversible)

- **Leaked access key:** deactivate it, don't delete it. You need the key ID to trace its use.
  `aws iam update-access-key --user-name <user> --access-key-id <AKIA...> --status Inactive` (asks first)
- AWS may email you and attach a **quarantine policy** to the user automatically. Leave it there.
- **Attacker-created IAM users/keys/roles:** deactivate keys, detach policies or attach a deny-all policy. Don't delete.
- **Crypto-mining instances:** snapshot the volumes, then **stop** them (not terminate). Check **every region**.
- **Bill exploding:** set a budget alert (Billing → Budgets), deactivate keys, stop resources. Open a case with AWS Support. They often help with fraud charges.
- **Root account:** make sure MFA is on and the email/password are still yours.

## Save the evidence (read-only)

```bash
aws sts get-caller-identity
aws ec2 describe-regions --query 'Regions[].RegionName' --output text
# Every API call made with the leaked key (repeat per region; IAM calls are in us-east-1)
aws cloudtrail lookup-events --region us-east-1 \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$LEAKED_KEY_ID" \
  --start-time 2026-01-01T00:00:00Z --max-results 50 --output json
aws iam list-users --output json
aws iam list-access-keys --user-name <user>
aws iam get-account-authorization-details --output json          # every user, role, policy
for r in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  aws ec2 describe-instances --region "$r" --query 'Reservations[].Instances[].[InstanceId,LaunchTime,InstanceType,State.Name]' --output text; done
aws logs filter-log-events --log-group-name /aws/lambda/<fn> --start-time <epoch-ms> --output json
aws ce get-cost-and-usage --time-period Start=2026-01-01,End=2026-01-31 --granularity DAILY --metrics UnblendedCost --group-by Type=DIMENSION,Key=SERVICE
```

Snapshots (they ask first, and they're safe):

```bash
aws ec2 create-snapshot --volume-id <vol> --description "incident <id> evidence"
aws rds create-db-snapshot --db-instance-identifier <db> --db-snapshot-identifier incident-<id>
```

## What to look for

- `CreateUser`, `CreateAccessKey`, `AttachUserPolicy`, `CreateLoginProfile`: persistence
- `RunInstances` in regions you never use; large GPU instance types
- `GetSecretValue`, `ListBuckets`, `GetObject` (if data events exist): data access
- `ConsoleLogin` from unknown IPs; `StopLogging` / `DeleteTrail` (covering tracks)

## Don't

- Don't terminate instances or delete users, keys or log groups.
- Don't close the account: you lose the logs and the ability to dispute charges.
