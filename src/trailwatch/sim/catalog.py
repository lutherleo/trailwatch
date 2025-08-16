"""Static catalogues for the simulator: API vocabularies, user agents, regions and networks.

API tuples are ``(eventSource short name, eventName, readOnly)``. Only CloudTrail *management*
events are modelled (the default trail configuration); data events such as ``s3:GetObject`` are
out of scope.
"""

from __future__ import annotations

Api = tuple[str, str, bool]

REGIONS = (
    "us-east-1",
    "us-west-2",
    "eu-west-1",
    "eu-central-1",
    "ap-south-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "sa-east-1",
    "ca-central-1",
    "eu-north-1",
)

# --- benign vocabularies ---------------------------------------------------------------------
DEV_APIS: tuple[tuple[Api, float], ...] = (
    (("sts", "GetCallerIdentity", True), 4),
    (("s3", "ListBuckets", True), 6),
    (("s3", "GetBucketLocation", True), 3),
    (("s3", "GetBucketPolicy", True), 1),
    (("ec2", "DescribeInstances", True), 10),
    (("ec2", "DescribeSecurityGroups", True), 4),
    (("ec2", "DescribeSubnets", True), 2),
    (("ec2", "DescribeVpcs", True), 2),
    (("ec2", "StartInstances", False), 1),
    (("ec2", "StopInstances", False), 1),
    (("lambda", "ListFunctions20150331", True), 5),
    (("lambda", "GetFunction20150331v2", True), 4),
    (("lambda", "UpdateFunctionCode20150331v2", False), 2),
    (("logs", "DescribeLogGroups", True), 5),
    (("logs", "DescribeLogStreams", True), 4),
    (("cloudwatch", "DescribeAlarms", True), 3),
    (("cloudwatch", "GetMetricData", True), 3),
    (("dynamodb", "DescribeTable", True), 3),
    (("dynamodb", "ListTables", True), 2),
    (("ecr", "GetAuthorizationToken", True), 3),
    (("ecr", "DescribeRepositories", True), 2),
    (("ssm", "GetParameter", True), 2),
    (("cloudformation", "DescribeStacks", True), 3),
    (("cloudformation", "DescribeStackEvents", True), 2),
)

ADMIN_APIS: tuple[tuple[Api, float], ...] = (
    (("iam", "ListUsers", True), 6),
    (("iam", "GetUser", True), 5),
    (("iam", "ListRoles", True), 5),
    (("iam", "GetRole", True), 4),
    (("iam", "ListAttachedUserPolicies", True), 4),
    (("iam", "ListAccessKeys", True), 3),
    (("iam", "GetAccountSummary", True), 1),
    (("iam", "AttachRolePolicy", False), 1),
    (("iam", "PutRolePolicy", False), 1),
    (("iam", "TagRole", False), 1),
    (("organizations", "DescribeOrganization", True), 1),
    (("cloudtrail", "DescribeTrails", True), 1),
    (("cloudtrail", "GetTrailStatus", True), 1),
    (("ec2", "DescribeInstances", True), 4),
    (("s3", "ListBuckets", True), 3),
    (("sts", "GetCallerIdentity", True), 2),
)

LEGACY_APIS: tuple[tuple[Api, float], ...] = (
    (("ec2", "DescribeInstances", True), 6),
    (("s3", "ListBuckets", True), 5),
    (("cloudwatch", "DescribeAlarms", True), 3),
    (("cloudwatch", "GetMetricData", True), 3),
    (("logs", "DescribeLogGroups", True), 2),
    (("ce", "GetCostAndUsage", True), 2),
    (("iam", "ListUsers", True), 1),
    (("iam", "GetUser", True), 1),
)

DATA_SCIENCE_APIS: tuple[tuple[Api, float], ...] = (
    (("athena", "StartQueryExecution", False), 6),
    (("athena", "GetQueryExecution", True), 8),
    (("athena", "GetQueryResults", True), 6),
    (("glue", "GetTables", True), 3),
    (("glue", "GetDatabases", True), 2),
    (("sagemaker", "ListNotebookInstances", True), 2),
    (("sagemaker", "DescribeTrainingJob", True), 2),
    (("s3", "ListBuckets", True), 3),
    (("sts", "GetCallerIdentity", True), 1),
)

PIPELINE_APIS: tuple[tuple[Api, float], ...] = (
    (("glue", "StartJobRun", False), 3),
    (("glue", "GetJobRun", True), 8),
    (("athena", "StartQueryExecution", False), 2),
    (("athena", "GetQueryExecution", True), 4),
    (("secretsmanager", "GetSecretValue", True), 2),
    (("kms", "Decrypt", True), 2),
    (("s3", "GetBucketLocation", True), 1),
)

APP_ROLE_APIS: tuple[tuple[Api, float], ...] = (
    (("sqs", "ListQueues", True), 1),
    (("secretsmanager", "GetSecretValue", True), 3),
    (("kms", "Decrypt", True), 4),
    (("ssm", "GetParameters", True), 2),
    (("dynamodb", "DescribeTable", True), 1),
)

# Terraform plan/apply touches a broad slice of read APIs plus a few writes.
TERRAFORM_READS: tuple[Api, ...] = (
    ("sts", "GetCallerIdentity", True),
    ("ec2", "DescribeVpcs", True),
    ("ec2", "DescribeSubnets", True),
    ("ec2", "DescribeSecurityGroups", True),
    ("ec2", "DescribeRouteTables", True),
    ("ec2", "DescribeInstances", True),
    ("ec2", "DescribeLaunchTemplates", True),
    ("ec2", "DescribeNetworkAcls", True),
    ("iam", "GetRole", True),
    ("iam", "GetRolePolicy", True),
    ("iam", "ListAttachedRolePolicies", True),
    ("iam", "GetPolicy", True),
    ("iam", "GetPolicyVersion", True),
    ("s3", "GetBucketPolicy", True),
    ("s3", "GetBucketVersioning", True),
    ("s3", "GetBucketEncryption", True),
    ("s3", "GetBucketTagging", True),
    ("lambda", "GetFunction20150331v2", True),
    ("lambda", "ListVersionsByFunction20150331", True),
    ("logs", "DescribeLogGroups", True),
    ("dynamodb", "DescribeTable", True),
    ("dynamodb", "DescribeContinuousBackups", True),
    ("kms", "DescribeKey", True),
    ("kms", "GetKeyPolicy", True),
    ("cloudtrail", "DescribeTrails", True),
    ("cloudtrail", "GetEventSelectors", True),
)
TERRAFORM_WRITES: tuple[Api, ...] = (
    ("ec2", "AuthorizeSecurityGroupIngress", False),
    ("ec2", "CreateTags", False),
    ("lambda", "UpdateFunctionConfiguration20150331v2", False),
    ("iam", "PutRolePolicy", False),
    ("s3", "PutBucketTagging", False),
    ("cloudtrail", "UpdateTrail", False),
)

# A third-party posture-management scanner enumerates everything on a schedule.
SCANNER_APIS: tuple[Api, ...] = (
    *TERRAFORM_READS,
    ("iam", "ListUsers", True),
    ("iam", "ListRoles", True),
    ("iam", "ListPolicies", True),
    ("iam", "GetAccountPasswordPolicy", True),
    ("iam", "ListMFADevices", True),
    ("iam", "ListAccessKeys", True),
    ("iam", "GetCredentialReport", True),
    ("s3", "ListBuckets", True),
    ("s3", "GetBucketAcl", True),
    ("s3", "GetBucketLogging", True),
    ("s3", "GetPublicAccessBlock", True),
    ("guardduty", "ListDetectors", True),
    ("guardduty", "GetDetector", True),
    ("config", "DescribeConfigurationRecorders", True),
    ("config", "DescribeConfigurationRecorderStatus", True),
    ("cloudtrail", "GetTrailStatus", True),
    ("rds", "DescribeDBInstances", True),
    ("rds", "DescribeDBSnapshots", True),
    ("ec2", "DescribeSnapshots", True),
    ("ec2", "DescribeVolumes", True),
    ("ec2", "DescribeFlowLogs", True),
    ("sns", "ListTopics", True),
    ("sqs", "ListQueues", True),
    ("secretsmanager", "ListSecrets", True),
    ("ecr", "DescribeRepositories", True),
    ("eks", "ListClusters", True),
)

# Benign exploration: APIs a human occasionally tries for the first time.
EXPLORATION_APIS: tuple[Api, ...] = (
    ("eks", "ListClusters", True),
    ("eks", "DescribeCluster", True),
    ("rds", "DescribeDBInstances", True),
    ("sns", "ListTopics", True),
    ("sqs", "ListQueues", True),
    ("route53", "ListHostedZones", True),
    ("acm", "ListCertificates", True),
    ("apigateway", "GetRestApis", True),
    ("states", "ListStateMachines", True),
    ("kinesis", "ListStreams", True),
    ("elasticloadbalancing", "DescribeLoadBalancers", True),
    ("cloudfront", "ListDistributions2020_05_31", True),
    ("secretsmanager", "GetSecretValue", True),
    ("ssm", "GetParameters", True),
)

# --- attacker vocabularies -------------------------------------------------------------------
RECON_APIS: tuple[Api, ...] = (
    ("sts", "GetCallerIdentity", True),
    ("iam", "GetAccountAuthorizationDetails", True),
    ("iam", "ListUsers", True),
    ("iam", "ListRoles", True),
    ("iam", "ListGroups", True),
    ("iam", "ListPolicies", True),
    ("iam", "ListAttachedUserPolicies", True),
    ("iam", "ListUserPolicies", True),
    ("iam", "GetAccountSummary", True),
    ("s3", "ListBuckets", True),
    ("s3", "GetBucketAcl", True),
    ("s3", "GetBucketPolicy", True),
    ("ec2", "DescribeInstances", True),
    ("ec2", "DescribeSnapshots", True),
    ("ec2", "DescribeVolumes", True),
    ("ec2", "DescribeSecurityGroups", True),
    ("ec2", "DescribeKeyPairs", True),
    ("ec2", "DescribeRegions", True),
    ("lambda", "ListFunctions20150331", True),
    ("lambda", "GetFunction20150331v2", True),
    ("rds", "DescribeDBInstances", True),
    ("rds", "DescribeDBSnapshots", True),
    ("secretsmanager", "ListSecrets", True),
    ("ssm", "DescribeParameters", True),
    ("kms", "ListKeys", True),
    ("kms", "ListAliases", True),
    ("dynamodb", "ListTables", True),
    ("sns", "ListTopics", True),
    ("sqs", "ListQueues", True),
    ("cloudtrail", "DescribeTrails", True),
    ("guardduty", "ListDetectors", True),
    ("organizations", "DescribeOrganization", True),
    ("organizations", "ListAccounts", True),
    ("ecr", "DescribeRepositories", True),
    ("eks", "ListClusters", True),
    ("cloudformation", "ListStacks", True),
)

# --- user agents -----------------------------------------------------------------------------
USER_AGENTS: dict[str, str] = {
    "aws-cli": (
        "aws-cli/2.15.{v} md/awscrt#0.19.19 ua/2.0 os/macos#23.4.0 md/arch#arm64 "
        "lang/python#3.11.8 md/pyimpl#CPython cfg/retry-mode#standard md/installer#exe "
        "md/prompt#off"
    ),
    "boto3": (
        "Boto3/1.34.{v} md/Botocore#1.34.{v} ua/2.0 os/linux#5.10.210 md/arch#x86_64 "
        "lang/python#3.11.8 md/pyimpl#CPython cfg/retry-mode#legacy Botocore/1.34.{v}"
    ),
    "terraform": (
        "APN/1.0 HashiCorp/1.0 Terraform/1.7.{v} (+https://www.terraform.io) "
        "terraform-provider-aws/5.42.0 aws-sdk-go-v2/1.26.0 os/linux lang/go#1.22.1"
    ),
    "aws-sdk-java": (
        "aws-sdk-java/1.12.{v} Linux/5.10.210 OpenJDK_64-Bit_Server_VM/17.0.10+7-LTS "
        "java/17.0.10 vendor/Amazon.com_Inc."
    ),
    "aws-sdk-go": "aws-sdk-go-v2/1.26.{v} os/linux lang/go#1.22.1 md/GOOS#linux",
    "console": "console.amazonaws.com",
    "browser": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.{v} Safari/605.1.15"
    ),
    "offensive-distro": ("aws-cli/1.32.{v} Python/3.11.8 Linux/6.6.9-amd64-kali botocore/1.34.{v}"),
    "scripted-http": "python-requests/2.31.{v}",
}


def user_agent(family: str, version: int) -> str:
    """Concrete user-agent string for a family; ``version`` drifts over time like real SDKs."""
    return USER_AGENTS[family].replace("{v}", str(version))


# --- networks (ASNs in the bundled synthetic netmap) -----------------------------------------
ASN_HQ = 64512
ASN_DUBLIN_OFFICE = 64513
ASN_VPN_FRANKFURT = 64514
ASN_VPN_ASHBURN = 64515
ASN_SEATTLE_ISP = 64520
ASN_AUSTIN_ISP = 64521
ASN_DUBLIN_ISP = 64522
ASN_BENGALURU_ISP = 64523
ASN_US_MOBILE = 64524
ASN_IE_MOBILE = 64525
ASN_LONDON_HOTEL = 64526
ASN_TOKYO_ISP = 64527
ASN_SINGAPORE_ISP = 64528
ASN_TORONTO_ISP = 64530
ASN_MUNICH_ISP = 64531
ASN_SYDNEY_ISP = 64532
ASN_CHICAGO_MOBILE = 64534
ASN_CI = 64540
ASN_DATACENTER = 64541
ASN_VENDOR = 64558
HOSTILE_ASNS = (64550, 64551, 64552, 64553, 64554, 64555, 64556, 64557)
TRAVEL_ASNS = (
    ASN_LONDON_HOTEL,
    ASN_TOKYO_ISP,
    ASN_SINGAPORE_ISP,
    ASN_TORONTO_ISP,
    ASN_MUNICH_ISP,
    ASN_SYDNEY_ISP,
)
# Addresses outside the netmap (unknown networks), e.g. cloud-hosted application egress.
UNMAPPED_PREFIX = "192.0.2."
