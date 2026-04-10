"""
CloudOps Intelligence Environment — core logic.

Simulates the cloud operations workflow that every cloud engineering and SRE
team performs daily: cost anomaly investigation (FinOps), security posture
remediation, and live incident response — combined into three progressively
harder tasks.

Task difficulty:
  easy   — FinOps: billing spike from zombie EC2 instances (1 root cause, 15 steps)
  medium — Security + SRE: S3 public exposure + broken service IAM (2 root causes, 25 steps)
  hard   — DDoS + FinOps + SRE: live attack, WAF deployment via Terraform,
           runaway auto-scaling cost ($50k/hr), cascading service failures
           (3 root causes, 40 steps)

Action space (all text-based — no spatial grids, no physics):
  view_logs(service)                         — service log output
  view_metrics(service, metric)              — time-series data
  list_resources(type, filter?)              — AWS resource inventory
  run_cli(command)                           — AWS CLI simulation
  view_billing(service?, period?)            — cost and usage report
  apply_fix(target, fix_type, params)        — apply remediation
  write_terraform(resource_type, config)     — generate + validate Terraform
  verify(target)                             — health/security check
  escalate                                   — hand off (partial credit)

Reward structure (all normalised to [0, 1]):
  +W_ROOT_CAUSE    per new root cause correctly identified
  +W_FIX_APPLIED   per correct fix applied
  +W_VERIFY        per service/resource that passes a health/security check
  +W_COMPLETION    episode completion bonus
  -W_WRONG_FIX     penalty for wrong-target fix
  -W_REDUNDANT     penalty for repeated identical investigation
"""

import json
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from openenv.core.env_server import Environment

try:
    from ..models import (
        IncidentAction,
        IncidentObservation,
        IncidentState,
        ServiceHealth,
    )
except ImportError:
    from models import IncidentAction, IncidentObservation, IncidentState, ServiceHealth  # type: ignore[no-redef]

# ---------------------------------------------------------------------------
# Reward weights
# ---------------------------------------------------------------------------
W_ROOT_CAUSE  = 0.30
W_FIX_APPLIED = 0.30
W_VERIFY      = 0.10
W_COMPLETION  = 0.20
W_WRONG_FIX   = 0.05
W_REDUNDANT   = 0.02

# ---------------------------------------------------------------------------
# Scenario library
# ---------------------------------------------------------------------------
SCENARIOS: Dict[str, dict] = {

    # ════════════════════════════════════════════════════════════════════════
    # EASY — Cloud FinOps: Zombie EC2 Cost Anomaly
    #
    # Inspired by real incident: data-science team left 3 m5.2xlarge GPU
    # training instances running after a cancelled ML project. Cost $885/month.
    # Discovered via AWS Cost Anomaly Detection (real AWS service) — 340% spike.
    # All CLI outputs use the exact JSON schema from AWS official documentation.
    # Pricing: m5.2xlarge = $0.384/hr (us-east-1 On-Demand, current AWS pricing).
    # ════════════════════════════════════════════════════════════════════════
    "easy": {
        "title": "AWS Billing Spike — Zombie EC2 Instances (FinOps)",
        "domain": "FinOps",
        "initial_alert": (
            "AWS COST ANOMALY ALERT — AnomalyDetector-EC2-spend\n"
            "Severity  : HIGH\n"
            "Account   : 123456789012  (us-east-1)\n"
            "Service   : Amazon EC2\n"
            "Detected  : 2026-04-10T08:00:00Z\n"
            "Impact    : $9,312.00 above expected ($12,106 actual vs $2,794 expected)\n"
            "Anomaly   : EC2 On-Demand compute — 340% over 30-day baseline\n"
            "Top driver: instance type m5.2xlarge — 3 instances flagged as idle\n"
            "Action    : Investigate idle instances before finance review at 12:00 UTC\n"
            "Console   : https://console.aws.amazon.com/cost-management/home#/anomaly-detection\n"
        ),
        "services": {
            "billing_dashboard": {
                "status": "healthy",
                "error_rate_pct": 0.0,
                "response_time_ms": 50.0,
                "uptime_pct": 100.0,
                "logs": (
                    # Real AWS Cost Anomaly Detection SNS notification format
                    "{\n"
                    "  \"anomalyId\": \"a1b2c3d4-5678-90ab-cdef-EXAMPLE11111\",\n"
                    "  \"accountId\": \"123456789012\",\n"
                    "  \"anomalyStartDate\": \"2026-03-09\",\n"
                    "  \"anomalyEndDate\": null,\n"
                    "  \"dimensionValue\": \"Amazon EC2\",\n"
                    "  \"monitorName\": \"EC2 spend monitor\",\n"
                    "  \"monitorArn\": \"arn:aws:ce::123456789012:anomalymonitor/"
                    "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111\",\n"
                    "  \"subscriptionName\": \"engineering-billing-alerts\",\n"
                    "  \"subscriptionArn\": \"arn:aws:ce::123456789012:anomalysubscription/"
                    "b2c3d4e5-6789-01ab-cdef-EXAMPLE22222\",\n"
                    "  \"impact\": {\n"
                    "    \"maxImpact\": 9312.00,\n"
                    "    \"totalActualSpend\": 12106.00,\n"
                    "    \"totalExpectedSpend\": 2794.00,\n"
                    "    \"totalImpact\": 9312.00,\n"
                    "    \"totalImpactPercentage\": 333.27\n"
                    "  },\n"
                    "  \"rootCauses\": [\n"
                    "    {\n"
                    "      \"service\": \"Amazon EC2\",\n"
                    "      \"region\": \"us-east-1\",\n"
                    "      \"linkedAccount\": \"123456789012\",\n"
                    "      \"usageType\": \"USE1-BoxUsage:m5.2xlarge\"\n"
                    "    }\n"
                    "  ]\n"
                    "}"
                ),
                "metrics": {
                    "ec2_cost": (
                        # Real AWS Cost Explorer get-cost-and-usage response format
                        "$ aws ce get-cost-and-usage \\\n"
                        "    --time-period Start=2026-03-09,End=2026-04-10 \\\n"
                        "    --granularity DAILY \\\n"
                        "    --metrics BlendedCost \\\n"
                        "    --group-by Type=DIMENSION,Key=INSTANCE_TYPE\n\n"
                        "{\n"
                        "  \"ResultsByTime\": [\n"
                        "    {\n"
                        "      \"TimePeriod\": {\"Start\": \"2026-03-08\", \"End\": \"2026-03-09\"},\n"
                        "      \"Total\": {\"BlendedCost\": {\"Amount\": \"92.16\", \"Unit\": \"USD\"}},\n"
                        "      \"Groups\": [{\"Keys\": [\"m5.xlarge\"], "
                        "\"Metrics\": {\"BlendedCost\": {\"Amount\": \"92.16\", \"Unit\": \"USD\"}}}]\n"
                        "    },\n"
                        "    {\n"
                        "      \"TimePeriod\": {\"Start\": \"2026-03-09\", \"End\": \"2026-03-10\"},\n"
                        "      \"Total\": {\"BlendedCost\": {\"Amount\": \"368.64\", \"Unit\": \"USD\"}},\n"
                        "      \"Groups\": [\n"
                        "        {\"Keys\": [\"m5.xlarge\"], "
                        "\"Metrics\": {\"BlendedCost\": {\"Amount\": \"92.16\", \"Unit\": \"USD\"}}},\n"
                        "        {\"Keys\": [\"m5.2xlarge\"], "
                        "\"Metrics\": {\"BlendedCost\": {\"Amount\": \"276.48\", \"Unit\": \"USD\"}}}"
                        "  <- NEW (3x $0.384/hr x 24h)\n"
                        "      ]\n"
                        "    },\n"
                        "    { \"...\": \"32 days of $368.64/day for m5.2xlarge\" },\n"
                        "    {\n"
                        "      \"TimePeriod\": {\"Start\": \"2026-04-09\", \"End\": \"2026-04-10\"},\n"
                        "      \"Total\": {\"BlendedCost\": {\"Amount\": \"368.64\", \"Unit\": \"USD\"}},\n"
                        "      \"Groups\": [{\"Keys\": [\"m5.2xlarge\"], "
                        "\"Metrics\": {\"BlendedCost\": {\"Amount\": \"276.48\", \"Unit\": \"USD\"}}}]\n"
                        "    }\n"
                        "  ]\n"
                        "}\n"
                        "\nSummary: m5.2xlarge running since 2026-03-09 — $276.48/day "
                        "($8,847.36 over 32 days). Baseline was $92.16/day. "
                        "3 instances × $0.384/hr × 24h = $27.65/day each."
                    ),
                },
            },
            "ec2_fleet": {
                "status": "degraded",
                "error_rate_pct": 0.0,
                "response_time_ms": 10.0,
                "uptime_pct": 100.0,
                "logs": (
                    # Real CloudTrail log format (from AWS docs) for RunInstances event
                    "{\n"
                    "  \"eventVersion\": \"1.08\",\n"
                    "  \"userIdentity\": {\n"
                    "    \"type\": \"IAMUser\",\n"
                    "    \"arn\": \"arn:aws:iam::123456789012:user/ci-deployment-bot\",\n"
                    "    \"accountId\": \"123456789012\",\n"
                    "    \"userName\": \"ci-deployment-bot\"\n"
                    "  },\n"
                    "  \"eventTime\": \"2026-03-09T02:14:07Z\",\n"
                    "  \"eventSource\": \"ec2.amazonaws.com\",\n"
                    "  \"eventName\": \"RunInstances\",\n"
                    "  \"awsRegion\": \"us-east-1\",\n"
                    "  \"sourceIPAddress\": \"10.0.1.100\",\n"
                    "  \"userAgent\": \"aws-cli/2.15.30 Python/3.11.8 "
                    "Linux/6.1.0-20-amd64 exec-env/CloudShell\",\n"
                    "  \"requestParameters\": {\n"
                    "    \"instanceType\": \"m5.2xlarge\",\n"
                    "    \"minCount\": 3, \"maxCount\": 3,\n"
                    "    \"tagSpecificationSet\": {\"items\": [{\n"
                    "      \"resourceType\": \"instance\",\n"
                    "      \"tags\": [\n"
                    "        {\"key\": \"Project\", \"value\": \"ProjectPhoenix\"},\n"
                    "        {\"key\": \"Env\", \"value\": \"staging\"},\n"
                    "        {\"key\": \"ManagedBy\", \"value\": \"ci-deployment-bot\"}\n"
                    "      ]\n"
                    "    }]}\n"
                    "  }\n"
                    "}\n"
                    "[Cost anomaly detector] 3 × m5.2xlarge running 32 days with "
                    "CPUUtilization avg=0.01% — PROJECT STATUS: CANCELLED (Jira: PROJ-4471)"
                ),
                "metrics": {
                    "utilization": (
                        # Real aws cloudwatch get-metric-statistics response format
                        "$ aws cloudwatch get-metric-statistics \\\n"
                        "    --namespace AWS/EC2 \\\n"
                        "    --metric-name CPUUtilization \\\n"
                        "    --dimensions Name=InstanceId,Value=i-0a1b2c3d4e5f67890 \\\n"
                        "    --start-time 2026-03-09T00:00:00Z \\\n"
                        "    --end-time 2026-04-10T08:00:00Z \\\n"
                        "    --period 86400 --statistics Average Maximum\n\n"
                        "{\n"
                        "  \"Datapoints\": [\n"
                        "    {\"Timestamp\": \"2026-03-09T00:00:00Z\", "
                        "\"Average\": 0.012, \"Maximum\": 0.024, \"Unit\": \"Percent\"},\n"
                        "    {\"Timestamp\": \"2026-03-10T00:00:00Z\", "
                        "\"Average\": 0.008, \"Maximum\": 0.017, \"Unit\": \"Percent\"},\n"
                        "    {\"...\": \"32 days — all datapoints < 0.03%\"},\n"
                        "    {\"Timestamp\": \"2026-04-09T00:00:00Z\", "
                        "\"Average\": 0.010, \"Maximum\": 0.019, \"Unit\": \"Percent\"}\n"
                        "  ],\n"
                        "  \"Label\": \"CPUUtilization\"\n"
                        "}\n\n"
                        "SAME PATTERN for i-0b2c3d4e5f678901 and i-0c3d4e5f67890123.\n"
                        "Threshold for zombie detection: avg CPU < 1% for > 14 days.\n"
                        "All 3 instances qualify — RECOMMENDED ACTION: terminate."
                    ),
                    "tags": (
                        # Real aws ec2 describe-tags response format
                        "$ aws ec2 describe-tags \\\n"
                        "    --filters Name=resource-id,"
                        "Values=i-0a1b2c3d4e5f67890,i-0b2c3d4e5f678901,i-0c3d4e5f67890123\n\n"
                        "{\n"
                        "  \"Tags\": [\n"
                        "    {\"Key\": \"Project\", \"Value\": \"ProjectPhoenix\", "
                        "\"ResourceId\": \"i-0a1b2c3d4e5f67890\", \"ResourceType\": \"instance\"},\n"
                        "    {\"Key\": \"Env\",     \"Value\": \"staging\",        "
                        "\"ResourceId\": \"i-0a1b2c3d4e5f67890\", \"ResourceType\": \"instance\"},\n"
                        "    {\"Key\": \"Project\", \"Value\": \"ProjectPhoenix\", "
                        "\"ResourceId\": \"i-0b2c3d4e5f678901\", \"ResourceType\": \"instance\"},\n"
                        "    {\"Key\": \"Project\", \"Value\": \"ProjectPhoenix\", "
                        "\"ResourceId\": \"i-0c3d4e5f67890123\", \"ResourceType\": \"instance\"}\n"
                        "  ]\n"
                        "}\n"
                        "Jira PROJ-4471 status: CANCELLED (2026-03-11) — "
                        "no decommission ticket raised."
                    ),
                },
                "cli_outputs": {
                    "aws ec2 describe-instances": (
                        # Real aws ec2 describe-instances JSON (Reservations structure from AWS docs)
                        "{\n"
                        "  \"Reservations\": [\n"
                        "    {\n"
                        "      \"ReservationId\": \"r-0a1b2c3d4e5f67890\",\n"
                        "      \"OwnerId\": \"123456789012\",\n"
                        "      \"Instances\": [\n"
                        "        {\n"
                        "          \"InstanceId\": \"i-0a1b2c3d4e5f67890\",\n"
                        "          \"InstanceType\": \"m5.2xlarge\",\n"
                        "          \"LaunchTime\": \"2026-03-09T02:14:07.000Z\",\n"
                        "          \"State\": {\"Code\": 16, \"Name\": \"running\"},\n"
                        "          \"Placement\": {\"AvailabilityZone\": \"us-east-1a\"},\n"
                        "          \"PrivateIpAddress\": \"10.0.1.101\",\n"
                        "          \"Tags\": [\n"
                        "            {\"Key\": \"Project\", \"Value\": \"ProjectPhoenix\"},\n"
                        "            {\"Key\": \"Env\",     \"Value\": \"staging\"}\n"
                        "          ]\n"
                        "        },\n"
                        "        {\n"
                        "          \"InstanceId\": \"i-0b2c3d4e5f678901\",\n"
                        "          \"InstanceType\": \"m5.2xlarge\",\n"
                        "          \"LaunchTime\": \"2026-03-09T02:15:02.000Z\",\n"
                        "          \"State\": {\"Code\": 16, \"Name\": \"running\"},\n"
                        "          \"Tags\": [\n"
                        "            {\"Key\": \"Project\", \"Value\": \"ProjectPhoenix\"},\n"
                        "            {\"Key\": \"Env\",     \"Value\": \"staging\"}\n"
                        "          ]\n"
                        "        },\n"
                        "        {\n"
                        "          \"InstanceId\": \"i-0c3d4e5f67890123\",\n"
                        "          \"InstanceType\": \"m5.2xlarge\",\n"
                        "          \"LaunchTime\": \"2026-03-09T02:15:19.000Z\",\n"
                        "          \"State\": {\"Code\": 16, \"Name\": \"running\"},\n"
                        "          \"Tags\": [\n"
                        "            {\"Key\": \"Project\", \"Value\": \"ProjectPhoenix\"},\n"
                        "            {\"Key\": \"Env\",     \"Value\": \"staging\"}\n"
                        "          ]\n"
                        "        }\n"
                        "      ]\n"
                        "    }\n"
                        "  ]\n"
                        "}\n"
                        "⚠ 3 × m5.2xlarge ($0.384/hr each) running 32 days — "
                        "Project=ProjectPhoenix (CANCELLED). "
                        "Total waste: $884.74. Terminate to stop bleeding."
                    ),
                    "aws ec2 terminate-instances": (
                        # Real aws ec2 terminate-instances response format
                        "{\n"
                        "  \"TerminatingInstances\": [\n"
                        "    {\n"
                        "      \"InstanceId\": \"i-0a1b2c3d4e5f67890\",\n"
                        "      \"CurrentState\": {\"Code\": 32, \"Name\": \"shutting-down\"},\n"
                        "      \"PreviousState\": {\"Code\": 16, \"Name\": \"running\"}\n"
                        "    },\n"
                        "    {\n"
                        "      \"InstanceId\": \"i-0b2c3d4e5f678901\",\n"
                        "      \"CurrentState\": {\"Code\": 32, \"Name\": \"shutting-down\"},\n"
                        "      \"PreviousState\": {\"Code\": 16, \"Name\": \"running\"}\n"
                        "    },\n"
                        "    {\n"
                        "      \"InstanceId\": \"i-0c3d4e5f67890123\",\n"
                        "      \"CurrentState\": {\"Code\": 32, \"Name\": \"shutting-down\"},\n"
                        "      \"PreviousState\": {\"Code\": 16, \"Name\": \"running\"}\n"
                        "    }\n"
                        "  ]\n"
                        "}\n"
                        "Instances terminating. EBS volumes (gp3 100GB each) will be "
                        "deleted (DeleteOnTermination=true). "
                        "Projected monthly savings: $884.74 + $30.00 EBS = $914.74/month."
                    ),
                },
            },
        },
        "root_causes": ["zombie_ec2_cost_overrun"],
        "correct_fixes": {
            "zombie_ec2_cost_overrun": {
                "target": "ec2_fleet",
                "affected_services": ["billing_dashboard"],
                "fix_types": [
                    "terminate",
                    "terminate_instance",
                    "stop_instance",
                    "delete_resource",
                    "cleanup",
                    "remove",
                ],
                "config_keys": [
                    "instance_id",
                    "i-0a1b2c3d4e5f67890",
                    "i-0b2c3d4e5f678901",
                    "i-0c3d4e5f67890123",
                    "zombie",
                    "project_phoenix",
                    "cancelled",
                ],
            }
        },
        "verify_services": ["ec2_fleet"],
        "post_fix_status": {
            "ec2_fleet": {
                "status": "healthy",
                "error_rate_pct": 0.0,
                "response_time_ms": 10.0,
                "uptime_pct": 100.0,
            },
            "billing_dashboard": {
                "status": "healthy",
                "error_rate_pct": 0.0,
                "response_time_ms": 50.0,
                "uptime_pct": 100.0,
            },
        },
        "max_steps": 15,
        "difficulty": "easy",
    },

    # ════════════════════════════════════════════════════════════════════════
    # MEDIUM — Security + SRE: S3 Public Exposure + Broken IAM
    #
    # Based on a documented class of real incidents (2024): deployment pipelines
    # that call PutBucketAcl / DeletePublicAccessBlock with legacy ACL arguments
    # accidentally make S3 buckets publicly readable.
    # Simultaneously, a typo in the IAM policy ("s3:GetObejct" vs "s3:GetObject")
    # breaks the payment service — a real AWS behaviour: unknown IAM actions are
    # silently ignored, not rejected at policy creation time.
    # All log/CLI output uses real AWS formats (Security Hub ASFF, CloudTrail,
    # aws s3api, aws iam get-role-policy exact response schemas).
    # ════════════════════════════════════════════════════════════════════════
    "medium": {
        "title": "Security Incident: S3 Public Exposure + Payment Service Auth Failure",
        "domain": "Security + SRE",
        "initial_alert": (
            # Real AWS Security Hub ASFF finding summary (S3.2 control)
            "AWS SECURITY HUB FINDING — CRITICAL\n"
            "FindingId : arn:aws:securityhub:us-east-1:123456789012:subscription/"
            "aws-foundational-security-best-practices/v/1.0.0/S3.2/"
            "finding/c3d4e5f6-7890-12ab-cdef-EXAMPLE33333\n"
            "Control   : S3.2 — S3 buckets should prohibit public read access\n"
            "Severity  : CRITICAL  (Normalized: 90)\n"
            "Resource  : arn:aws:s3:::prod-customer-data\n"
            "Status    : FAILED\n"
            "FirstSeen : 2026-04-10T08:52:11Z\n"
            "Title     : S3 bucket prod-customer-data allows public read access\n"
            "---\n"
            "CONCURRENT INCIDENT — payment-service HTTP 403 error rate: 89%\n"
            "Root cause: IAM role policy updated in deployment v4.2.0 at 11:45:50Z\n"
            "Impact    : ~22,000 active checkout sessions blocked\n"
            "GDPR      : Breach notification window open 2h 55m (deadline: 72h)\n"
            "Runbook   : https://wiki.internal/runbooks/s3-exposure-response\n"
        ),
        "services": {
            "payment_service": {
                "status": "degraded",
                "error_rate_pct": 89.0,
                "response_time_ms": 180.0,
                "uptime_pct": 11.0,
                "logs": (
                    # Real Java AWS SDK exception format + CloudWatch Logs format
                    "2026-04-10T11:47:02.341Z ERROR [payment-svc] "
                    "com.amazonaws.services.s3.model.AmazonS3Exception: "
                    "Access Denied (Service: Amazon S3; "
                    "Status Code: 403; Error Code: AccessDenied; "
                    "Request ID: TX4B3F2A1E0D9C8B7A6; "
                    "S3 Extended Request ID: "
                    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY=)\n"
                    "2026-04-10T11:47:02.339Z ERROR [payment-svc] "
                    "Failed to load TLS cert s3://prod-customer-data/certs/payment.pem\n"
                    "2026-04-10T11:47:02.330Z WARN  [payment-svc] "
                    "Retrying S3 fetch (attempt 3/3) — backing off 500ms\n"
                    "2026-04-10T11:47:01.210Z ERROR [payment-svc] "
                    "Certificate renewal aborted — S3 access denied\n"
                    "2026-04-10T11:45:50.003Z INFO  [payment-svc] "
                    "Deployment v4.2.0 complete. IAM role: payment-service-role. "
                    "Commit: a3f8c1d (Update IAM policy for S3 cert access)"
                ),
            },
            "s3_prod_customer_data": {
                "status": "degraded",
                "error_rate_pct": 0.0,
                "response_time_ms": 8.0,
                "uptime_pct": 100.0,
                "logs": (
                    # Real CloudTrail JSON for PutBucketAcl event (from AWS docs schema)
                    "{\n"
                    "  \"eventVersion\": \"1.08\",\n"
                    "  \"userIdentity\": {\n"
                    "    \"type\": \"IAMUser\",\n"
                    "    \"arn\": \"arn:aws:iam::123456789012:user/ci-deployment-bot\",\n"
                    "    \"accountId\": \"123456789012\",\n"
                    "    \"userName\": \"ci-deployment-bot\"\n"
                    "  },\n"
                    "  \"eventTime\": \"2026-04-10T08:52:11Z\",\n"
                    "  \"eventSource\": \"s3.amazonaws.com\",\n"
                    "  \"eventName\": \"PutBucketAcl\",\n"
                    "  \"awsRegion\": \"us-east-1\",\n"
                    "  \"sourceIPAddress\": \"10.0.2.50\",\n"
                    "  \"userAgent\": \"aws-cli/2.15.30\",\n"
                    "  \"requestParameters\": {\n"
                    "    \"bucketName\": \"prod-customer-data\",\n"
                    "    \"AccessControlPolicy\": \"\",\n"
                    "    \"x-amz-acl\": \"public-read-write\"\n"
                    "  },\n"
                    "  \"responseElements\": null,\n"
                    "  \"requestID\": \"BKJH5N4M3L2K1J0I\",\n"
                    "  \"eventID\": \"d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f9a\"\n"
                    "}\n"
                    "--- S3 Server Access Log (bucket: prod-customer-data) ---\n"
                    "123456789012 prod-customer-data [10/Apr/2026:09:14:33 +0000] "
                    "203.0.113.45 - TX1A2B3C4D REST.GET.OBJECT customers/user_0001.json "
                    "\"GET /customers/user_0001.json HTTP/1.1\" 200 - 4821 4821 12 11 "
                    "\"-\" \"python-requests/2.31.0\" - AIDAIOSFODNN7EXAMPLE "
                    "SigV4 ECDHE-RSA-AES128-GCM-SHA256 AuthHeader prod-customer-data.s3.amazonaws.com TLSv1.3\n"
                    "[Anomaly] 2,847 anonymous GET requests between 09:00–11:47 UTC"
                ),
                "cli_outputs": {
                    "aws s3api get-bucket-acl": (
                        # Exact format from AWS docs (https://docs.aws.amazon.com/cli/latest/reference/s3api/get-bucket-acl.html)
                        "{\n"
                        "    \"Owner\": {\n"
                        "        \"DisplayName\": \"prod-account-owner\",\n"
                        "        \"ID\": \"79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be\"\n"
                        "    },\n"
                        "    \"Grants\": [\n"
                        "        {\n"
                        "            \"Grantee\": {\n"
                        "                \"DisplayName\": \"prod-account-owner\",\n"
                        "                \"ID\": \"79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be\",\n"
                        "                \"Type\": \"CanonicalUser\"\n"
                        "            },\n"
                        "            \"Permission\": \"FULL_CONTROL\"\n"
                        "        },\n"
                        "        {\n"
                        "            \"Grantee\": {\n"
                        "                \"Type\": \"Group\",\n"
                        "                \"URI\": \"http://acs.amazonaws.com/groups/global/AllUsers\"\n"
                        "            },\n"
                        "            \"Permission\": \"READ\"\n"
                        "        },\n"
                        "        {\n"
                        "            \"Grantee\": {\n"
                        "                \"Type\": \"Group\",\n"
                        "                \"URI\": \"http://acs.amazonaws.com/groups/global/AllUsers\"\n"
                        "            },\n"
                        "            \"Permission\": \"WRITE\"\n"
                        "        }\n"
                        "    ]\n"
                        "}\n"
                        "⚠ CRITICAL: AllUsers GROUP has READ + WRITE — bucket is publicly "
                        "accessible to the entire internet. Contains customer PII."
                    ),
                    "aws s3api get-public-access-block": (
                        # Exact format from AWS docs
                        "{\n"
                        "    \"PublicAccessBlockConfiguration\": {\n"
                        "        \"BlockPublicAcls\": false,\n"
                        "        \"IgnorePublicAcls\": false,\n"
                        "        \"BlockPublicPolicy\": false,\n"
                        "        \"RestrictPublicBuckets\": false\n"
                        "    }\n"
                        "}\n"
                        "All four S3 Block Public Access settings are DISABLED.\n"
                        "Fix: aws s3api put-public-access-block \\\n"
                        "       --bucket prod-customer-data \\\n"
                        "       --public-access-block-configuration "
                        "BlockPublicAcls=true,IgnorePublicAcls=true,"
                        "BlockPublicPolicy=true,RestrictPublicBuckets=true"
                    ),
                },
                "metrics": {
                    "access": (
                        # Real S3 Storage Lens / CloudWatch metrics format
                        "$ aws cloudwatch get-metric-statistics \\\n"
                        "    --namespace AWS/S3 --metric-name NumberOfObjects \\\n"
                        "    --dimensions Name=BucketName,Value=prod-customer-data "
                        "Name=StorageType,Value=AllStorageTypes \\\n"
                        "    --start-time 2026-04-10T08:00:00Z "
                        "--end-time 2026-04-10T12:00:00Z \\\n"
                        "    --period 300 --statistics SampleCount\n\n"
                        "Anonymous request count by 5-min window (S3 server access logs):\n"
                        "08:52Z  ACL changed to public-read-write (PutBucketAcl)\n"
                        "09:00Z  14  anonymous GET requests\n"
                        "09:30Z  287 anonymous GET requests [escalating]\n"
                        "10:00Z  612 anonymous GET requests\n"
                        "11:00Z  1,024 anonymous GET requests [peak]\n"
                        "11:47Z  2,847 total anonymous GETs since exposure\n"
                        "11:41Z  12 anonymous PUT requests (test write probe)\n"
                        "Data exfiltration risk: customers/ prefix, "
                        "JSON files ~4.8 KB each, ~50,000 objects."
                    ),
                },
            },
            "iam_payment_role": {
                "status": "degraded",
                "error_rate_pct": 0.0,
                "response_time_ms": 5.0,
                "uptime_pct": 100.0,
                "logs": (
                    # Real CloudTrail JSON for PutRolePolicy event
                    "{\n"
                    "  \"eventVersion\": \"1.08\",\n"
                    "  \"userIdentity\": {\n"
                    "    \"type\": \"IAMUser\",\n"
                    "    \"arn\": \"arn:aws:iam::123456789012:user/ci-deployment-bot\",\n"
                    "    \"userName\": \"ci-deployment-bot\"\n"
                    "  },\n"
                    "  \"eventTime\": \"2026-04-10T11:45:48Z\",\n"
                    "  \"eventSource\": \"iam.amazonaws.com\",\n"
                    "  \"eventName\": \"PutRolePolicy\",\n"
                    "  \"awsRegion\": \"us-east-1\",\n"
                    "  \"requestParameters\": {\n"
                    "    \"roleName\": \"payment-service-role\",\n"
                    "    \"policyName\": \"payment-s3-cert-access\",\n"
                    "    \"policyDocument\": \"%7B%22Statement%22%3A%5B%7B%22Effect%22%3A"
                    "%22Allow%22%2C%22Action%22%3A%5B%22s3%3AGetObejct%22%2C"
                    "%22s3%3AListBucket%22%5D%7D%5D%7D\"\n"
                    "  }\n"
                    "}\n"
                    "Note: IAM accepts unknown actions without error — "
                    "'s3:GetObejct' (typo) is stored as-is and silently ignored at eval time."
                ),
                "cli_outputs": {
                    "aws iam get-role-policy": (
                        # Exact real format from AWS docs
                        "{\n"
                        "    \"RoleName\": \"payment-service-role\",\n"
                        "    \"PolicyName\": \"payment-s3-cert-access\",\n"
                        "    \"PolicyDocument\": {\n"
                        "        \"Version\": \"2012-10-17\",\n"
                        "        \"Statement\": [\n"
                        "            {\n"
                        "                \"Sid\": \"AllowS3CertAccess\",\n"
                        "                \"Effect\": \"Allow\",\n"
                        "                \"Action\": [\n"
                        "                    \"s3:GetObejct\",\n"
                        "                    \"s3:ListBucket\"\n"
                        "                ],\n"
                        "                \"Resource\": [\n"
                        "                    \"arn:aws:s3:::prod-customer-data/certs/*\",\n"
                        "                    \"arn:aws:s3:::prod-customer-data\"\n"
                        "                ]\n"
                        "            }\n"
                        "        ]\n"
                        "    }\n"
                        "}\n"
                        "⚠ TYPO: 's3:GetObejct' is NOT a recognised IAM action.\n"
                        "AWS accepts unknown actions at policy creation (no validation).\n"
                        "At evaluation time, the action is silently skipped — "
                        "effectively no s3:GetObject permission is granted.\n"
                        "Correct action string: 's3:GetObject'"
                    ),
                },
                "metrics": {
                    "auth": (
                        # Real AWS IAM Access Analyzer / CloudTrail Insights style output
                        "$ aws cloudtrail lookup-events \\\n"
                        "    --lookup-attributes "
                        "AttributeKey=EventName,AttributeValue=AssumeRole \\\n"
                        "    --start-time 2026-04-10T11:30:00Z\n\n"
                        "AccessDenied events for payment-service-role (last 30 min):\n"
                        "11:46:02Z  s3:GetObject  prod-customer-data/certs/payment.pem  "
                        "DENY  (no matching allow statement)\n"
                        "11:46:03Z  s3:GetObject  prod-customer-data/certs/payment.pem  "
                        "DENY\n"
                        "... 890 more identical denials ...\n"
                        "IAM policy simulator result:\n"
                        "  Evaluated action: s3:GetObject\n"
                        "  Policy actions present: ['s3:GetObejct', 's3:ListBucket']\n"
                        "  Match found: NO (action name mismatch — typo)\n"
                        "  Decision: DENY (implicit)"
                    ),
                },
            },
            "api_gateway": {
                "status": "degraded",
                "error_rate_pct": 89.0,
                "response_time_ms": 180.0,
                "uptime_pct": 11.0,
                "logs": (
                    "2026-04-10T11:47:02Z ERROR api-gw: "
                    "POST /v1/checkout → 403 Forbidden (payment-service upstream)\n"
                    "2026-04-10T11:47:00Z WARN  api-gw: "
                    "Error rate 89% on /v1/checkout path — SLO breach (target: <1%)\n"
                    "2026-04-10T11:46:58Z INFO  api-gw: "
                    "X-Amzn-RequestId: b5c6d7e8-f9a0-1b2c-3d4e-5f6a7b8c9d0e"
                ),
            },
            "auth_service": {
                "status": "healthy",
                "error_rate_pct": 0.1,
                "response_time_ms": 12.0,
                "uptime_pct": 99.9,
                "logs": (
                    "2026-04-10T11:47:00Z INFO  auth-svc: "
                    "22,047 active sessions. JWT validation healthy.\n"
                    "2026-04-10T11:47:00Z WARN  auth-svc: "
                    "Downstream payment errors detected — not auth-related."
                ),
            },
        },
        "root_causes": [
            "s3_public_access_enabled",
            "iam_role_typo",
        ],
        "correct_fixes": {
            "s3_public_access_enabled": {
                "target": "s3_prod_customer_data",
                "affected_services": [],
                "fix_types": [
                    "update_policy",
                    "block_public_access",
                    "restrict_access",
                    "remove_public_acl",
                    "apply_bucket_policy",
                    "put_public_access_block",
                    "fix_acl",
                    "rollback",
                    "adjust_config",
                ],
                "config_keys": [
                    "public_access_block",
                    "acl",
                    "block_public_acls",
                    "restrict_public_buckets",
                    "private",
                    "bucket_policy",
                ],
            },
            "iam_role_typo": {
                "target": "iam_payment_role",
                "affected_services": ["payment_service", "api_gateway"],
                "fix_types": [
                    "update_policy",
                    "fix_iam",
                    "fix_permission",
                    "correct_action",
                    "attach_policy",
                    "adjust_config",
                    "rollback",
                    "put_role_policy",
                ],
                "config_keys": [
                    "s3:GetObject",
                    "getobject",
                    "iam_policy",
                    "payment_service_role",
                    "s3_permission",
                    "typo",
                ],
            },
        },
        "verify_services": ["payment_service", "s3_prod_customer_data"],
        "post_fix_status": {
            "payment_service": {
                "status": "healthy",
                "error_rate_pct": 0.1,
                "response_time_ms": 95.0,
                "uptime_pct": 99.9,
            },
            "s3_prod_customer_data": {
                "status": "healthy",
                "error_rate_pct": 0.0,
                "response_time_ms": 8.0,
                "uptime_pct": 100.0,
            },
            "iam_payment_role": {
                "status": "healthy",
                "error_rate_pct": 0.0,
                "response_time_ms": 5.0,
                "uptime_pct": 100.0,
            },
            "api_gateway": {
                "status": "healthy",
                "error_rate_pct": 0.2,
                "response_time_ms": 85.0,
                "uptime_pct": 99.9,
            },
        },
        "max_steps": 25,
        "difficulty": "medium",
    },

    # ════════════════════════════════════════════════════════════════════════
    # HARD — DDoS + FinOps + SRE: Live Attack, WAF Deployment, Cost Runaway
    #
    # Based on real DDoS incident patterns documented in AWS Shield threat
    # landscape reports (2023-2024) and the VPC Flow Log format from official
    # AWS documentation (flow-logs-records-examples).
    # VPC Flow Log format: version account-id interface-id srcaddr dstaddr
    #   srcport dstport protocol packets bytes start end action log-status
    # Attack pattern: SYN flood (tcp-flags=2) + HTTP flood (protocol=6, port=443)
    # from 3 coordinated CIDR ranges — characteristic of botnet-driven L4/L7 DDoS.
    # EC2 pricing: m5.xlarge = $0.192/hr (us-east-1 On-Demand, real AWS price).
    # ════════════════════════════════════════════════════════════════════════
    "hard": {
        "title": "DDoS Attack — WAF Deployment + Runaway Auto-Scaling + Cascading Failures",
        "domain": "Security + FinOps + SRE",
        "initial_alert": (
            # Real AWS GuardDuty finding format for DDoS
            "AWS GUARDDUTY FINDING — HIGH SEVERITY\n"
            "FindingId : f6a7b8c9-0d1e-2f3a-4b5c-6d7e8f9a0b1c\n"
            "Type      : UnauthorizedAccess:EC2/RDPBruteForce + "
            "Impact:EC2/WinRMBruteForce\n"
            "Severity  : 8.9  (HIGH)\n"
            "AccountId : 123456789012\n"
            "Region    : us-east-1\n"
            "Title     : EC2 instance i-0f1a2b3c4d5e6f789 is being used to perform "
            "a DDoS attack against multiple external hosts.\n"
            "---\n"
            "P0 INCIDENT ALERT — Active DDoS + Cascading Service Failures\n"
            "Time    : 2026-04-10T03:12:44Z\n"
            "Attack  : Volumetric DDoS — 840,000 req/min from 3 CIDR ranges\n"
            "Cost    : Auto-scaling unbounded — 213 instances running ($40.90/hr, "
            "on track for $84,096/day at max_capacity=500)\n"
            "Services: api_gateway (90% error), order_service (DOWN), "
            "inventory_service (72% error)\n"
            "WAF     : NO Web ACL attached to api_gateway stage\n"
            "SLA     : P0 — all purchases blocked for 22,000+ sessions\n"
            "Runbook : https://wiki.internal/runbooks/ddos-response\n"
        ),
        "services": {
            "api_gateway": {
                "status": "degraded",
                "error_rate_pct": 90.0,
                "response_time_ms": 28000.0,
                "uptime_pct": 10.0,
                "logs": (
                    "2026-04-10T03:12:43Z ERROR [api-gateway] "
                    "RequestCount spike: 14,003 req/sec (baseline: 20 req/sec)\n"
                    "2026-04-10T03:12:43Z WARN  [api-gateway] "
                    "Throttling is DISABLED on stage prod — "
                    "DefaultRouteThrottlingBurstLimit not set\n"
                    "2026-04-10T03:12:41Z ERROR [api-gateway] "
                    "TargetConnectionErrorCount: 98,432 in last 60s\n"
                    "2026-04-10T03:12:40Z WARN  [api-gateway] "
                    "No WebACL associated: aws wafv2 list-web-acls returns []\n"
                    "2026-04-10T03:12:38Z INFO  [api-gateway] "
                    "Registered targets in TG: 213 (was 13 at 03:00Z)\n"
                    "2026-04-10T03:00:12Z WARN  [api-gateway] "
                    "Anomalous traffic detected from 203.0.113.0/24 — no block rule"
                ),
                "metrics": {
                    "request_rate": (
                        # Real CloudWatch API Gateway metrics format
                        "$ aws cloudwatch get-metric-statistics \\\n"
                        "    --namespace AWS/ApiGateway \\\n"
                        "    --metric-name Count \\\n"
                        "    --dimensions Name=ApiId,Value=abc1234567 "
                        "Name=Stage,Value=prod \\\n"
                        "    --start-time 2026-04-10T02:42:00Z \\\n"
                        "    --end-time 2026-04-10T03:12:00Z \\\n"
                        "    --period 60 --statistics Sum\n\n"
                        "{\n"
                        "  \"Datapoints\": [\n"
                        "    {\"Timestamp\": \"2026-04-10T02:42:00Z\", "
                        "\"Sum\": 1183.0, \"Unit\": \"Count\"},\n"
                        "    {\"Timestamp\": \"2026-04-10T02:52:00Z\", "
                        "\"Sum\": 1207.0, \"Unit\": \"Count\"},\n"
                        "    {\"Timestamp\": \"2026-04-10T03:00:00Z\", "
                        "\"Sum\": 8401.0, \"Unit\": \"Count\"},\n"
                        "    {\"Timestamp\": \"2026-04-10T03:05:00Z\", "
                        "\"Sum\": 120480.0, \"Unit\": \"Count\"},\n"
                        "    {\"Timestamp\": \"2026-04-10T03:10:00Z\", "
                        "\"Sum\": 580112.0, \"Unit\": \"Count\"},\n"
                        "    {\"Timestamp\": \"2026-04-10T03:12:00Z\", "
                        "\"Sum\": 840240.0, \"Unit\": \"Count\"}\n"
                        "  ]\n"
                        "}\n\n"
                        "Attack source CIDRs (from VPC Flow Logs):\n"
                        "  203.0.113.0/24   — 280,000 req/min  (33%) SYN flood\n"
                        "  198.51.100.0/24  — 310,000 req/min  (37%) HTTP flood\n"
                        "  192.0.2.0/24     — 250,000 req/min  (30%) GET flood\n"
                        "Legitimate traffic: ~1,200 req/min (fully saturated by attack)"
                    ),
                    "waf_status": (
                        # Real aws wafv2 get-web-acl-for-resource format
                        "$ aws wafv2 get-web-acl-for-resource \\\n"
                        "    --resource-arn arn:aws:apigateway:us-east-1::"
                        "/restapis/abc1234567/stages/prod \\\n"
                        "    --scope REGIONAL\n\n"
                        "An error occurred (WAFNonexistentItemException) "
                        "when calling the GetWebACLForResource operation: "
                        "No WebACL is associated with the resource.\n\n"
                        "$ aws wafv2 list-web-acls --scope REGIONAL "
                        "--region us-east-1\n"
                        "{\"WebACLs\": [], \"NextMarker\": null}\n\n"
                        "AWS Shield Standard: enabled (default, no DDoS response team)\n"
                        "AWS Shield Advanced: NOT subscribed\n"
                        "Managed rules active: NONE\n"
                        "Recommended fix: terraform apply wafv2_web_acl + ip_set "
                        "blocking 203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24"
                    ),
                },
                "cli_outputs": {
                    "aws wafv2 list-web-acls": (
                        # Exact real format from AWS CLI docs
                        "{\n"
                        "    \"WebACLs\": [],\n"
                        "    \"NextMarker\": null\n"
                        "}\n"
                        "No WAF Web ACLs exist in us-east-1 (REGIONAL scope)."
                    ),
                    "aws vpc get-flow-logs": (
                        # Real VPC Flow Log format per AWS official docs
                        # format: version account-id interface-id srcaddr dstaddr
                        #         srcport dstport protocol packets bytes start end
                        #         action log-status
                        # Attack pattern: SYN flood (tcp protocol=6, many packets,
                        # small bytes per packet — characteristic of SYN flood)
                        "VPC Flow Logs — eni-0f1a2b3c4d5e6f789 (api-gateway ENI)\n"
                        "Format: version account-id interface-id srcaddr dstaddr "
                        "srcport dstport protocol packets bytes start end action log-status\n\n"
                        "2 123456789012 eni-0f1a2b3c4d5e6f789 "
                        "203.0.113.14 10.0.1.50 54301 443 6 8421 421050 "
                        "1744254720 1744254780 ACCEPT OK\n"
                        "2 123456789012 eni-0f1a2b3c4d5e6f789 "
                        "203.0.113.87 10.0.1.50 54302 443 6 8350 417500 "
                        "1744254720 1744254780 ACCEPT OK\n"
                        "2 123456789012 eni-0f1a2b3c4d5e6f789 "
                        "203.0.113.143 10.0.1.50 54303 443 6 9102 455100 "
                        "1744254720 1744254780 ACCEPT OK\n"
                        "... (247 more flows from 203.0.113.0/24 in this 60s window) ...\n"
                        "2 123456789012 eni-0f1a2b3c4d5e6f789 "
                        "198.51.100.23 10.0.1.50 55001 443 6 9844 492200 "
                        "1744254720 1744254780 ACCEPT OK\n"
                        "2 123456789012 eni-0f1a2b3c4d5e6f789 "
                        "198.51.100.91 10.0.1.50 55002 80  6 7621 381050 "
                        "1744254720 1744254780 ACCEPT OK\n"
                        "... (313 more flows from 198.51.100.0/24) ...\n"
                        "2 123456789012 eni-0f1a2b3c4d5e6f789 "
                        "192.0.2.17 10.0.1.50 56111 443 6 8031 401550 "
                        "1744254720 1744254780 ACCEPT OK\n"
                        "2 123456789012 eni-0f1a2b3c4d5e6f789 "
                        "192.0.2.204 10.0.1.50 56112 443 6 8901 445050 "
                        "1744254720 1744254780 ACCEPT OK\n"
                        "... (248 more flows from 192.0.2.0/24) ...\n\n"
                        "Pattern analysis:\n"
                        "  203.0.113.0/24  → 250 source IPs, avg 8,421 pkts/flow, "
                        "port 443, protocol 6 (TCP) — SYN flood\n"
                        "  198.51.100.0/24 → 314 source IPs, avg 7,621 pkts/flow, "
                        "ports 80+443, protocol 6 — HTTP flood\n"
                        "  192.0.2.0/24    → 248 source IPs, avg 8,031 pkts/flow, "
                        "port 443, protocol 6 — GET flood\n"
                        "All flows: ACCEPT (no WAF/NACL block rules in place)"
                    ),
                },
            },
            "auto_scaling": {
                "status": "degraded",
                "error_rate_pct": 0.0,
                "response_time_ms": 5.0,
                "uptime_pct": 100.0,
                "logs": (
                    "2026-04-10T03:12:40Z WARN  [asg] "
                    "ScalingActivity: Launch  DesiredCapacity 13→213  "
                    "Cause: monitor alarm EC2-HighCPU in state ALARM\n"
                    "2026-04-10T03:12:38Z INFO  [asg] "
                    "Launching 200 new EC2 instances (m5.xlarge) in us-east-1a/b\n"
                    "2026-04-10T03:12:30Z WARN  [asg] "
                    "Cost anomaly: $38.40/hr for DDoS-driven instances. "
                    "MaxSize=500 provides NO cost cap.\n"
                    "2026-04-10T03:00:05Z INFO  [asg] "
                    "CPUUtilization alarm ALARM: 100% (DDoS flood processing)"
                ),
                "metrics": {
                    "cost": (
                        # Real aws cloudwatch get-metric-statistics for auto-scaling
                        "$ aws cloudwatch get-metric-statistics \\\n"
                        "    --namespace AWS/AutoScaling \\\n"
                        "    --metric-name GroupTotalInstances \\\n"
                        "    --dimensions Name=AutoScalingGroupName,Value=api-asg-prod \\\n"
                        "    --start-time 2026-04-10T02:59:00Z \\\n"
                        "    --end-time 2026-04-10T03:12:00Z \\\n"
                        "    --period 60 --statistics Maximum\n\n"
                        "{\n"
                        "  \"Datapoints\": [\n"
                        "    {\"Timestamp\": \"2026-04-10T02:59:00Z\", "
                        "\"Maximum\": 13.0, \"Unit\": \"Count\"},\n"
                        "    {\"Timestamp\": \"2026-04-10T03:00:00Z\", "
                        "\"Maximum\": 18.0, \"Unit\": \"Count\"},\n"
                        "    {\"Timestamp\": \"2026-04-10T03:05:00Z\", "
                        "\"Maximum\": 67.0, \"Unit\": \"Count\"},\n"
                        "    {\"Timestamp\": \"2026-04-10T03:10:00Z\", "
                        "\"Maximum\": 143.0, \"Unit\": \"Count\"},\n"
                        "    {\"Timestamp\": \"2026-04-10T03:12:00Z\", "
                        "\"Maximum\": 213.0, \"Unit\": \"Count\"}\n"
                        "  ]\n"
                        "}\n"
                        "Cost at 213 instances: 213 × $0.192/hr = $40.90/hr\n"
                        "Projected if MaxSize=500 reached: $96.00/hr ($84,096/day)\n"
                        "Fix: set MaxSize=20. Scale-in to terminate 193 excess instances."
                    ),
                    "instances": (
                        "Current: 213 running (200 excess — DDoS-driven scale-out)\n"
                        "min_size=2  desired=213  max_size=500 (UNBOUNDED)\n"
                        "Scale-out policy: CPU > 70% for 1 period (too sensitive for DDoS)\n"
                        "Cooldown: 300s (scaling still active during DDoS)"
                    ),
                },
                "cli_outputs": {
                    "aws autoscaling describe-auto-scaling-groups": (
                        # Real aws autoscaling describe-auto-scaling-groups response (from AWS docs)
                        "{\n"
                        "    \"AutoScalingGroups\": [\n"
                        "        {\n"
                        "            \"AutoScalingGroupName\": \"api-asg-prod\",\n"
                        "            \"AutoScalingGroupARN\": \"arn:aws:autoscaling:us-east-1:"
                        "123456789012:autoScalingGroup:a1b2c3d4-5678-90ab-cdef-EXAMPLE11111:"
                        "autoScalingGroupName/api-asg-prod\",\n"
                        "            \"LaunchTemplate\": {\n"
                        "                \"LaunchTemplateId\": \"lt-0a1b2c3d4e5f67890\",\n"
                        "                \"LaunchTemplateName\": \"api-launch-template\",\n"
                        "                \"Version\": \"$Latest\"\n"
                        "            },\n"
                        "            \"MinSize\": 2,\n"
                        "            \"MaxSize\": 500,\n"
                        "            \"DesiredCapacity\": 213,\n"
                        "            \"DefaultCooldown\": 300,\n"
                        "            \"AvailabilityZones\": [\"us-east-1a\", \"us-east-1b\"],\n"
                        "            \"HealthCheckType\": \"EC2\",\n"
                        "            \"CreatedTime\": \"2025-01-15T09:00:00.000Z\",\n"
                        "            \"Instances\": [\n"
                        "                {\"InstanceId\": \"i-0001\", "
                        "\"InstanceType\": \"m5.xlarge\", \"LifecycleState\": \"InService\"},\n"
                        "                {\"...\": \"213 instances total\"}\n"
                        "            ]\n"
                        "        }\n"
                        "    ]\n"
                        "}\n"
                        "⚠ MaxSize=500 with no cost cap. 200 excess instances at "
                        "$0.192/hr = $38.40/hr burning until DDoS or manual fix.\n"
                        "Fix: aws autoscaling update-auto-scaling-group \\\n"
                        "       --auto-scaling-group-name api-asg-prod \\\n"
                        "       --max-size 20 --desired-capacity 8"
                    ),
                },
            },
            "order_service": {
                "status": "down",
                "error_rate_pct": 100.0,
                "response_time_ms": 0.0,
                "uptime_pct": 0.0,
                "logs": (
                    "2026-04-10T03:12:43Z FATAL [order-svc] "
                    "Executor pool exhausted: 512/512 threads active (DDoS saturation)\n"
                    "2026-04-10T03:12:43Z ERROR [order-svc] "
                    "java.net.SocketTimeoutException: Connection queue full (32768/32768)\n"
                    "2026-04-10T03:12:40Z ERROR [order-svc] "
                    "All legitimate order requests rejected — gateway not rate-limiting\n"
                    "2026-04-10T03:12:35Z WARN  [order-svc] "
                    "HTTP 503 Service Unavailable from api-gateway upstream"
                ),
            },
            "inventory_service": {
                "status": "degraded",
                "error_rate_pct": 72.0,
                "response_time_ms": 8800.0,
                "uptime_pct": 28.0,
                "logs": (
                    "2026-04-10T03:12:43Z ERROR [inventory-svc] "
                    "HTTP 503 from api-gateway (saturated by DDoS)\n"
                    "2026-04-10T03:12:40Z WARN  [inventory-svc] "
                    "72.3% of read requests timing out (>8s timeout)\n"
                    "2026-04-10T03:12:35Z INFO  [inventory-svc] "
                    "Circuit breaker OPEN on api-gateway dependency"
                ),
            },
            "waf_service": {
                "status": "degraded",
                "error_rate_pct": 100.0,
                "response_time_ms": 0.0,
                "uptime_pct": 0.0,
                "logs": (
                    "2026-04-10T03:12:43Z INFO  [waf] "
                    "No AWS WAFv2 Web ACL associated with api-gateway/prod stage\n"
                    "2026-04-10T03:12:43Z INFO  [waf] "
                    "WAFv2 service available — no rules deployed\n"
                    "2026-04-10T03:12:43Z WARN  [waf] "
                    "Shield Standard active — no automated DDoS mitigation for L7"
                ),
            },
            "billing_dashboard": {
                "status": "degraded",
                "error_rate_pct": 0.0,
                "response_time_ms": 50.0,
                "uptime_pct": 100.0,
                "logs": (
                    "AWS COST ANOMALY ALERT — Realtime\n"
                    "Current spend rate: $51,200.00/hr (CRITICAL — 700× normal)\n"
                    "Driver: EC2 Auto Scaling — 213 instances (DesiredCapacity=213, "
                    "MaxSize=500)\n"
                    "Normal baseline: ~$73/hr (13 instances × $5.6/hr avg)\n"
                    "Runaway cause: Auto Scaling Group has no DDoS protection ceiling\n"
                    "Projected daily overrun if not fixed: $1,228,800.00\n"
                    "Action: Cap AutoScaling MaxCapacity to ≤20 immediately."
                ),
                "metrics": {
                    "ec2_cost": (
                        "Current EC2 hourly cost: $51,200.00 (213 instances)\n"
                        "m5.xlarge × 200 excess: $0.1920/hr × 200 = $38.40/hr → "
                        "$38,400.00/hr overage\n"
                        "Fix: apply_fix(auto_scaling, adjust_config, max_capacity=20)"
                    )
                },
            },
        },
        "root_causes": [
            "waf_not_configured",
            "autoscaling_unbounded",
            "api_gateway_no_rate_limit",
        ],
        "correct_fixes": {
            "waf_not_configured": {
                "target": "waf_service",
                "affected_services": ["api_gateway", "order_service", "inventory_service"],
                "fix_types": [
                    "write_terraform",
                    "deploy_waf",
                    "create_waf_rule",
                    "block_ips",
                    "apply_fix",
                    "create_web_acl",
                    "deploy",
                ],
                "config_keys": [
                    "aws_wafv2_web_acl",
                    "aws_wafv2_ip_set",
                    "203.0.113.0/24",
                    "198.51.100.0/24",
                    "192.0.2.0/24",
                    "block",
                    "waf_rule",
                    "ip_block",
                    "web_acl",
                    "terraform",
                ],
            },
            "autoscaling_unbounded": {
                "target": "auto_scaling",
                "affected_services": [],
                "fix_types": [
                    "adjust_config",
                    "update_policy",
                    "update_scaling_policy",
                    "set_max_capacity",
                    "cap_scaling",
                    "terminate_excess",
                    "scale_in",
                ],
                "config_keys": [
                    "max_capacity",
                    "max_size",
                    "desired_capacity",
                    "scaling_policy",
                    "cooldown",
                    "terminate",
                ],
            },
            "api_gateway_no_rate_limit": {
                "target": "api_gateway",
                "affected_services": [],
                "fix_types": [
                    "enable_rate_limiting",
                    "apply_fix",
                    "adjust_config",
                    "set_throttle",
                    "configure_throttling",
                    "add_usage_plan",
                ],
                "config_keys": [
                    "rate_limit",
                    "throttle",
                    "burst_limit",
                    "quota",
                    "usage_plan",
                    "requests_per_second",
                ],
            },
        },
        "verify_services": ["api_gateway", "waf_service", "order_service"],
        "post_fix_status": {
            "api_gateway": {
                "status": "healthy",
                "error_rate_pct": 0.3,
                "response_time_ms": 145.0,
                "uptime_pct": 99.8,
            },
            "waf_service": {
                "status": "healthy",
                "error_rate_pct": 0.0,
                "response_time_ms": 2.0,
                "uptime_pct": 100.0,
            },
            "auto_scaling": {
                "status": "healthy",
                "error_rate_pct": 0.0,
                "response_time_ms": 5.0,
                "uptime_pct": 100.0,
            },
            "order_service": {
                "status": "healthy",
                "error_rate_pct": 0.4,
                "response_time_ms": 210.0,
                "uptime_pct": 99.6,
            },
            "inventory_service": {
                "status": "healthy",
                "error_rate_pct": 0.1,
                "response_time_ms": 85.0,
                "uptime_pct": 99.9,
            },
            "billing_dashboard": {
                "status": "healthy",
                "error_rate_pct": 0.0,
                "response_time_ms": 50.0,
                "uptime_pct": 100.0,
            },
        },
        "max_steps": 40,
        "difficulty": "hard",
    },
}

# ---------------------------------------------------------------------------
# Real-data loader
# Enriches scenarios at startup from the data/ directory populated by
# data_fetcher.py.  Runs once at module import; silently skips if files
# are missing (e.g., during CI or first-run before data_fetcher.py is run).
# ---------------------------------------------------------------------------

def _load_real_data() -> None:
    """
    Load downloaded datasets and inject real data into SCENARIOS at module import.
    Enriches:
      - hard scenario: replaces hard-coded attack CIDRs with actual Spamhaus DROP entries
      - hard scenario: appends real CIC-IDS2018 DoS flow statistics to VPC flow logs
      - easy/hard scenarios: updates pricing from official AWS Pricing CSV
      - all scenarios: adds MITRE ATT&CK technique context to initial_alert
    """
    data_dir = Path(__file__).parent.parent / "data"

    # ── 1. Spamhaus DROP — use 3 real criminal CIDRs for the DDoS scenario ──
    spamhaus_path = data_dir / "spamhaus_drop.json"
    if spamhaus_path.exists():
        try:
            drop_data = json.loads(spamhaus_path.read_text())
            records = drop_data.get("records", [])
            # Pick 3 geographically spread /24 blocks from the real list
            # (avoid private ranges; prefer /24 for realism)
            candidates = [r["cidr"] for r in records if "/" in r["cidr"]
                          and not r["cidr"].startswith(("10.", "192.168.", "172."))]
            slash24 = [c for c in candidates if c.endswith("/24")]
            other   = [c for c in candidates if not c.endswith("/24")]
            chosen  = (slash24[:2] + other[:1]) if len(slash24) >= 2 else candidates[:3]
            if len(chosen) == 3:
                cidr_a, cidr_b, cidr_c = chosen[0], chosen[1], chosen[2]
                sbl_a = next(r["sbl_ref"] for r in records if r["cidr"] == cidr_a)
                sbl_b = next(r["sbl_ref"] for r in records if r["cidr"] == cidr_b)
                sbl_c = next(r["sbl_ref"] for r in records if r["cidr"] == cidr_c)
                hard = SCENARIOS["hard"]

                # Update the attack CIDRs in request_rate metric
                rate_metric = hard["services"]["api_gateway"]["metrics"]["request_rate"]
                rate_metric = rate_metric.replace("203.0.113.0/24", cidr_a)
                rate_metric = rate_metric.replace("198.51.100.0/24", cidr_b)
                rate_metric = rate_metric.replace("192.0.2.0/24", cidr_c)
                hard["services"]["api_gateway"]["metrics"]["request_rate"] = rate_metric

                # Update VPC Flow Logs with real CIDRs and SBL references
                vpc_logs = hard["services"]["api_gateway"]["cli_outputs"]["aws vpc get-flow-logs"]
                vpc_logs = vpc_logs.replace("203.0.113.14", cidr_a.split("/")[0][:-1] + "14")
                vpc_logs = vpc_logs.replace("203.0.113.87", cidr_a.split("/")[0][:-1] + "87")
                vpc_logs = vpc_logs.replace("203.0.113.143", cidr_a.split("/")[0][:-1] + "143")
                vpc_logs = vpc_logs.replace("203.0.113.0/24", f"{cidr_a}  ; {sbl_a}")
                vpc_logs = vpc_logs.replace("198.51.100.23", cidr_b.split("/")[0][:-1] + "23")
                vpc_logs = vpc_logs.replace("198.51.100.91", cidr_b.split("/")[0][:-1] + "91")
                vpc_logs = vpc_logs.replace("198.51.100.0/24", f"{cidr_b}  ; {sbl_b}")
                vpc_logs = vpc_logs.replace("192.0.2.17", cidr_c.split("/")[0][:-1] + "17")
                vpc_logs = vpc_logs.replace("192.0.2.204", cidr_c.split("/")[0][:-1] + "204")
                vpc_logs = vpc_logs.replace("192.0.2.0/24", f"{cidr_c}  ; {sbl_c}")
                hard["services"]["api_gateway"]["cli_outputs"]["aws vpc get-flow-logs"] = vpc_logs

                # Update correct_fixes config_keys with real CIDRs
                hard["correct_fixes"]["waf_not_configured"]["config_keys"].extend(
                    [cidr_a, cidr_b, cidr_c]
                )
                # Also update the initial_alert reference
                alert = hard["initial_alert"]
                alert = alert.replace("203.0.113.0/24", cidr_a)
                alert = alert.replace("198.51.100.0/24", cidr_b)
                alert = alert.replace("192.0.2.0/24", cidr_c)
                hard["initial_alert"] = alert
                print(f"[data] ✓ Spamhaus DROP: injected {cidr_a}, {cidr_b}, {cidr_c} "
                      f"into hard scenario VPC flow logs")
        except Exception as e:
            print(f"[data] ✗ Spamhaus DROP load error: {e}")

    # ── 2. CIC-IDS2018 — append real flow statistics to the VPC flow logs ──
    cic_path = data_dir / "cic_ids2018_ddos.json"
    if cic_path.exists():
        try:
            cic_data = json.loads(cic_path.read_text())
            records = cic_data.get("records", [])
            if records:
                sample = records[:5]
                stats_lines = []
                for r in sample:
                    label = r.get("Label", "DoS")
                    pps = r.get("Flow Pkts/s", "N/A")
                    bps = r.get("Flow Byts/s", "N/A")
                    dur = r.get("Flow Duration", "N/A")
                    syn = r.get("SYN Flag Cnt", "0")
                    stats_lines.append(
                        f"  CIC-IDS2018: {label}  pkt/s={pps}  bytes/s={bps}  "
                        f"dur={dur}µs  SYN_flags={syn}"
                    )
                cic_block = (
                    "\n\nReal flow statistics from CIC-IDS2018 (Canadian Institute for "
                    "Cybersecurity, UNB):\n"
                    + "\n".join(stats_lines)
                    + f"\n(Source: {cic_data['source']})"
                )
                hard = SCENARIOS["hard"]
                current_logs = hard["services"]["api_gateway"]["cli_outputs"]["aws vpc get-flow-logs"]
                hard["services"]["api_gateway"]["cli_outputs"]["aws vpc get-flow-logs"] = (
                    current_logs + cic_block
                )
                print(f"[data] ✓ CIC-IDS2018: appended {len(records)} real DoS flow "
                      f"stats to VPC log output")
        except Exception as e:
            print(f"[data] ✗ CIC-IDS2018 load error: {e}")

    # ── 3. AWS EC2 Pricing — update cost figures with real prices ──
    pricing_path = data_dir / "ec2_pricing.json"
    if pricing_path.exists():
        try:
            pricing_data = json.loads(pricing_path.read_text())
            prices = pricing_data.get("prices_usd_per_hour", {})
            fetched_at = pricing_data.get("fetched_at", "unknown")

            if "m5.2xlarge" in prices:
                p = prices["m5.2xlarge"]
                daily = p * 24
                monthly = p * 24 * 30
                triple_monthly = monthly * 3
                note = f" (real price from AWS Pricing API, {fetched_at[:10]})"
                for svc in SCENARIOS["easy"]["services"].values():
                    for metric_key in list(svc.get("metrics", {}).keys()):
                        old = svc["metrics"][metric_key]
                        new = (old
                               .replace("$0.384/hr", f"${p:.3f}/hr{note}")
                               .replace("$27.65/day each", f"${daily:.2f}/day each")
                               .replace("$276.48", f"${triple_monthly:.2f}")
                               .replace("$884.74", f"${triple_monthly:.2f}"))
                        svc["metrics"][metric_key] = new
                print(f"[data] ✓ EC2 pricing: m5.2xlarge=${p:.4f}/hr injected "
                      f"into easy scenario")

            if "m5.xlarge" in prices:
                p = prices["m5.xlarge"]
                note = f" (real price from AWS Pricing API, {fetched_at[:10]})"
                hard = SCENARIOS["hard"]
                for svc in hard["services"].values():
                    for metric_key in list(svc.get("metrics", {}).keys()):
                        old = svc["metrics"][metric_key]
                        svc["metrics"][metric_key] = old.replace(
                            "$0.192/hr", f"${p:.3f}/hr{note}"
                        )
                print(f"[data] ✓ EC2 pricing: m5.xlarge=${p:.4f}/hr injected "
                      f"into hard scenario")
        except Exception as e:
            print(f"[data] ✗ EC2 pricing load error: {e}")

    # ── 4. MITRE ATT&CK — append technique context to initial alerts ──
    mitre_path = data_dir / "mitre_techniques.json"
    if mitre_path.exists():
        try:
            mitre_data = json.loads(mitre_path.read_text())
            techniques = mitre_data.get("techniques", {})

            mappings = {
                "hard":   ("T1498", "Network Denial of Service"),
                "medium": ("T1530", "Data from Cloud Storage Object"),
            }
            for task, (tid, fallback_name) in mappings.items():
                tech = techniques.get(tid, {})
                name = tech.get("name", fallback_name)
                tactics = ", ".join(tech.get("tactics", []))
                url = tech.get("url", f"https://attack.mitre.org/techniques/{tid}/")
                mitre_line = (
                    f"MITRE ATT&CK: {tid} {name}"
                    + (f" [{tactics}]" if tactics else "")
                    + f" — {url}\n"
                )
                SCENARIOS[task]["initial_alert"] = (
                    SCENARIOS[task]["initial_alert"] + mitre_line
                )

            found = len(techniques)
            print(f"[data] ✓ MITRE ATT&CK: {found} technique(s) injected "
                  f"into scenario alerts ({list(techniques.keys())})")
        except Exception as e:
            print(f"[data] ✗ MITRE ATT&CK load error: {e}")


# Run at import time — silently skips if data/ files are missing
_load_real_data()


# ---------------------------------------------------------------------------
# Available actions (shown to agent each step)
# ---------------------------------------------------------------------------
AVAILABLE_ACTIONS = [
    "view_logs",
    "view_metrics",
    "list_resources",
    "run_cli",
    "view_billing",
    "apply_fix",
    "write_terraform",
    "verify",
    "escalate",
]


class IncidentResponseEnvironment(Environment):
    """
    OpenEnv Environment for CloudOps Intelligence (AIOps + FinOps + Security).

    The agent plays the role of a cloud operations engineer. Each episode
    presents a real cloud incident combining one or more of: service outage,
    cost anomaly, and security vulnerability. The agent must investigate,
    remediate, and verify recovery — all within a step budget.

    Thread-safe: all mutable state is instance-level.
    """

    SUPPORTS_CONCURRENT_SESSIONS = True

    def __init__(self) -> None:
        self._task: str = "easy"
        self._scenario: dict = {}
        self._services: Dict[str, dict] = {}
        self._root_causes_identified: List[str] = []
        self._fixes_applied: List[str] = []
        self._services_fixed: List[str] = []
        self._actions_log: List[str] = []
        self._queries_seen: List[str] = []
        self._step_count: int = 0
        self._max_steps: int = 15
        self._cumulative_reward: float = 0.0
        self._episode_id: str = ""
        self._done: bool = False
        self._escalated: bool = False

    # ── OpenEnv interface ─────────────────────────────────────────────────

    def reset(self, seed: int = 42, task: str = "easy") -> IncidentObservation:  # type: ignore[override]
        if task not in SCENARIOS:
            task = "medium"

        self._task = task
        self._scenario = SCENARIOS[task]
        self._services = {k: dict(v) for k, v in self._scenario["services"].items()}
        self._root_causes_identified = []
        self._fixes_applied = []
        self._services_fixed = []
        self._actions_log = []
        self._queries_seen = []
        self._step_count = 0
        self._max_steps = self._scenario["max_steps"]
        self._cumulative_reward = 0.0
        self._episode_id = str(uuid.uuid4())
        self._done = False
        self._escalated = False

        return self._make_observation(
            action_output=(
                "=== INCIDENT OPENED ===\n"
                + self._scenario["initial_alert"]
                + "\nBegin investigation. Use view_logs, view_metrics, list_resources, "
                "run_cli, and view_billing to identify root causes. "
                "Then apply_fix or write_terraform to remediate, and verify to confirm."
            ),
            reward=0.0,
        )

    def step(self, action: IncidentAction) -> IncidentObservation:  # type: ignore[override]
        if not self._scenario:
            # No active session — auto-reset to 'easy' so stateless HTTP callers get
            # a coherent response. Multi-step evaluation should use WebSocket (/ws).
            self.reset(task="easy")
        if self._done:
            return self._make_observation(
                action_output="Episode complete. Call reset() to start a new episode.",
                reward=0.0,
            )

        self._step_count += 1
        action_type = (action.action_type or "").lower().strip()
        target = (action.target or "").lower().strip().replace("-", "_").replace(" ", "_")
        params = action.parameters or {}

        reward = 0.0
        output = ""

        if action_type == "view_logs":
            output, reward = self._handle_view_logs(target)
        elif action_type == "view_metrics":
            metric = (params.get("metric") or "").lower().strip()
            output, reward = self._handle_view_metrics(target, metric)
        elif action_type == "list_resources":
            resource_type = (params.get("type") or target or "ec2").lower().strip()
            output, reward = self._handle_list_resources(resource_type, params)
        elif action_type == "run_cli":
            command = (params.get("command") or target or "").lower().strip()
            output, reward = self._handle_run_cli(command)
        elif action_type == "view_billing":
            period = (params.get("period") or "month").lower().strip()
            output, reward = self._handle_view_billing(target, period)
        elif action_type in ("apply_fix", "terminate", "update_policy", "block_ips"):
            fix_type = (
                params.get("fix_type") or params.get("action") or action_type
            ).lower().strip()
            config_key = (params.get("config_key") or params.get("key") or "").lower().strip()
            config_value = params.get("config_value") or params.get("value") or ""
            output, reward = self._handle_apply_fix(target, fix_type, config_key, config_value)
        elif action_type == "write_terraform":
            resource_type = (params.get("resource_type") or target or "").lower().strip()
            config = params.get("config") or params.get("terraform") or ""
            output, reward = self._handle_write_terraform(resource_type, config)
        elif action_type == "verify":
            output, reward = self._handle_verify(target)
        elif action_type == "escalate":
            output, reward = self._handle_escalate()
        else:
            output = (
                f"Unknown action_type '{action_type}'. "
                f"Valid types: {AVAILABLE_ACTIONS}"
            )

        self._actions_log.append(
            f"step={self._step_count} type={action_type} "
            f"target={target} reward={reward:.4f}"
        )
        self._cumulative_reward += reward

        if self._escalated:
            self._done = True
        elif self._step_count >= self._max_steps:
            self._done = True
            output += (
                "\n\n⏰ STEP BUDGET EXHAUSTED — incident auto-escalated. "
                "Identify all root causes before step limit."
            )
        elif self._all_resolved():
            self._done = True
            output += (
                "\n\n✅ ALL ISSUES RESOLVED — incident closed. "
                "Post-mortem scheduled."
            )

        return self._make_observation(action_output=output, reward=min(1.0, max(0.0, reward)))

    @property
    def state(self) -> IncidentState:
        return IncidentState(
            episode_id=self._episode_id,
            step_count=self._step_count,
            task=self._task,
            incident_title=self._scenario.get("title", ""),
            actions_log=list(self._actions_log),
            root_causes_identified=list(self._root_causes_identified),
            fixes_applied=list(self._fixes_applied),
            services_status={n: s["status"] for n, s in self._services.items()},
            resolved=self._all_resolved(),
            escalated=self._escalated,
            cumulative_reward=round(self._cumulative_reward, 4),
        )

    # ── Action handlers ───────────────────────────────────────────────────

    def _handle_view_logs(self, target: str) -> Tuple[str, float]:
        svc = self._find_service(target)
        if svc is None:
            return self._unknown_target(target), 0.0
        query_key = f"logs:{target}"
        reward = -W_REDUNDANT if query_key in self._queries_seen else 0.0
        if query_key not in self._queries_seen:
            self._queries_seen.append(query_key)
        logs = svc.get("logs", f"[No logs for {target}]")
        suffix = "\n[Repeated query]" if reward < 0 else ""
        return f"=== LOGS: {target} ===\n{logs}{suffix}", reward

    def _handle_view_metrics(self, target: str, metric: str) -> Tuple[str, float]:
        svc = self._find_service(target)
        if svc is None:
            return self._unknown_target(target), 0.0
        metrics = svc.get("metrics", {})
        if not metric:
            return (
                f"Specify metric. Available for {target}: {list(metrics.keys()) or ['cpu','memory','cost']}",
                0.0,
            )
        query_key = f"metrics:{target}:{metric}"
        reward = -W_REDUNDANT if query_key in self._queries_seen else 0.0
        if query_key not in self._queries_seen:
            self._queries_seen.append(query_key)
        matched = next((v for k, v in metrics.items() if metric in k or k in metric), None)
        if matched:
            suffix = "\n[Repeated query]" if reward < 0 else ""
            return f"=== METRICS: {target}/{metric} ===\n{matched}{suffix}", reward
        return f"Metric '{metric}' not found for {target}. Available: {list(metrics.keys())}", 0.0

    def _handle_list_resources(self, resource_type: str, params: dict) -> Tuple[str, float]:
        # Try to find relevant service with list data
        for svc_name, svc in self._services.items():
            if resource_type in svc_name or svc_name in resource_type:
                metrics = svc.get("metrics", {})
                for k, v in metrics.items():
                    if resource_type in k or "utilization" in k or "instances" in k:
                        return f"=== LIST RESOURCES: {resource_type} ===\n{v}", 0.0
                if "logs" in svc:
                    return f"=== LIST RESOURCES: {resource_type} ===\n{svc['logs']}", 0.0
        # Generic fallback
        return (
            f"=== LIST RESOURCES: {resource_type} ===\n"
            f"Use run_cli with 'aws {resource_type} describe-...' for detailed output.\n"
            f"Available services with resource data: {list(self._services.keys())}",
            0.0,
        )

    def _handle_run_cli(self, command: str) -> Tuple[str, float]:
        # Search all services for a matching CLI output
        for svc_name, svc in self._services.items():
            cli_outputs = svc.get("cli_outputs", {})
            for cmd_key, output in cli_outputs.items():
                if cmd_key.lower() in command or any(
                    word in command for word in cmd_key.lower().split()
                    if len(word) > 4
                ):
                    query_key = f"cli:{cmd_key}"
                    reward = -W_REDUNDANT if query_key in self._queries_seen else 0.0
                    if query_key not in self._queries_seen:
                        self._queries_seen.append(query_key)
                    return f"$ {command}\n\n{output}", reward

        # Try metric-based CLI simulation
        for svc_name, svc in self._services.items():
            if any(word in command for word in svc_name.split("_") if len(word) > 3):
                metrics = svc.get("metrics", {})
                if metrics:
                    first_metric = next(iter(metrics.values()))
                    return f"$ {command}\n\n{first_metric}", 0.0

        return (
            f"$ {command}\n\nCommand executed. "
            f"For pre-defined output, try commands like:\n"
            f"  aws ec2 describe-instances\n"
            f"  aws s3api get-bucket-acl --bucket <name>\n"
            f"  aws iam get-role-policy --role-name <role>\n"
            f"  aws wafv2 list-web-acls\n"
            f"  aws vpc get-flow-logs\n"
            f"  aws autoscaling describe-auto-scaling-groups",
            0.0,
        )

    def _handle_view_billing(self, target: str, period: str) -> Tuple[str, float]:
        # Search for billing/cost metrics
        for svc_name, svc in self._services.items():
            if "billing" in svc_name or "cost" in svc_name:
                metrics = svc.get("metrics", {})
                for k, v in metrics.items():
                    if any(w in k for w in ("cost", "billing", "ec2", "spend")):
                        return f"=== BILLING REPORT ({period}) ===\n{v}", 0.0
                logs = svc.get("logs", "")
                if logs:
                    return f"=== BILLING LOGS ===\n{logs}", 0.0
        # Search auto_scaling for cost data (hard task)
        for svc_name, svc in self._services.items():
            metrics = svc.get("metrics", {})
            for k, v in metrics.items():
                if "cost" in k:
                    return f"=== BILLING REPORT ({period}) ===\n{v}", 0.0
        return (
            f"=== BILLING REPORT ({period}) ===\n"
            f"No cost data available yet. Use run_cli('aws ce get-cost-and-usage ...') "
            f"or view_metrics(billing_dashboard, ec2_cost).",
            0.0,
        )

    # Canonical fix hints used in failure feedback — kept out of the matcher so
    # they can be shown even when the root cause is already resolved.
    _RC_HINTS: Dict[str, str] = {
        "waf_not_configured": (
            "No WAF Web ACL → write_terraform(resource_type='aws_wafv2_web_acl', "
            "config='{ip_set_cidrs: [203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24], action: block}')"
        ),
        "autoscaling_unbounded": (
            "Auto-scaling max_capacity=500 unbounded → "
            "apply_fix(target='auto_scaling', fix_type='adjust_config', "
            "config_key='max_capacity', config_value='20')"
        ),
        "api_gateway_no_rate_limit": (
            "API Gateway has NO rate limiting — FINAL root cause → "
            "apply_fix(target='api_gateway', fix_type='enable_rate_limiting', "
            "config_key='throttle', config_value='1000')"
        ),
        "zombie_ec2_cost_overrun": (
            "Zombie EC2 fleet burning cost → "
            "apply_fix(target='ec2_fleet', fix_type='terminate', config_key='zombie')"
        ),
        "s3_public_access_enabled": (
            "S3 bucket public ACL → "
            "apply_fix(target='s3_prod_customer_data', fix_type='block_public_access')"
        ),
        "iam_role_typo": (
            "IAM policy typo 's3:GetObejct' → "
            "apply_fix(target='iam_payment_role', fix_type='fix_iam', "
            "config_key='s3:GetObejct', config_value='s3:GetObject')"
        ),
    }

    def _handle_write_terraform(self, resource_type: str, config: str) -> Tuple[str, float]:
        """
        Grades Terraform submissions.  Checks for correct resource types and
        malicious CIDRs.  When no remaining root cause is addressed, returns a
        *targeted* failure message that names every unresolved root cause and
        the exact action needed — preventing the agent from looping.
        """
        combined = (resource_type + " " + config).lower()
        correct_fixes = self._scenario.get("correct_fixes", {})

        for rc_id, fix_def in correct_fixes.items():
            if rc_id in self._fixes_applied:
                continue
            config_keys = [k.lower() for k in fix_def.get("config_keys", [])]
            fix_types   = [f.lower() for f in fix_def.get("fix_types", [])]

            tf_matches = any(k in combined for k in config_keys)
            type_matches = (
                any(f in combined for f in fix_types)
                or "terraform" in combined
                or "aws_" in resource_type
                or "aws_" in combined
            )
            target_matches = (
                fix_def["target"] in ("waf_service",)
                or resource_type in fix_def.get("config_keys", [])
                or any(k in resource_type for k in config_keys)
            )

            if tf_matches and type_matches and target_matches:
                self._fixes_applied.append(rc_id)
                if rc_id not in self._root_causes_identified:
                    self._root_causes_identified.append(rc_id)
                self._services_fixed.append(fix_def["target"])
                reward = W_ROOT_CAUSE + W_FIX_APPLIED
                # Build a list of what's still left so the agent knows next steps
                still_remaining = [
                    r for r in correct_fixes if r not in self._fixes_applied
                ]
                next_hint = ""
                if still_remaining:
                    hints = [
                        f"  • {r.replace('_', ' ').upper()}: "
                        f"{self._RC_HINTS.get(r, 'investigate further')}"
                        for r in still_remaining
                    ]
                    next_hint = (
                        f"\n\n🎯 STILL UNRESOLVED ({len(still_remaining)} remaining):\n"
                        + "\n".join(hints)
                    )
                return (
                    f"✅ TERRAFORM VALIDATED & APPLIED\n"
                    f"Resource   : {resource_type or 'aws_wafv2_web_acl'}\n"
                    f"Root cause : {rc_id.replace('_', ' ')} — RESOLVED\n"
                    f"WAF rule deployed and attached to api_gateway.\n"
                    f"Attack traffic from 203.0.113.0/24, 198.51.100.0/24, "
                    f"192.0.2.0/24 is now BLOCKED.\n"
                    f"Reward: +{reward:.2f}"
                    f"{next_hint}"
                ), reward

        # ── No remaining root cause was addressed ──────────────────────────────
        remaining = [r for r in correct_fixes if r not in self._fixes_applied]
        already   = [r for r in correct_fixes if r in self._fixes_applied]

        if not remaining:
            return (
                "✅ All root causes already resolved via Terraform / apply_fix.\n"
                "Use verify() to confirm services are healthy."
            ), 0.0

        already_msg = ""
        if already:
            already_msg = (
                f"\nAlready resolved: "
                + ", ".join(f"✅ {r.replace('_', ' ')}" for r in already)
            )

        remaining_lines = [
            f"  • {r.replace('_', ' ').upper()}: "
            f"{self._RC_HINTS.get(r, 'investigate further')}"
            for r in remaining
        ]
        return (
            f"⚠️  Terraform does NOT address any remaining root cause.{already_msg}\n\n"
            f"🎯 UNRESOLVED ROOT CAUSES ({len(remaining)} remaining — use apply_fix or "
            f"write_terraform as appropriate):\n"
            + "\n".join(remaining_lines)
        ), -W_WRONG_FIX

    def _handle_apply_fix(
        self, target: str, fix_type: str, config_key: str, config_value: str
    ) -> Tuple[str, float]:
        correct_fixes = self._scenario.get("correct_fixes", {})

        for rc_id, fix_def in correct_fixes.items():
            if rc_id in self._fixes_applied:
                continue

            svc_target = fix_def["target"].replace("-", "_").replace(" ", "_")
            fix_types_lower = [f.lower() for f in fix_def["fix_types"]]
            config_keys_lower = [
                k.lower().replace("-", "_") for k in fix_def.get("config_keys", [])
            ]

            # Target passes if:
            #  • empty (agent didn't specify one)
            #  • exact match against the fix's canonical target
            #  • any word-token of the canonical target appears in the supplied target
            #  • the supplied target matches (or is contained in) a known config_key
            #    (covers cases where the agent sends a specific instance ID as the target)
            target_ok = (
                not target
                or target == svc_target
                or any(t in target for t in svc_target.split("_"))
                or any(k in target or target in k for k in config_keys_lower)
            )
            if not target_ok:
                continue

            combined_input = f"{fix_type} {config_key} {config_value}".lower()
            fix_match = any(f in combined_input or combined_input in f for f in fix_types_lower)
            key_match = any(k in combined_input for k in config_keys_lower) if config_keys_lower else False

            if fix_match or key_match:
                self._fixes_applied.append(rc_id)
                if rc_id not in self._root_causes_identified:
                    self._root_causes_identified.append(rc_id)
                self._services_fixed.append(svc_target)
                reward = W_ROOT_CAUSE + W_FIX_APPLIED
                fix_desc = (
                    f"adjust {config_key}={config_value}" if config_key else fix_type
                )
                return (
                    f"✅ FIX APPLIED: {fix_desc} on {svc_target}\n"
                    f"Root cause resolved: {rc_id.replace('_', ' ')}\n"
                    f"Reward: +{reward:.2f}\n"
                    f"Next: verify({svc_target!r}) to confirm."
                ), reward

        return (
            f"⚠️  Fix '{fix_type}' on '{target}' did not match any remaining root cause.\n"
            f"Continue investigating logs/metrics/billing to identify what to fix."
        ), -W_WRONG_FIX

    def _handle_verify(self, target: str) -> Tuple[str, float]:
        svc = self._find_service(target)
        if svc is None:
            return self._unknown_target(target), 0.0

        post_fix = self._scenario.get("post_fix_status", {})
        correct_fixes = self._scenario.get("correct_fixes", {})
        verify_key = f"verify:{target}"

        cause_fixed = any(
            rc_id in self._fixes_applied
            and (
                correct_fixes[rc_id]["target"].replace("-", "_") == target
                or target in [
                    s.replace("-", "_")
                    for s in correct_fixes[rc_id].get("affected_services", [])
                ]
            )
            for rc_id in correct_fixes
        )

        if cause_fixed and target in post_fix:
            svc.update(post_fix[target])
            # Cascade-heal downstream services
            for downstream, ds_post in post_fix.items():
                if downstream != target:
                    ds = self._services.get(downstream, {})
                    if ds.get("status") in ("degraded", "down"):
                        self._services[downstream].update(ds_post)

        status = svc.get("status", "unknown")
        reward = 0.0

        if status == "healthy":
            if verify_key not in self._queries_seen:
                reward = W_VERIFY
                self._queries_seen.append(verify_key)
            return (
                f"✅ HEALTH CHECK PASSED: {target}\n"
                f"Status         : HEALTHY\n"
                f"Error rate     : {svc['error_rate_pct']:.1f}%\n"
                f"Response time  : {svc['response_time_ms']:.0f} ms\n"
                f"Uptime         : {svc['uptime_pct']:.1f}%"
                + (f"\nReward: +{reward:.2f}" if reward > 0 else "")
            ), reward
        else:
            return (
                f"⚠️  HEALTH CHECK FAILED: {target}\n"
                f"Status         : {status.upper()}\n"
                f"Error rate     : {svc['error_rate_pct']:.1f}%\n"
                f"Response time  : {svc['response_time_ms']:.0f} ms\n"
                f"Apply the correct fix first, then verify again."
            ), 0.0

    def _handle_escalate(self) -> Tuple[str, float]:
        self._escalated = True
        fixed = len(self._fixes_applied)
        total = len(self._scenario["root_causes"])
        partial = fixed / max(1, total) * 0.5
        return (
            f"📞 ESCALATED — {fixed}/{total} root causes fixed before escalation.\n"
            f"Partial credit: {partial:.2f}"
        ), partial

    # ── Helpers ───────────────────────────────────────────────────────────

    def _find_service(self, target: str) -> Optional[dict]:
        if target in self._services:
            return self._services[target]
        # Fuzzy: try partial match
        for name, svc in self._services.items():
            if target in name or name in target:
                return svc
        return None

    def _unknown_target(self, target: str) -> str:
        return (
            f"Resource '{target}' not found. "
            f"Available: {list(self._services.keys())}"
        )

    def _all_resolved(self) -> bool:
        if not self._scenario:
            return False
        root_causes = set(self._scenario.get("root_causes", []))
        if not root_causes:
            return False
        if not root_causes.issubset(set(self._fixes_applied)):
            return False
        return all(
            self._services.get(s, {}).get("status") == "healthy"
            for s in self._scenario.get("verify_services", [])
        )

    def _make_observation(self, action_output: str, reward: float) -> IncidentObservation:
        healthy = sum(1 for s in self._services.values() if s.get("status") == "healthy")
        total = len(self._services)
        rc_found = len(self._root_causes_identified)
        rc_total = len(self._scenario.get("root_causes", []))

        if self._all_resolved():
            reward = max(reward, W_COMPLETION)

        services_list = [
            ServiceHealth(
                name=name,
                status=svc.get("status", "unknown"),
                error_rate_pct=svc.get("error_rate_pct", 0.0),
                response_time_ms=svc.get("response_time_ms", 0.0),
                uptime_pct=svc.get("uptime_pct", 100.0),
            )
            for name, svc in self._services.items()
        ]

        correct_fixes = self._scenario.get("correct_fixes", {})
        remaining_rcs = [
            rc for rc in self._scenario.get("root_causes", [])
            if rc not in self._fixes_applied
        ]

        situation = (
            f"=== STATUS — step {self._step_count}/{self._max_steps} ===\n"
            f"Task    : {self._task.upper()} — {self._scenario.get('title', '')}\n"
            f"Domain  : {self._scenario.get('domain', '')}\n"
            f"Services: {healthy}/{total} healthy | "
            f"Root causes: {rc_found}/{rc_total} resolved\n"
            f"Resolved: {'YES ✅' if self._all_resolved() else 'NO ⏳'}\n"
        )
        if remaining_rcs:
            hint_lines = [
                f"  → {rc.replace('_', ' ').upper()}: "
                f"{self._RC_HINTS.get(rc, 'investigate with logs/metrics/CLI')}"
                for rc in remaining_rcs
            ]
            situation += "UNRESOLVED ROOT CAUSES:\n" + "\n".join(hint_lines) + "\n"
        else:
            # All root causes fixed — direct the agent to close the episode
            verify_targets = self._scenario.get("verify_services", [])
            if verify_targets and not self._all_resolved():
                verify_call = f"verify({verify_targets[0]})"
                situation += (
                    f"✅ All root causes resolved!  "
                    f"Call verify() to confirm service health and complete the episode.\n"
                    f"  e.g. {verify_call}\n"
                )

        return IncidentObservation(
            situation_report=situation,
            services=services_list,
            action_output=action_output,
            available_actions=AVAILABLE_ACTIONS,
            services_healthy=healthy,
            services_total=total,
            root_causes_found=rc_found,
            root_causes_total=rc_total,
            reward=float(min(1.0, max(0.0, reward))),
            done=self._done,
        )
