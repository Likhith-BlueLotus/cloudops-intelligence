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

import uuid
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
    # Monthly AWS bill spiked 340%. Three EC2 instances have been running
    # with 0% CPU utilization for 32 days following a product launch that
    # was quietly cancelled. Combined cost: $3,200 / month.
    # The agent must identify and terminate all three zombie instances.
    # ════════════════════════════════════════════════════════════════════════
    "easy": {
        "title": "AWS Billing Spike — Zombie EC2 Instances",
        "domain": "FinOps",
        "initial_alert": (
            "BILLING ALERT — Unusual AWS Charges Detected\n"
            "Time      : 2026-04-10 08:00:00 UTC\n"
            "Account   : prod-account-7291 (us-east-1)\n"
            "Symptom   : EC2 spend $12,400 this month (+340% vs $2,800 baseline)\n"
            "Projected : $14,880 / month if unresolved (+$12,080 overspend)\n"
            "SLA       : Finance review in 4 hours — identify and terminate waste\n"
            "Runbook   : https://wiki.internal/runbooks/cloud-cost-anomaly\n"
        ),
        "services": {
            "billing_dashboard": {
                "status": "healthy",
                "error_rate_pct": 0.0,
                "response_time_ms": 50.0,
                "uptime_pct": 100.0,
                "logs": (
                    "[08:00:01] INFO  billing: Monthly spend alert triggered\n"
                    "[08:00:01] WARN  billing: EC2 On-Demand charges: $9,600 (budget: $2,000)\n"
                    "[08:00:01] WARN  billing: EBS volume charges: $2,800 (budget: $600)\n"
                    "[08:00:01] INFO  billing: Cost anomaly detector: 3 resources flagged\n"
                    "[08:00:00] INFO  billing: Top cost driver: us-east-1 m5.2xlarge instances\n"
                ),
                "metrics": {
                    "ec2_cost": (
                        "EC2 Cost — Daily Trend (last 35 days)\n"
                        "Mar 10  $93 / day   (baseline)\n"
                        "Mar 11  $93 / day\n"
                        "Mar 12  $93 / day\n"
                        "Mar 13  $402 / day  [+332%] ← 3 m5.2xlarge instances launched\n"
                        "Mar 14  $402 / day  [cost anomaly]\n"
                        "Apr 10  $402 / day  [running 32 days — zero utilisation detected]\n"
                        "\nTop resources by cost:\n"
                        "  i-0a1b2c3d4e5f6789  m5.2xlarge  $0.384/hr  $295/month\n"
                        "  i-0b2c3d4e5f678901  m5.2xlarge  $0.384/hr  $295/month\n"
                        "  i-0c3d4e5f67890123  m5.2xlarge  $0.384/hr  $295/month\n"
                    ),
                },
            },
            "ec2_fleet": {
                "status": "degraded",
                "error_rate_pct": 0.0,
                "response_time_ms": 10.0,
                "uptime_pct": 100.0,
                "logs": (
                    "[08:00:01] INFO  ec2: 12 instances running in us-east-1\n"
                    "[08:00:01] WARN  ec2: Cost anomaly: 3 instances with CPU=0% for 32 days\n"
                    "[08:00:00] INFO  ec2: Instances i-0a1b..., i-0b2c..., i-0c3d... "
                    "launched 2026-03-09 for cancelled 'Project Phoenix' launch\n"
                ),
                "metrics": {
                    "utilization": (
                        "EC2 CPU Utilisation — Last 32 Days\n"
                        "\nInstance ID           | Type        | Avg CPU | Max CPU | State   | Age\n"
                        "i-0a1b2c3d4e5f6789  | m5.2xlarge  |  0.00%  |  0.02%  | running | 32d  ← ZOMBIE\n"
                        "i-0b2c3d4e5f678901  | m5.2xlarge  |  0.00%  |  0.01%  | running | 32d  ← ZOMBIE\n"
                        "i-0c3d4e5f67890123  | m5.2xlarge  |  0.00%  |  0.00%  | running | 32d  ← ZOMBIE\n"
                        "i-0d4e5f6789012345  | t3.medium   | 42.00%  | 87.00%  | running |  8d  (prod)\n"
                        "i-0e5f678901234567  | t3.medium   | 38.00%  | 79.00%  | running |  8d  (prod)\n"
                        "... 7 more healthy prod instances ...\n"
                        "\nRecommendation: Terminate i-0a1b..., i-0b2c..., i-0c3d... "
                        "(saves $885/month, all tagged ProjectPhoenix:cancelled)\n"
                    ),
                    "tags": (
                        "EC2 Instance Tags\n"
                        "i-0a1b2c3d4e5f6789: Project=ProjectPhoenix, Status=cancelled, "
                        "Owner=team-alpha, LaunchDate=2026-03-09\n"
                        "i-0b2c3d4e5f678901: Project=ProjectPhoenix, Status=cancelled, "
                        "Owner=team-alpha, LaunchDate=2026-03-09\n"
                        "i-0c3d4e5f67890123: Project=ProjectPhoenix, Status=cancelled, "
                        "Owner=team-alpha, LaunchDate=2026-03-09\n"
                    ),
                },
                "cli_outputs": {
                    "aws ec2 describe-instances": (
                        "[\n"
                        "  {\"InstanceId\": \"i-0a1b2c3d4e5f6789\", \"InstanceType\": \"m5.2xlarge\", "
                        "\"State\": \"running\", \"LaunchTime\": \"2026-03-09T02:14:00Z\", "
                        "\"Tags\": [{\"Key\": \"Project\", \"Value\": \"ProjectPhoenix\"}, "
                        "{\"Key\": \"Status\", \"Value\": \"cancelled\"}]},\n"
                        "  {\"InstanceId\": \"i-0b2c3d4e5f678901\", \"InstanceType\": \"m5.2xlarge\", "
                        "\"State\": \"running\", \"LaunchTime\": \"2026-03-09T02:15:00Z\", "
                        "\"Tags\": [{\"Key\": \"Project\", \"Value\": \"ProjectPhoenix\"}, "
                        "{\"Key\": \"Status\", \"Value\": \"cancelled\"}]},\n"
                        "  {\"InstanceId\": \"i-0c3d4e5f67890123\", \"InstanceType\": \"m5.2xlarge\", "
                        "\"State\": \"running\", \"LaunchTime\": \"2026-03-09T02:15:00Z\", "
                        "\"Tags\": [{\"Key\": \"Project\", \"Value\": \"ProjectPhoenix\"}, "
                        "{\"Key\": \"Status\", \"Value\": \"cancelled\"}]}\n"
                        "]\n"
                        "(3 zombie instances. 9 active prod instances omitted.)"
                    ),
                    "aws ec2 terminate-instances": (
                        "{\n"
                        "  \"TerminatingInstances\": [\n"
                        "    {\"InstanceId\": \"<target>\", "
                        "\"CurrentState\": {\"Name\": \"shutting-down\"}, "
                        "\"PreviousState\": {\"Name\": \"running\"}}\n"
                        "  ]\n"
                        "}"
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
                    "i-0a1b2c3d4e5f6789",
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
    # Two concurrent issues triggered by a single misconfigured deployment:
    # 1. S3 bucket prod-customer-data accidentally set to public-read-write
    #    (CRITICAL — PII exposed to the public internet for 3 hours)
    # 2. Payment service IAM role has a typo in the S3 permission, causing
    #    all payment flows to return 401/403 errors.
    # ════════════════════════════════════════════════════════════════════════
    "medium": {
        "title": "Security Incident: S3 Public Exposure + Payment Service Auth Failure",
        "domain": "Security + SRE",
        "initial_alert": (
            "P0 SECURITY ALERT — Critical Vulnerability + Service Outage\n"
            "Time      : 2026-04-10 11:47:03 UTC\n"
            "Issues    : S3 data exposure (CRITICAL) + payment-service auth failures\n"
            "Symptom 1 : AWS Trusted Advisor: S3 bucket 'prod-customer-data' is PUBLIC\n"
            "Symptom 2 : payment-service HTTP 403 error rate 89% — checkout broken\n"
            "User Impact: ~22,000 customers cannot complete purchases\n"
            "Compliance : GDPR breach window open since 08:52 UTC (2h 55m ago)\n"
            "SLA       : Security: immediate | Service: < 15 min\n"
            "Runbook   : https://wiki.internal/runbooks/s3-exposure\n"
        ),
        "services": {
            "payment_service": {
                "status": "degraded",
                "error_rate_pct": 89.0,
                "response_time_ms": 180.0,
                "uptime_pct": 11.0,
                "logs": (
                    "[11:47:02] ERROR payment_service: S3 access denied — "
                    "s3:GetObject on arn:aws:s3:::prod-customer-data/certs/payment.pem\n"
                    "[11:47:01] ERROR payment_service: "
                    "com.amazonaws.services.s3.model.AmazonS3Exception: "
                    "Access Denied (Service: Amazon S3; Status Code: 403)\n"
                    "[11:47:00] WARN  payment_service: Payment certificate load failed — "
                    "falling back to insecure mode (rejected by gateway)\n"
                    "[11:46:55] ERROR payment_service: TLS handshake failed — "
                    "certificate unavailable from S3\n"
                    "[11:45:50] INFO  payment_service: Deployment v4.2.0 completed "
                    "(IAM role updated: payment-service-role)\n"
                ),
            },
            "s3_prod_customer_data": {
                "status": "degraded",
                "error_rate_pct": 0.0,
                "response_time_ms": 8.0,
                "uptime_pct": 100.0,
                "logs": (
                    "[11:47:02] WARN  s3: 47 anonymous GET requests to "
                    "prod-customer-data/customers/ in last 10 min\n"
                    "[11:47:00] WARN  s3: Public access block disabled on "
                    "prod-customer-data (changed by deployment v4.2.0)\n"
                    "[11:46:58] INFO  s3: Bucket ACL changed to public-read-write "
                    "by iam:deployment-user at 08:52:11 UTC\n"
                    "[11:46:55] WARN  s3: Anonymous PUT request to "
                    "prod-customer-data/test.txt (succeeded — public write enabled!)\n"
                ),
                "cli_outputs": {
                    "aws s3api get-bucket-acl": (
                        "{\n"
                        "  \"Owner\": {\"DisplayName\": \"prod-account\"},\n"
                        "  \"Grants\": [\n"
                        "    {\"Grantee\": {\"Type\": \"CanonicalUser\"}, "
                        "\"Permission\": \"FULL_CONTROL\"},\n"
                        "    {\"Grantee\": {\"Type\": \"Group\", "
                        "\"URI\": \"http://acs.amazonaws.com/groups/global/AllUsers\"}, "
                        "\"Permission\": \"READ\"},\n"
                        "    {\"Grantee\": {\"Type\": \"Group\", "
                        "\"URI\": \"http://acs.amazonaws.com/groups/global/AllUsers\"}, "
                        "\"Permission\": \"WRITE\"}\n"
                        "  ]\n"
                        "}\n"
                        "⚠️  CRITICAL: public-read-write ACL detected on bucket "
                        "containing customer PII data."
                    ),
                    "aws s3api get-public-access-block": (
                        "{\n"
                        "  \"PublicAccessBlockConfiguration\": {\n"
                        "    \"BlockPublicAcls\": false,\n"
                        "    \"IgnorePublicAcls\": false,\n"
                        "    \"BlockPublicPolicy\": false,\n"
                        "    \"RestrictPublicBuckets\": false\n"
                        "  }\n"
                        "}\n"
                        "All public access blocks DISABLED — bucket is fully public."
                    ),
                },
                "metrics": {
                    "access": (
                        "S3 — Request Source (last 3 hours)\n"
                        "08:52 UTC: public-read-write ACL applied\n"
                        "09:00–11:47: 2,847 anonymous GET requests (customers/ prefix)\n"
                        "11:41–11:47: 12 anonymous PUT requests (test writes)\n"
                        "Status: CRITICAL DATA EXPOSURE — public internet can read and write\n"
                    ),
                },
            },
            "iam_payment_role": {
                "status": "degraded",
                "error_rate_pct": 0.0,
                "response_time_ms": 5.0,
                "uptime_pct": 100.0,
                "logs": (
                    "[11:47:01] WARN  iam: Deny on s3:GetObject for role "
                    "payment-service-role — policy missing s3:GetObject action\n"
                    "[11:45:50] INFO  iam: Role policy updated by deployment v4.2.0\n"
                    "[11:45:48] INFO  iam: Previous policy had s3:GetObject; "
                    "new policy has s3:GetObejct (typo — invalid action, silently ignored)\n"
                ),
                "cli_outputs": {
                    "aws iam get-role-policy": (
                        "{\n"
                        "  \"RoleName\": \"payment-service-role\",\n"
                        "  \"PolicyName\": \"payment-s3-access\",\n"
                        "  \"PolicyDocument\": {\n"
                        "    \"Statement\": [{\n"
                        "      \"Effect\": \"Allow\",\n"
                        "      \"Action\": [\n"
                        "        \"s3:GetObejct\",\n"
                        "        \"s3:ListBucket\"\n"
                        "      ],\n"
                        "      \"Resource\": \"arn:aws:s3:::prod-customer-data/*\"\n"
                        "    }]\n"
                        "  }\n"
                        "}\n"
                        "⚠️  TYPO DETECTED: 's3:GetObejct' is not a valid IAM action "
                        "(should be 's3:GetObject'). Permission is silently ignored by AWS."
                    ),
                },
                "metrics": {
                    "auth": (
                        "IAM Role — Auth Failures (last 30 min)\n"
                        "payment-service-role: 892 denied s3:GetObject calls\n"
                        "Denial reason: Action 's3:GetObejct' not in policy "
                        "(invalid action string — typo in deployment v4.2.0)\n"
                    ),
                },
            },
            "api_gateway": {
                "status": "degraded",
                "error_rate_pct": 89.0,
                "response_time_ms": 180.0,
                "uptime_pct": 11.0,
                "logs": (
                    "[11:47:02] ERROR api_gateway: /checkout → payment_service 403\n"
                    "[11:47:00] WARN  api_gateway: Payment flow failure rate: 89%\n"
                ),
            },
            "auth_service": {
                "status": "healthy",
                "error_rate_pct": 0.1,
                "response_time_ms": 12.0,
                "uptime_pct": 99.9,
                "logs": (
                    "[11:47:00] INFO  auth_service: User sessions: 22,047 active\n"
                    "[11:47:00] WARN  auth_service: Payment errors upstream\n"
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
    # A coordinated DDoS from three CIDR ranges is flooding the API gateway.
    # Auto-scaling responds by spinning up 200 extra instances (cost $50k/hr).
    # The attack cascades: order service and inventory service begin failing
    # as legitimate traffic cannot get through.
    # Three root causes — each in a different domain:
    #   1. No WAF configured to block malicious IPs (Security)
    #   2. Auto-scaling max_capacity mis-set to unlimited (FinOps)
    #   3. Rate-limiting not enabled on the API gateway (SRE)
    # ════════════════════════════════════════════════════════════════════════
    "hard": {
        "title": "DDoS Attack — WAF Deployment + Runaway Auto-Scaling + Cascading Failures",
        "domain": "Security + FinOps + SRE",
        "initial_alert": (
            "P0 INCIDENT — Active DDoS Attack + Cascading Failures\n"
            "Time      : 2026-04-10 03:12:44 UTC\n"
            "Attack    : Volumetric DDoS from 3 CIDR ranges — 840k req/min\n"
            "Services  : api_gateway (90% errors), order_service (down), "
            "inventory_service (degraded)\n"
            "Cost      : Auto-scaling spawned 200 extra EC2 instances — "
            "CURRENT COST $51,200/hr\n"
            "User Impact: ALL purchases and inventory updates blocked\n"
            "Compliance: WAF not configured — DDoS protection SLA breached\n"
            "SLA       : P0 — immediate response required\n"
            "Runbook   : https://wiki.internal/runbooks/ddos-response\n"
        ),
        "services": {
            "api_gateway": {
                "status": "degraded",
                "error_rate_pct": 90.0,
                "response_time_ms": 28000.0,
                "uptime_pct": 10.0,
                "logs": (
                    "[03:12:43] ERROR api_gateway: Request flood detected — "
                    "840,000 req/min (baseline: 1,200 req/min)\n"
                    "[03:12:43] WARN  api_gateway: Top source IPs — "
                    "203.0.113.x (280k req/min), "
                    "198.51.100.x (310k req/min), "
                    "192.0.2.x (250k req/min)\n"
                    "[03:12:41] ERROR api_gateway: Rate limit threshold exceeded "
                    "(throttling disabled — no rate limit policy configured)\n"
                    "[03:12:40] WARN  api_gateway: No WAF Web ACL attached to this "
                    "API Gateway stage\n"
                    "[03:12:38] INFO  api_gateway: Auto-scaling triggered — "
                    "target group capacity: 213 instances (was: 13)\n"
                ),
                "metrics": {
                    "request_rate": (
                        "API Gateway — Request Rate (last 30 min)\n"
                        "02:42  1,180 req/min (normal)\n"
                        "02:52  1,210 req/min (normal)\n"
                        "03:00  8,400 req/min [attack begins]\n"
                        "03:05  120,000 req/min [escalating]\n"
                        "03:10  580,000 req/min [DDoS peak]\n"
                        "03:12  840,000 req/min [current]\n"
                        "\nAttack source CIDRs:\n"
                        "  203.0.113.0/24   — 280,000 req/min (33%)\n"
                        "  198.51.100.0/24  — 310,000 req/min (37%)\n"
                        "  192.0.2.0/24     — 250,000 req/min (30%)\n"
                        "Legitimate traffic: ~1,200 req/min (completely masked)\n"
                    ),
                    "waf_status": (
                        "WAF Configuration — api_gateway (us-east-1)\n"
                        "Web ACL attached: NONE\n"
                        "Rate-based rules: NOT CONFIGURED\n"
                        "IP block rules: NOT CONFIGURED\n"
                        "AWS Shield Advanced: NOT ENABLED\n"
                        "\nRecommendation: Deploy WAFv2 Web ACL with IP set block rule "
                        "for the 3 malicious CIDRs and attach to api_gateway stage.\n"
                    ),
                },
                "cli_outputs": {
                    "aws wafv2 list-web-acls": (
                        "{\n"
                        "  \"WebACLs\": []\n"
                        "}\n"
                        "No WAF Web ACLs configured in us-east-1."
                    ),
                    "aws vpc get-flow-logs": (
                        "VPC Flow Logs — Last 15 min (attack traffic only)\n"
                        "2026-04-10T03:00:00Z 203.0.113.0/24  → 10.0.1.50:443 "
                        "ACCEPT 280000 packets (SYN flood pattern)\n"
                        "2026-04-10T03:00:00Z 198.51.100.0/24 → 10.0.1.50:443 "
                        "ACCEPT 310000 packets (HTTP flood pattern)\n"
                        "2026-04-10T03:00:00Z 192.0.2.0/24    → 10.0.1.50:443 "
                        "ACCEPT 250000 packets (GET flood pattern)\n"
                        "Source IPs not in any blocklist. No WAF rules matched.\n"
                    ),
                },
            },
            "auto_scaling": {
                "status": "degraded",
                "error_rate_pct": 0.0,
                "response_time_ms": 5.0,
                "uptime_pct": 100.0,
                "logs": (
                    "[03:12:40] WARN  auto_scaling: Scale-out event — "
                    "target: 213 instances (was: 13)\n"
                    "[03:12:40] WARN  auto_scaling: max_capacity=500 — "
                    "no upper bound protection against DDoS-driven scaling\n"
                    "[03:12:38] INFO  auto_scaling: Launching 200 m5.xlarge instances\n"
                    "[03:12:30] WARN  auto_scaling: Cost alarm: $51,200/hr "
                    "(200 × m5.xlarge × $0.192/hr + data transfer)\n"
                    "[03:00:00] INFO  auto_scaling: Scale-out triggered by "
                    "CPU > 70% threshold (100% CPU from DDoS flood processing)\n"
                ),
                "metrics": {
                    "cost": (
                        "Auto-Scaling — Realtime Cost\n"
                        "02:59  13 instances  $2.50/hr (baseline)\n"
                        "03:00  18 instances  $3.46/hr [scale-out begins]\n"
                        "03:05  67 instances  $12.86/hr\n"
                        "03:10  143 instances  $27.46/hr\n"
                        "03:12  213 instances  $40.90/hr [current]\n"
                        "Projected at max_capacity=500: $96.00/hr ($84,096/day)\n"
                        "\nmax_capacity config: 500 (NO PROTECTION AGAINST RUNAWAY SCALING)\n"
                        "Recommended: Set max_capacity=20 and enable scaling protection\n"
                    ),
                    "instances": (
                        "Auto-Scaling Group — Instance Count\n"
                        "Current: 213 running (200 unnecessary — DDoS-driven)\n"
                        "min_size: 2, desired: 213, max_size: 500\n"
                        "Cooldown: 60s (insufficient for DDoS scenarios)\n"
                    ),
                },
                "cli_outputs": {
                    "aws autoscaling describe-auto-scaling-groups": (
                        "{\n"
                        "  \"AutoScalingGroupName\": \"api-asg-prod\",\n"
                        "  \"MinSize\": 2,\n"
                        "  \"MaxSize\": 500,\n"
                        "  \"DesiredCapacity\": 213,\n"
                        "  \"Instances\": \"213 running (200 launched in last 12 min)\"\n"
                        "}\n"
                        "COST ALERT: 200 excess instances at $0.192/hr = $38.40/hr ongoing"
                    ),
                },
            },
            "order_service": {
                "status": "down",
                "error_rate_pct": 100.0,
                "response_time_ms": 0.0,
                "uptime_pct": 0.0,
                "logs": (
                    "[03:12:43] FATAL order_service: Overloaded by DDoS traffic — "
                    "connection queue full (32768 / 32768)\n"
                    "[03:12:40] ERROR order_service: Unable to process legitimate "
                    "orders — all threads busy serving DDoS requests\n"
                    "[03:12:35] WARN  order_service: Thread pool exhausted — "
                    "no rate limiting at gateway layer\n"
                ),
            },
            "inventory_service": {
                "status": "degraded",
                "error_rate_pct": 72.0,
                "response_time_ms": 8800.0,
                "uptime_pct": 28.0,
                "logs": (
                    "[03:12:43] ERROR inventory_service: Upstream api_gateway "
                    "returning 503 (overloaded by DDoS)\n"
                    "[03:12:40] WARN  inventory_service: 72% of requests timing out\n"
                ),
            },
            "waf_service": {
                "status": "degraded",
                "error_rate_pct": 100.0,
                "response_time_ms": 0.0,
                "uptime_pct": 0.0,
                "logs": (
                    "[03:12:43] INFO  waf: No Web ACL configured for api_gateway\n"
                    "[03:12:43] INFO  waf: AWS WAFv2 available but not deployed\n"
                ),
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
        },
        "max_steps": 40,
        "difficulty": "hard",
    },
}

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

    def _handle_write_terraform(self, resource_type: str, config: str) -> Tuple[str, float]:
        """
        Grades Terraform submissions for the DDoS WAF task.
        Checks for presence of correct resource types and malicious CIDRs.
        """
        combined = (resource_type + " " + config).lower()
        correct_fixes = self._scenario.get("correct_fixes", {})

        for rc_id, fix_def in correct_fixes.items():
            if rc_id in self._fixes_applied:
                continue
            config_keys = [k.lower() for k in fix_def.get("config_keys", [])]
            fix_types = [f.lower() for f in fix_def.get("fix_types", [])]

            tf_matches = any(k in combined for k in config_keys)
            # Recognise Terraform submissions: any AWS resource type, 'terraform' keyword,
            # or a known fix_type in the combined text
            type_matches = (
                any(f in combined for f in fix_types)
                or "terraform" in combined
                or "aws_" in resource_type   # AWS Terraform resource type prefix
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
                return (
                    f"✅ TERRAFORM VALIDATED & APPLIED\n"
                    f"Resource: {resource_type or 'aws_wafv2_web_acl'}\n"
                    f"Root cause resolved: {rc_id.replace('_', ' ')}\n"
                    f"WAF rule deployed and attached to api_gateway.\n"
                    f"Attack traffic from 203.0.113.0/24, 198.51.100.0/24, "
                    f"192.0.2.0/24 is now BLOCKED.\n"
                    f"Reward: +{reward:.2f}\n"
                    f"Next: verify(api_gateway) to confirm attack mitigated."
                ), reward

        # Didn't match — give feedback
        return (
            "⚠️  Terraform submitted but does not address a remaining root cause.\n"
            "Hints:\n"
            "  - Use resource type: aws_wafv2_web_acl + aws_wafv2_ip_set\n"
            "  - Include CIDRs: 203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24\n"
            "  - Set action: block\n"
            "Example config key: resource_type=aws_wafv2_web_acl, "
            "config='{ip_set_cidrs: [203.0.113.0/24, ...], action: block}'"
        ), -W_WRONG_FIX

    def _handle_apply_fix(
        self, target: str, fix_type: str, config_key: str, config_value: str
    ) -> Tuple[str, float]:
        correct_fixes = self._scenario.get("correct_fixes", {})

        for rc_id, fix_def in correct_fixes.items():
            if rc_id in self._fixes_applied:
                continue

            svc_target = fix_def["target"].replace("-", "_").replace(" ", "_")
            if target and target != svc_target and not any(
                t in target for t in svc_target.split("_")
            ):
                continue

            fix_types_lower = [f.lower() for f in fix_def["fix_types"]]
            config_keys_lower = [k.lower() for k in fix_def.get("config_keys", [])]

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

        situation = (
            f"=== STATUS — step {self._step_count}/{self._max_steps} ===\n"
            f"Task    : {self._task.upper()} — {self._scenario.get('title', '')}\n"
            f"Domain  : {self._scenario.get('domain', '')}\n"
            f"Services: {healthy}/{total} healthy | "
            f"Root causes: {rc_found}/{rc_total} resolved\n"
            f"Resolved: {'YES ✅' if self._all_resolved() else 'NO ⏳'}\n"
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
