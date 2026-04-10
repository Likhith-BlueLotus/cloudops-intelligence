"""
AIOps Incident Response Environment — core logic.

Simulates the on-call engineering workflow for three classes of real production
incidents. The agent acts as an on-call engineer who must:
  1. Read the initial alert and service health dashboard.
  2. Investigate root causes by querying logs and metrics.
  3. Apply targeted fixes.
  4. Verify that all services return to healthy status.

This is a purely text-based, step-based environment. There is no spatial grid,
no physics engine, and no game-like mechanics. Every scenario is drawn from
real-world production incident patterns documented in SRE literature.

Task difficulty:
  easy   — 1 root cause, 3 services, 15 steps
  medium — 2 root causes, 5 services, 25 steps
  hard   — 3 root causes, 7 services, 40 steps

Reward structure (all components are normalised to [0, 1]):
  +W_ROOT_CAUSE   fractional credit when a new root cause is identified
  +W_FIX_APPLIED  fractional credit when a correct fix is applied
  +W_VERIFY       credit when a fixed service passes a health check
  +completion_bonus  +0.20 when ALL root causes fixed and ALL services healthy
  -W_WRONG_FIX    penalty for applying a fix to the wrong service
  -W_REDUNDANT    small penalty for repeated identical investigations
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
W_ROOT_CAUSE     = 0.30   # per root cause correctly identified
W_FIX_APPLIED    = 0.30   # per correct fix applied
W_VERIFY         = 0.10   # per service health-check passed after fix
W_COMPLETION     = 0.20   # episode completion bonus (all fixed + all healthy)
W_WRONG_FIX      = 0.05   # penalty per wrong-target fix
W_REDUNDANT      = 0.02   # penalty per redundant action

# ---------------------------------------------------------------------------
# Incident scenario library
# Each scenario is fully self-contained: pre-defined log outputs, metric
# tables, correct fix sequences, and grading rubrics. No external services
# are called — the environment is a deterministic state machine.
# ---------------------------------------------------------------------------
SCENARIOS: Dict[str, dict] = {

    # ════════════════════════════════════════════════════════════════════════
    # EASY — Database Connection Pool Exhaustion
    # Pattern: high-volume event causes connection pool saturation on the
    # database; payment service degrades; fix is adjusting max_connections.
    # ════════════════════════════════════════════════════════════════════════
    "easy": {
        "title": "Payment Service Checkout Failures",
        "initial_alert": (
            "CRITICAL ALERT — Payment Service Degraded\n"
            "Time      : 2026-04-10 14:23:41 UTC\n"
            "Service   : payment-service (pod: payment-prod-7b4f2)\n"
            "Symptom   : HTTP 503 errors spiking — current error rate 47%\n"
            "User Impact: Checkout failures affecting ~1,200 users / minute\n"
            "SLA       : P1 — resolution required within 15 minutes\n"
            "Runbook   : https://wiki.internal/runbooks/payment-service\n"
        ),
        "services": {
            "payment_service": {
                "status": "degraded",
                "error_rate_pct": 47.0,
                "response_time_ms": 8400.0,
                "uptime_pct": 61.0,
                "logs": (
                    "[14:23:41] ERROR payment_service: Failed to acquire DB connection — "
                    "timeout after 30 000 ms\n"
                    "[14:23:41] ERROR payment_service: HikariPool-1 — Connection is not "
                    "available, request timed out after 30 000ms.\n"
                    "[14:23:40] ERROR payment_service: org.springframework.dao."
                    "DataAccessResourceFailureException: Unable to acquire JDBC Connection\n"
                    "[14:23:38] WARN  payment_service: HikariPool-1 connection pool at "
                    "90% capacity (9/10 connections in use)\n"
                    "[14:23:32] INFO  payment_service: Processing payment order #847291\n"
                    "[14:23:31] INFO  payment_service: Processing payment order #847290\n"
                    "[14:23:10] INFO  payment_service: Flash sale traffic spike detected "
                    "(3x normal load)\n"
                ),
            },
            "user_db": {
                "status": "degraded",
                "error_rate_pct": 0.0,
                "response_time_ms": 450.0,
                "uptime_pct": 99.9,
                "logs": (
                    "[14:23:41] INFO  mysql: Active connections: 10 / max_connections: 10 "
                    "— LIMIT REACHED\n"
                    "[14:23:40] INFO  mysql: Thread_connected: 10, Thread_running: 10, "
                    "Threads_waiting: 47\n"
                    "[14:23:35] INFO  mysql: Active connections: 8\n"
                    "[14:23:10] INFO  mysql: Incoming connection surge from "
                    "payment_service (flash sale)\n"
                    "[14:22:45] INFO  mysql: Query: SELECT * FROM transactions WHERE "
                    "user_id=? (2 ms)\n"
                ),
                "metrics": {
                    "connections": (
                        "user_db — Active Connections (last 10 min)\n"
                        "14:14  2 / 10\n"
                        "14:16  3 / 10\n"
                        "14:18  5 / 10\n"
                        "14:20  7 / 10\n"
                        "14:22  9 / 10   [WARN]\n"
                        "14:23 10 / 10   [CRITICAL — LIMIT REACHED — 47 queries waiting]\n"
                        "\nmax_connections config: 10 (set at last deployment 6 weeks ago)\n"
                    ),
                    "cpu": (
                        "user_db — CPU Utilisation\n"
                        "Current: 28%  |  P95 (1h): 31%  |  Threshold: 80%\n"
                        "Status: NORMAL\n"
                    ),
                    "memory": (
                        "user_db — Memory\n"
                        "Used: 4.2 GB / 8 GB (52%)  |  Status: NORMAL\n"
                    ),
                },
            },
            "redis_cache": {
                "status": "healthy",
                "error_rate_pct": 0.0,
                "response_time_ms": 1.8,
                "uptime_pct": 100.0,
                "logs": (
                    "[14:23:41] INFO  redis: GET session:user_847291 — HIT (0.1 ms)\n"
                    "[14:23:38] INFO  redis: Memory usage: 45% (2.1 GB / 4 GB)\n"
                    "[14:23:00] INFO  redis: Connected clients: 12  |  Status: OK\n"
                ),
                "metrics": {
                    "memory": (
                        "redis_cache — Memory\n"
                        "Used: 2.1 GB / 4 GB (52%)  |  Status: NORMAL\n"
                    ),
                    "connections": (
                        "redis_cache — Connections\n"
                        "Current: 12  |  Max: 10 000  |  Status: NORMAL\n"
                    ),
                },
            },
        },
        "root_causes": ["user_db_connection_pool_exhausted"],
        "correct_fixes": {
            "user_db_connection_pool_exhausted": {
                "target": "user_db",
                "affected_services": ["payment_service"],
                "fix_types": [
                    "adjust_config",
                    "increase_capacity",
                    "increase_connections",
                    "adjust_max_connections",
                ],
                "config_keys": ["max_connections", "pool_size", "connection_limit"],
            }
        },
        "verify_services": ["payment_service"],
        "post_fix_status": {
            "payment_service": {
                "status": "healthy",
                "error_rate_pct": 0.2,
                "response_time_ms": 95.0,
                "uptime_pct": 99.9,
            },
            "user_db": {
                "status": "healthy",
                "error_rate_pct": 0.0,
                "response_time_ms": 18.0,
                "uptime_pct": 100.0,
            },
        },
        "max_steps": 15,
        "difficulty": "easy",
    },

    # ════════════════════════════════════════════════════════════════════════
    # MEDIUM — Cache Stampede + Missing Index
    # Pattern: product catalog Redis cache TTL mis-set to 0 causes all keys
    # to expire immediately; simultaneously a missing DB index causes full
    # table scans as cold cache requests pile in.
    # ════════════════════════════════════════════════════════════════════════
    "medium": {
        "title": "Product Catalog Degradation — High Latency & Errors",
        "initial_alert": (
            "HIGH ALERT — Catalog & Search Services Degraded\n"
            "Time      : 2026-04-10 09:11:03 UTC\n"
            "Services  : catalog-service, search-service\n"
            "Symptom   : P95 response time > 8 s (SLA: 500 ms); error rate 22%\n"
            "User Impact: Product browsing broken for ~45 000 active users\n"
            "SLA       : P1 — resolution required within 25 minutes\n"
            "Runbook   : https://wiki.internal/runbooks/catalog-service\n"
        ),
        "services": {
            "catalog_service": {
                "status": "degraded",
                "error_rate_pct": 22.0,
                "response_time_ms": 8700.0,
                "uptime_pct": 78.0,
                "logs": (
                    "[09:11:02] ERROR catalog_service: Redis GET product:* — MISS "
                    "(100% miss rate over last 60 s)\n"
                    "[09:11:02] ERROR catalog_service: DB query timeout — "
                    "SELECT * FROM products WHERE category=? took > 8 000 ms\n"
                    "[09:10:58] WARN  catalog_service: Cache miss storm detected — "
                    "1 800 cache misses / sec (baseline: 12 / sec)\n"
                    "[09:10:55] WARN  catalog_service: Falling back to DB for all "
                    "product lookups (cache unavailable)\n"
                    "[09:10:50] INFO  catalog_service: Deployment v2.4.1 completed "
                    "(config change: cache_ttl updated)\n"
                ),
            },
            "search_service": {
                "status": "degraded",
                "error_rate_pct": 18.0,
                "response_time_ms": 6200.0,
                "uptime_pct": 82.0,
                "logs": (
                    "[09:11:02] ERROR search_service: Upstream catalog_service "
                    "returning 503 (timeout)\n"
                    "[09:10:58] WARN  search_service: Circuit breaker OPEN for "
                    "catalog_service (5 consecutive failures)\n"
                    "[09:10:52] INFO  search_service: Serving stale search index "
                    "(fallback mode active)\n"
                ),
            },
            "redis_cache": {
                "status": "degraded",
                "error_rate_pct": 0.0,
                "response_time_ms": 1.2,
                "uptime_pct": 100.0,
                "logs": (
                    "[09:11:02] WARN  redis: Key expiry rate: 1 847 / sec "
                    "(baseline: 12 / sec) — ALL product keys expiring immediately\n"
                    "[09:10:58] INFO  redis: Cache hit rate: 0.1% (baseline: 96%)\n"
                    "[09:10:50] INFO  redis: FLUSHDB executed for product namespace\n"
                    "[09:10:50] INFO  redis: SET product:config cache_ttl=0 "
                    "(deployment config push)\n"
                ),
                "metrics": {
                    "hit_rate": (
                        "redis_cache — Cache Hit Rate (last 15 min)\n"
                        "09:00  96.2%\n"
                        "09:05  95.8%\n"
                        "09:10  95.1%\n"
                        "09:10:50 [DEPLOY] cache_ttl set to 0\n"
                        "09:11   0.1%  [CRITICAL — cache_ttl=0 causes immediate expiry]\n"
                    ),
                    "memory": (
                        "redis_cache — Memory\n"
                        "Used: 0.2 GB / 8 GB (2.5%)  |  "
                        "NOTE: low memory due to immediate key expiry\n"
                    ),
                },
            },
            "product_db": {
                "status": "degraded",
                "error_rate_pct": 5.0,
                "response_time_ms": 9100.0,
                "uptime_pct": 94.0,
                "logs": (
                    "[09:11:02] ERROR mysql: Slow query: SELECT * FROM products "
                    "WHERE category=? — 8 947 ms (full table scan: 4.2M rows)\n"
                    "[09:11:00] WARN  mysql: CPU at 97% — query queue: 234 pending\n"
                    "[09:10:58] INFO  mysql: Missing index on products.category_id "
                    "— EXPLAIN shows type=ALL (full scan)\n"
                    "[09:10:50] INFO  mysql: Deployment migration ran: "
                    "ALTER TABLE products DROP INDEX idx_category (migration v2.4.1)\n"
                ),
                "metrics": {
                    "cpu": (
                        "product_db — CPU Utilisation\n"
                        "09:05   22%\n"
                        "09:10   28%\n"
                        "09:10:50 [DEPLOY — index dropped]\n"
                        "09:11   97%  [CRITICAL]\n"
                    ),
                    "slow_queries": (
                        "product_db — Slow Queries (> 1 000 ms)\n"
                        "09:05  0 / min\n"
                        "09:11  234 / min  [CRITICAL]\n"
                        "Top query: SELECT * FROM products WHERE category_id=? "
                        "(no index — full table scan 4.2 M rows)\n"
                    ),
                    "connections": (
                        "product_db — Connections\n"
                        "Current: 189 / 200 (94%)  |  Status: WARNING\n"
                    ),
                },
            },
            "api_gateway": {
                "status": "healthy",
                "error_rate_pct": 0.3,
                "response_time_ms": 12.0,
                "uptime_pct": 99.9,
                "logs": (
                    "[09:11:02] INFO  api_gateway: Routing /api/catalog → "
                    "catalog_service (upstream degraded)\n"
                    "[09:11:00] WARN  api_gateway: Upstream catalog_service "
                    "timeout rate: 22%\n"
                ),
            },
        },
        "root_causes": [
            "redis_cache_ttl_zero",
            "product_db_missing_index",
        ],
        "correct_fixes": {
            "redis_cache_ttl_zero": {
                "target": "redis_cache",
                "affected_services": ["catalog_service", "search_service"],
                "fix_types": [
                    "adjust_config",
                    "fix_ttl",
                    "set_cache_ttl",
                    "rollback",
                    "adjust_ttl",
                ],
                "config_keys": ["cache_ttl", "ttl", "key_ttl"],
            },
            "product_db_missing_index": {
                "target": "product_db",
                "affected_services": ["catalog_service"],
                "fix_types": [
                    "adjust_config",
                    "create_index",
                    "add_index",
                    "rebuild_index",
                    "rollback",
                    "fix_index",
                ],
                "config_keys": ["index_category_id", "idx_category", "category_index"],
            },
        },
        "verify_services": ["catalog_service", "search_service"],
        "post_fix_status": {
            "catalog_service": {
                "status": "healthy",
                "error_rate_pct": 0.1,
                "response_time_ms": 120.0,
                "uptime_pct": 99.9,
            },
            "search_service": {
                "status": "healthy",
                "error_rate_pct": 0.0,
                "response_time_ms": 85.0,
                "uptime_pct": 99.9,
            },
            "redis_cache": {
                "status": "healthy",
                "error_rate_pct": 0.0,
                "response_time_ms": 1.2,
                "uptime_pct": 100.0,
            },
            "product_db": {
                "status": "healthy",
                "error_rate_pct": 0.0,
                "response_time_ms": 8.0,
                "uptime_pct": 100.0,
            },
        },
        "max_steps": 25,
        "difficulty": "medium",
    },

    # ════════════════════════════════════════════════════════════════════════
    # HARD — Multi-Root-Cause Cascade
    # Pattern: three independent failures cascade:
    #   1. Message queue disk full → order events silently dropped
    #   2. Order service OOM (memory leak in v3.1.0) → repeated crash-loops
    #   3. Inventory DB deadlock (concurrent LOCK TABLE from reporting job)
    # Must identify all 3 and fix in dependency order.
    # ════════════════════════════════════════════════════════════════════════
    "hard": {
        "title": "Order Processing System — Multi-Service P0 Incident",
        "initial_alert": (
            "P0 INCIDENT — Order Processing System Down\n"
            "Time      : 2026-04-10 03:47:22 UTC\n"
            "Services  : order-service, inventory-service, notification-service\n"
            "Symptom   : Orders not processing; inventory desync; notifications "
            "undelivered\n"
            "User Impact: CRITICAL — ~8 200 orders stuck; revenue loss $420 / min\n"
            "SLA       : P0 — immediate response required\n"
            "Runbook   : https://wiki.internal/runbooks/order-processing\n"
        ),
        "services": {
            "order_service": {
                "status": "down",
                "error_rate_pct": 100.0,
                "response_time_ms": 0.0,
                "uptime_pct": 12.0,
                "logs": (
                    "[03:47:20] FATAL order_service: Out of memory — "
                    "Container killed by OOM killer (RSS: 4 096 MB / limit: 4 096 MB)\n"
                    "[03:47:18] ERROR order_service: java.lang.OutOfMemoryError: "
                    "Java heap space\n"
                    "[03:47:15] WARN  order_service: Heap usage at 98% (4 014 MB / "
                    "4 096 MB) — GC overhead limit exceeded\n"
                    "[03:46:50] WARN  order_service: Heap growing abnormally — "
                    "possible memory leak in ProductCacheManager (v3.1.0 introduced "
                    "static cache with no eviction)\n"
                    "[03:44:00] INFO  order_service: Deployment v3.1.0 completed "
                    "(feature: product recommendation caching)\n"
                    "[03:47:22] INFO  k8s: CrashLoopBackOff — pod order-prod-9f3a1 "
                    "restarted 14 times in last 30 min\n"
                ),
                "metrics": {
                    "memory": (
                        "order_service — JVM Heap Memory\n"
                        "03:40  1.2 GB / 4 GB (30%)\n"
                        "03:42  1.9 GB / 4 GB (47%)\n"
                        "03:44  2.8 GB / 4 GB (70%)  [DEPLOY v3.1.0]\n"
                        "03:45  3.5 GB / 4 GB (87%)\n"
                        "03:46  3.9 GB / 4 GB (97%)  [CRITICAL]\n"
                        "03:47  OOM kill\n"
                        "\nNOTE: Heap growth rate +400 MB/min — abnormal "
                        "(baseline: +5 MB/min). Leak correlates with v3.1.0 "
                        "ProductCacheManager (unbounded static cache).\n"
                    ),
                    "cpu": (
                        "order_service — CPU\n"
                        "Current: 0% (pod crashed)  |  Pre-crash P95: 89%\n"
                        "GC overhead pre-crash: 94% of CPU time\n"
                    ),
                    "restarts": (
                        "order_service — Pod Restarts\n"
                        "Last 30 min: 14 restarts (CrashLoopBackOff)\n"
                        "First restart: 03:44:12 (2 min after v3.1.0 deploy)\n"
                    ),
                },
            },
            "message_queue": {
                "status": "down",
                "error_rate_pct": 100.0,
                "response_time_ms": 0.0,
                "uptime_pct": 0.0,
                "logs": (
                    "[03:47:20] FATAL rabbitmq: Disk alarm triggered — "
                    "disk_free: 0 bytes (limit: 50 MB) — all producers BLOCKED\n"
                    "[03:47:18] ERROR rabbitmq: Message queue blocked — "
                    "no disk space to persist messages\n"
                    "[03:46:00] WARN  rabbitmq: Disk space critical — "
                    "1.2 GB remaining (2% of 60 GB)\n"
                    "[03:40:00] WARN  rabbitmq: Disk space low — "
                    "5 GB remaining (8% of 60 GB)\n"
                    "[03:00:00] INFO  rabbitmq: Dead letter queue growing: "
                    "dlq.orders — 8 247 unacknowledged messages (retention: 7 days)\n"
                    "[02:00:00] INFO  rabbitmq: 7-day message retention filled "
                    "60 GB disk — no automatic cleanup configured\n"
                ),
                "metrics": {
                    "disk": (
                        "message_queue — Disk Usage\n"
                        "02:00  58 GB / 60 GB (97%)  [Retention filled disk]\n"
                        "03:40  59 GB / 60 GB (98%)  [WARN]\n"
                        "03:46  59.9 GB / 60 GB (99.8%)  [CRITICAL]\n"
                        "03:47  60 GB / 60 GB (100%)  [ALARM — producers blocked]\n"
                        "\nRoot cause: 7-day message retention policy filled "
                        "the entire 60 GB disk. No cleanup/TTL configured.\n"
                    ),
                    "messages": (
                        "message_queue — Queue Depth\n"
                        "orders.created  : 8 247 unacked (blocked)\n"
                        "orders.fulfilled: 0 (consumers down)\n"
                        "dlq.orders      : 8 247 messages\n"
                    ),
                },
            },
            "inventory_service": {
                "status": "degraded",
                "error_rate_pct": 67.0,
                "response_time_ms": 15800.0,
                "uptime_pct": 33.0,
                "logs": (
                    "[03:47:20] ERROR inventory_service: "
                    "com.mysql.jdbc.exceptions.jdbc4.MySQLTransactionRollbackException: "
                    "Deadlock found when trying to get lock; try restarting transaction\n"
                    "[03:47:18] ERROR inventory_service: Transaction deadlock on "
                    "inventory table — victim selected, rolled back\n"
                    "[03:47:00] WARN  inventory_service: Lock wait timeout exceeded "
                    "(innodb_lock_wait_timeout=50s) on inventory.stock table\n"
                    "[03:45:00] INFO  reporting_job: Running nightly inventory audit — "
                    "LOCK TABLES inventory.stock WRITE (will hold for ~30 min)\n"
                    "[03:44:55] INFO  inventory_service: Attempting to UPDATE "
                    "inventory.stock — waiting for table lock\n"
                ),
                "metrics": {
                    "lock_wait": (
                        "inventory_service — InnoDB Lock Waits\n"
                        "03:44  0 / min\n"
                        "03:45  3 / min  [reporting_job acquired LOCK TABLES]\n"
                        "03:46  28 / min  [WARN]\n"
                        "03:47  67 / min  [CRITICAL — deadlock storm]\n"
                        "\nBlocking query: reporting_job holding LOCK TABLES "
                        "inventory.stock WRITE since 03:45:00 (12 min)\n"
                    ),
                    "cpu": (
                        "inventory_service — CPU\n"
                        "Current: 8%  |  P95 (1h): 62%  |  Status: LOW (blocked on locks)\n"
                    ),
                },
            },
            "notification_service": {
                "status": "degraded",
                "error_rate_pct": 100.0,
                "response_time_ms": 0.0,
                "uptime_pct": 0.0,
                "logs": (
                    "[03:47:20] ERROR notification_service: Failed to consume from "
                    "message_queue — broker connection refused (queue blocked)\n"
                    "[03:47:18] ERROR notification_service: RabbitMQ connection "
                    "timeout — retrying (attempt 24/∞)\n"
                    "[03:47:00] WARN  notification_service: 0 notifications sent "
                    "in last 10 min (baseline: ~500 / min)\n"
                ),
            },
            "checkout_service": {
                "status": "degraded",
                "error_rate_pct": 83.0,
                "response_time_ms": 32000.0,
                "uptime_pct": 17.0,
                "logs": (
                    "[03:47:20] ERROR checkout_service: order_service unavailable "
                    "(CrashLoopBackOff)\n"
                    "[03:47:18] ERROR checkout_service: Failed to reserve inventory — "
                    "inventory_service timeout (15 800 ms)\n"
                    "[03:47:10] ERROR checkout_service: Payment processed but order "
                    "creation failed — requires manual reconciliation\n"
                ),
            },
            "payment_service": {
                "status": "healthy",
                "error_rate_pct": 0.2,
                "response_time_ms": 110.0,
                "uptime_pct": 99.8,
                "logs": (
                    "[03:47:20] INFO  payment_service: Transaction processed "
                    "successfully (order creation downstream failed)\n"
                    "[03:47:18] INFO  payment_service: Health check OK\n"
                ),
            },
            "api_gateway": {
                "status": "degraded",
                "error_rate_pct": 42.0,
                "response_time_ms": 28000.0,
                "uptime_pct": 58.0,
                "logs": (
                    "[03:47:20] ERROR api_gateway: Upstream checkout_service "
                    "timeout — returning 504\n"
                    "[03:47:15] WARN  api_gateway: Circuit breaker OPEN for "
                    "checkout_service\n"
                ),
            },
        },
        "root_causes": [
            "message_queue_disk_full",
            "order_service_memory_leak",
            "inventory_db_deadlock",
        ],
        "correct_fixes": {
            "message_queue_disk_full": {
                "target": "message_queue",
                "affected_services": ["notification_service"],
                "fix_types": [
                    "clear_queue",
                    "purge_messages",
                    "increase_capacity",
                    "free_disk",
                    "adjust_config",
                    "clear_dlq",
                ],
                "config_keys": [
                    "message_ttl",
                    "retention_days",
                    "disk_free_limit",
                    "max_disk",
                ],
            },
            "order_service_memory_leak": {
                "target": "order_service",
                "affected_services": ["checkout_service"],
                "fix_types": [
                    "rollback",
                    "restart_service",
                    "adjust_config",
                    "fix_memory_leak",
                    "revert_deployment",
                ],
                "config_keys": [
                    "deployment_version",
                    "heap_size",
                    "cache_eviction",
                    "version",
                ],
            },
            "inventory_db_deadlock": {
                "target": "inventory_service",
                "affected_services": [],
                "fix_types": [
                    "kill_query",
                    "stop_reporting_job",
                    "adjust_config",
                    "fix_deadlock",
                    "restart_service",
                ],
                "config_keys": [
                    "lock_timeout",
                    "reporting_job",
                    "innodb_lock_wait_timeout",
                    "table_lock",
                ],
            },
        },
        "verify_services": ["order_service", "message_queue", "inventory_service"],
        "post_fix_status": {
            "order_service": {
                "status": "healthy",
                "error_rate_pct": 0.3,
                "response_time_ms": 145.0,
                "uptime_pct": 99.8,
            },
            "message_queue": {
                "status": "healthy",
                "error_rate_pct": 0.0,
                "response_time_ms": 2.1,
                "uptime_pct": 100.0,
            },
            "inventory_service": {
                "status": "healthy",
                "error_rate_pct": 0.1,
                "response_time_ms": 85.0,
                "uptime_pct": 99.9,
            },
            "notification_service": {
                "status": "healthy",
                "error_rate_pct": 0.0,
                "response_time_ms": 55.0,
                "uptime_pct": 100.0,
            },
            "checkout_service": {
                "status": "healthy",
                "error_rate_pct": 0.2,
                "response_time_ms": 320.0,
                "uptime_pct": 99.9,
            },
        },
        "max_steps": 40,
        "difficulty": "hard",
    },
}


# ---------------------------------------------------------------------------
# Available actions reminder (shown in every observation)
# ---------------------------------------------------------------------------
AVAILABLE_ACTIONS = [
    "view_logs",
    "view_metrics",
    "apply_fix",
    "verify",
    "escalate",
]


class IncidentResponseEnvironment(Environment):
    """
    OpenEnv Environment for AIOps Incident Response.

    The agent plays the role of an on-call engineer. Each episode presents
    a realistic production incident with one or more root causes. The agent
    must investigate (via logs/metrics), apply the correct fix(es), and
    verify service recovery — all within a step budget.

    Thread-safe: all mutable state is instance-level; no global shared state.
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
        self._queries_seen: List[str] = []  # for redundancy detection
        self._step_count: int = 0
        self._max_steps: int = 15
        self._cumulative_reward: float = 0.0
        self._episode_id: str = ""
        self._done: bool = False
        self._escalated: bool = False

    # ── OpenEnv interface ─────────────────────────────────────────────────

    def reset(self, seed: int = 42, task: str = "easy") -> IncidentObservation:  # type: ignore[override]
        """Initialise a fresh episode for the given task difficulty."""
        if task not in SCENARIOS:
            task = "medium"  # safe fallback

        self._task = task
        self._scenario = SCENARIOS[task]
        self._services = {
            name: dict(data)
            for name, data in self._scenario["services"].items()
        }
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
                + "\nBegin investigation. Use view_logs and view_metrics to "
                "identify root causes, then apply_fix to remediate."
            ),
            reward=0.0,
        )

    def step(self, action: IncidentAction) -> IncidentObservation:  # type: ignore[override]
        if self._done:
            return self._make_observation(
                action_output="Episode already complete. Call reset() to start a new episode.",
                reward=0.0,
            )

        self._step_count += 1
        action_type = (action.action_type or "").lower().strip()
        target = (action.target or "").lower().strip()
        params = action.parameters or {}

        reward = 0.0
        output = ""

        if action_type == "view_logs":
            output, reward = self._handle_view_logs(target)

        elif action_type == "view_metrics":
            metric = (params.get("metric") or params.get("name") or "").lower().strip()
            output, reward = self._handle_view_metrics(target, metric)

        elif action_type == "apply_fix":
            fix_type = (
                params.get("fix_type") or params.get("action") or ""
            ).lower().strip()
            config_key = (params.get("config_key") or params.get("key") or "").lower().strip()
            config_value = params.get("config_value") or params.get("value") or ""
            output, reward = self._handle_apply_fix(target, fix_type, config_key, config_value)

        elif action_type == "verify":
            output, reward = self._handle_verify(target)

        elif action_type == "escalate":
            output, reward = self._handle_escalate()

        else:
            output = (
                f"Unknown action_type '{action_type}'. "
                f"Valid types: {AVAILABLE_ACTIONS}"
            )
            reward = 0.0

        self._actions_log.append(
            f"step={self._step_count} type={action_type} "
            f"target={target} reward={reward:.4f}"
        )
        self._cumulative_reward += reward

        # Check episode termination
        if self._escalated:
            self._done = True
        elif self._step_count >= self._max_steps:
            self._done = True
            output += (
                "\n\n⏰ STEP BUDGET EXHAUSTED — Incident automatically escalated. "
                "Ensure all root causes are fixed before step limit."
            )
        elif self._all_resolved():
            self._done = True
            output += (
                "\n\n✅ ALL SERVICES HEALTHY — Incident resolved successfully. "
                "Post-mortem scheduled for next business day."
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
            services_status={
                name: svc["status"] for name, svc in self._services.items()
            },
            resolved=self._all_resolved(),
            escalated=self._escalated,
            cumulative_reward=round(self._cumulative_reward, 4),
        )

    # ── Action handlers ───────────────────────────────────────────────────

    def _handle_view_logs(self, target: str) -> Tuple[str, float]:
        query_key = f"logs:{target}"
        if target not in self._services:
            return (
                f"Service '{target}' not found. "
                f"Available: {list(self._services.keys())}",
                0.0,
            )

        reward = 0.0
        if query_key in self._queries_seen:
            reward = -W_REDUNDANT
            suffix = "\n[Repeated query — no new information available]"
        else:
            self._queries_seen.append(query_key)
            suffix = ""

        svc = self._services[target]
        logs = svc.get("logs", f"[No log data available for {target}]")
        output = f"=== LOGS: {target} ===\n{logs}{suffix}"
        return output, reward

    def _handle_view_metrics(self, target: str, metric: str) -> Tuple[str, float]:
        if target not in self._services:
            return (
                f"Service '{target}' not found. "
                f"Available: {list(self._services.keys())}",
                0.0,
            )

        svc = self._services[target]
        metrics = svc.get("metrics", {})

        if not metric:
            available = list(metrics.keys()) if metrics else ["cpu", "memory", "connections"]
            return (
                f"Specify a metric. Available for {target}: {available}",
                0.0,
            )

        query_key = f"metrics:{target}:{metric}"
        reward = 0.0
        if query_key in self._queries_seen:
            reward = -W_REDUNDANT
            suffix = "\n[Repeated metric query — no new information]"
        else:
            self._queries_seen.append(query_key)
            suffix = ""

        # Fuzzy metric lookup
        matched_key = None
        for k in metrics:
            if metric in k or k in metric:
                matched_key = k
                break

        if matched_key:
            output = f"=== METRICS: {target} / {matched_key} ===\n{metrics[matched_key]}{suffix}"
        else:
            output = (
                f"Metric '{metric}' not found for {target}. "
                f"Available: {list(metrics.keys())}"
            )

        return output, reward

    def _handle_apply_fix(
        self, target: str, fix_type: str, config_key: str, config_value: str
    ) -> Tuple[str, float]:
        if target not in self._services:
            return (
                f"Service '{target}' not found. "
                f"Available: {list(self._services.keys())}",
                -W_WRONG_FIX,
            )

        correct_fixes = self._scenario["correct_fixes"]
        reward = 0.0
        output = ""

        for rc_id, fix_def in correct_fixes.items():
            if rc_id in self._fixes_applied:
                continue  # already fixed

            # Check if this fix targets the correct service
            if target != fix_def["target"]:
                continue

            # Check if fix_type matches (with fuzzy matching)
            fix_matches = any(
                ft in fix_type or fix_type in ft
                for ft in fix_def["fix_types"]
            )
            # Also accept if config_key matches a known key
            config_matches = any(
                ck in config_key or config_key in ck
                for ck in fix_def.get("config_keys", [])
            ) if config_key else False

            if fix_matches or config_matches:
                # Correct fix applied — record it, but wait for explicit verify
                # to update service statuses (so the agent gets verify credit)
                self._fixes_applied.append(rc_id)
                if rc_id not in self._root_causes_identified:
                    self._root_causes_identified.append(rc_id)

                self._services_fixed.append(target)
                reward = W_ROOT_CAUSE + W_FIX_APPLIED

                fix_description = (
                    f"adjust {config_key}={config_value}" if config_key
                    else f"{fix_type}"
                )
                output = (
                    f"✅ FIX APPLIED: {fix_description} on {target}\n"
                    f"Root cause identified: {rc_id.replace('_', ' ')}\n"
                    f"Service status will update once you verify health.\n"
                    f"Reward: +{reward:.2f} (root cause credit + fix credit)\n"
                    f"\nNext: use verify({target!r}) to confirm the fix worked."
                )
                return output, reward

        # Fix applied to wrong service or wrong type
        already_fixed_ids = [
            rc for rc in correct_fixes if rc in self._fixes_applied
        ]
        remaining = [
            rc for rc in correct_fixes if rc not in self._fixes_applied
        ]
        output = (
            f"⚠️  Fix '{fix_type}' on '{target}' did not address any remaining "
            f"root cause.\n"
            f"Remaining root causes to find: {len(remaining)}\n"
            f"Hint: continue investigating logs/metrics to identify what needs fixing."
        )
        return output, -W_WRONG_FIX

    def _handle_verify(self, target: str) -> Tuple[str, float]:
        if target not in self._services:
            return (
                f"Service '{target}' not found. "
                f"Available: {list(self._services.keys())}",
                0.0,
            )

        svc = self._services[target]
        reward = 0.0
        verify_key = f"verify:{target}"

        # Check whether a fixed root cause directly targets or affects this service.
        post_fix = self._scenario.get("post_fix_status", {})
        cause_was_fixed = any(
            rc_id in self._fixes_applied
            and (
                self._scenario["correct_fixes"][rc_id]["target"] == target
                or target in self._scenario["correct_fixes"][rc_id].get("affected_services", [])
            )
            for rc_id in self._scenario["correct_fixes"]
        )

        if cause_was_fixed and target in post_fix:
            svc.update(post_fix[target])

        status = svc.get("status", "unknown")

        if status == "healthy":
            if verify_key not in self._queries_seen:
                reward = W_VERIFY
                self._queries_seen.append(verify_key)

            output = (
                f"✅ HEALTH CHECK: {target}\n"
                f"Status         : HEALTHY\n"
                f"Error rate     : {svc['error_rate_pct']:.1f}%\n"
                f"Response time  : {svc['response_time_ms']:.0f} ms\n"
                f"Uptime         : {svc['uptime_pct']:.1f}%\n"
                f"Verdict        : Service is operating normally."
            )
            if reward > 0:
                output += f"\nReward: +{reward:.2f} (verification credit)"
        else:
            output = (
                f"⚠️  HEALTH CHECK: {target}\n"
                f"Status         : {status.upper()}\n"
                f"Error rate     : {svc['error_rate_pct']:.1f}%\n"
                f"Response time  : {svc['response_time_ms']:.0f} ms\n"
                f"Uptime         : {svc['uptime_pct']:.1f}%\n"
                f"Verdict        : Service still degraded — apply correct fix first."
            )

        return output, reward

    def _handle_escalate(self) -> Tuple[str, float]:
        self._escalated = True
        fixed = len(self._fixes_applied)
        total = len(self._scenario["root_causes"])
        partial_score = fixed / max(1, total) * 0.5
        output = (
            f"📞 ESCALATED to senior on-call engineer.\n"
            f"Root causes fixed before escalation: {fixed} / {total}\n"
            f"Partial credit awarded: {partial_score:.2f}\n"
            "Episode ended."
        )
        return output, partial_score

    # ── Helpers ───────────────────────────────────────────────────────────

    def _all_resolved(self) -> bool:
        """True when every root cause is fixed and all verify_services are healthy."""
        root_causes = set(self._scenario["root_causes"])
        if not root_causes.issubset(set(self._fixes_applied)):
            return False
        verify_svcs = self._scenario.get("verify_services", [])
        return all(
            self._services.get(s, {}).get("status") == "healthy"
            for s in verify_svcs
        )

    def _make_observation(self, action_output: str, reward: float) -> IncidentObservation:
        healthy = sum(
            1 for s in self._services.values() if s.get("status") == "healthy"
        )
        total = len(self._services)
        rc_found = len(self._root_causes_identified)
        rc_total = len(self._scenario.get("root_causes", []))

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

        # Completion bonus
        if self._all_resolved():
            reward = max(reward, W_COMPLETION)

        # Clip to [0, 1] for the observation field (OpenEnv spec).
        # Penalties contribute to cumulative_reward but are not surfaced as
        # negative reward values in the observation to keep the reward field
        # compliant with the [0, 1] range requirement.
        clipped_reward = float(min(1.0, max(0.0, reward)))

        situation = self._build_situation_report(healthy, total, rc_found, rc_total)

        return IncidentObservation(
            situation_report=situation,
            services=services_list,
            action_output=action_output,
            available_actions=AVAILABLE_ACTIONS,
            services_healthy=healthy,
            services_total=total,
            root_causes_found=rc_found,
            root_causes_total=rc_total,
            reward=clipped_reward,
            done=self._done,
        )

    def _build_situation_report(
        self, healthy: int, total: int, rc_found: int, rc_total: int
    ) -> str:
        degraded = [
            name
            for name, svc in self._services.items()
            if svc.get("status") != "healthy"
        ]
        degraded_str = ", ".join(degraded) if degraded else "none"
        return (
            f"=== INCIDENT STATUS — step {self._step_count}/{self._max_steps} ===\n"
            f"Task         : {self._task.upper()} — "
            f"{self._scenario.get('title', '')}\n"
            f"Services     : {healthy}/{total} healthy "
            f"(degraded: {degraded_str})\n"
            f"Root causes  : {rc_found}/{rc_total} identified and fixed\n"
            f"Steps used   : {self._step_count}/{self._max_steps}\n"
            f"Resolved     : {'YES ✅' if self._all_resolved() else 'NO ⏳'}\n"
        )
