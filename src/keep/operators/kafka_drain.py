"""Deletion proof: deny the gateway, drain bounded requests, then cross Kafka offsets.

This table records an operation proof, never an alert dispatch queue. Kafka
retention gaps or missing bindings leave deletion pending rather than fabricate
an empty backlog. The 15-second barrier includes the ten-second gateway context,
one outstanding 1.1-second produce, and two seconds of clock uncertainty.
"""

import json
import time
from datetime import timedelta

from psycopg.types.json import Jsonb

from keep.shared.errors import unavailable


def require_drain(db, settings, work, check, *, consumer_factory=None, deadline=None):
    if db is None or settings is None or not settings.kafka_bootstrap:
        raise unavailable("operator_kafka_drain_unverified")
    document = json.loads(work.policy_document)
    if document.get("enabled") is not False:
        raise unavailable("operator_kafka_drain_unverified")
    from keep.clock_health import require_clock_health

    require_clock_health(settings)
    check()
    with db.transaction(work.tenant_id) as conn:
        control = conn.execute("SELECT * FROM kafka_pipeline_control WHERE singleton").fetchone()
        if not control or not control["enabled"] or not control["received_partitions"]:
            raise unavailable("operator_kafka_drain_unverified")
        proof = conn.execute(
            """INSERT INTO operator_kafka_drains(operator_id,policy_generation,denied_at)
            VALUES(%s,%s,clock_timestamp()) ON CONFLICT(operator_id) DO UPDATE SET
            policy_generation=EXCLUDED.policy_generation,
            denied_at=CASE WHEN operator_kafka_drains.policy_generation=EXCLUDED.policy_generation
                THEN operator_kafka_drains.denied_at ELSE EXCLUDED.denied_at END,
            offsets=CASE WHEN operator_kafka_drains.policy_generation=EXCLUDED.policy_generation
                THEN operator_kafka_drains.offsets ELSE NULL END RETURNING *""",
            (work.operator_id, work.policy_generation),
        ).fetchone()
        now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
    # Commit the denial observation before yielding. The next attempt proves the
    # same immutable generation again; it must not restart this elapsed window.
    if now < proof["denied_at"] + timedelta(seconds=15):
        raise unavailable("operator_kafka_drain_pending")

    from confluent_kafka import Consumer, TopicPartition
    from keep.service_clients import kafka_options

    deadline = deadline or time.monotonic() + 20

    def timeout():
        remaining = deadline - time.monotonic()
        if remaining <= 0.1:
            raise unavailable("operator_kafka_drain_pending")
        return min(3, remaining)

    consumer = (consumer_factory or Consumer)(
        {
            **kafka_options(settings),
            "group.id": f"keep.{settings.environment}.source-v2",
            "enable.auto.commit": False,
            "enable.auto.offset.store": False,
            "isolation.level": "read_committed",
        }
    )
    topic = f"keep.{settings.environment}.alerts.received"
    try:
        metadata = consumer.list_topics(topic, timeout=timeout()).topics.get(topic)
        if (
            metadata is None
            or metadata.error
            or len(metadata.partitions) != control["received_partitions"]
        ):
            raise unavailable("operator_kafka_drain_unverified")
        partitions = [TopicPartition(topic, n) for n in sorted(metadata.partitions)]
        watermarks = {
            p.partition: consumer.get_watermark_offsets(p, timeout=timeout()) for p in partitions
        }
        offsets = proof["offsets"]
        if offsets is None:
            offsets = {
                "topic": topic,
                "partitions": {str(n): high for n, (_, high) in watermarks.items()},
            }
            check()
            with db.transaction(work.tenant_id) as conn:
                conn.execute(
                    "UPDATE operator_kafka_drains SET offsets=%s WHERE operator_id=%s AND policy_generation=%s AND offsets IS NULL",
                    (Jsonb(offsets), work.operator_id, work.policy_generation),
                )
        if offsets.get("topic") != topic or set(offsets.get("partitions", {})) != {
            str(p.partition) for p in partitions
        }:
            raise unavailable("operator_kafka_drain_unverified")
        committed = consumer.committed(partitions, timeout=timeout())
        if len(committed) != len(partitions) or {p.partition for p in committed} != set(watermarks):
            raise unavailable("operator_kafka_drain_unverified")
        for partition in committed:
            low, _ = watermarks[partition.partition]
            position = partition.offset if partition.offset >= 0 else 0
            if partition.error or position < low:
                raise unavailable("operator_kafka_drain_unverified")
            if position < offsets["partitions"][str(partition.partition)]:
                raise unavailable("operator_kafka_drain_pending")
        check()
        with db.transaction(work.tenant_id) as conn:
            if conn.execute(
                "SELECT 1 FROM kafka_pipeline_faults WHERE consumer='source' AND topic=%s AND reason='retention_gap' LIMIT 1",
                (topic,),
            ).fetchone():
                raise unavailable("operator_kafka_drain_unverified")
    finally:
        consumer.close()
