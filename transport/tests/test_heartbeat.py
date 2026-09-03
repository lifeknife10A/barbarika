import base64
import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

from heartbeat import (
    HeartbeatGenerator,
    HeartbeatPayload,
    HeartbeatValidationError,
    HeartbeatWatchdog,
    TelemetryLossAssessment,
    TelemetryLossDisposition,
    WatchdogState,
)


TRANSPORT_DIR = Path(__file__).resolve().parents[1]


def valid_payload() -> dict[str, object]:
    return {
        "agent_id": "primary-srv-01",
        "boot_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
        "sequence": 1842,
        "sent_at_utc": "2026-08-19T10:14:05Z",
        "last_event_sequence": 931,
        "last_event_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "agent_health": "healthy",
        "signature": base64.b64encode(b"s" * 64).decode("ascii"),
    }


class HeartbeatPayloadTests(unittest.TestCase):
    def test_valid_payload_round_trips(self) -> None:
        parsed = HeartbeatPayload.from_mapping(valid_payload())
        self.assertEqual(parsed.to_mapping(), valid_payload())

    def test_json_schema_fields_match_python_payload_fields(self) -> None:
        schema = json.loads((TRANSPORT_DIR / "heartbeat.schema.json").read_text())
        self.assertEqual(set(schema["required"]), HeartbeatPayload.FIELD_NAMES)
        self.assertEqual(set(schema["properties"]), HeartbeatPayload.FIELD_NAMES)
        self.assertFalse(schema["additionalProperties"])

    def test_missing_and_unexpected_fields_are_rejected(self) -> None:
        payload = valid_payload()
        del payload["sequence"]
        payload["extra"] = "not allowed"
        with self.assertRaisesRegex(HeartbeatValidationError, "missing=.*sequence"):
            HeartbeatPayload.from_mapping(payload)

    def test_invalid_signature_length_is_rejected(self) -> None:
        payload = valid_payload()
        payload["signature"] = base64.b64encode(b"short").decode("ascii")
        with self.assertRaisesRegex(HeartbeatValidationError, "64-byte Ed25519"):
            HeartbeatPayload.from_mapping(payload)

    def test_non_utc_timestamp_is_rejected(self) -> None:
        payload = valid_payload()
        payload["sent_at_utc"] = "2026-08-19T15:44:05+05:30"
        with self.assertRaisesRegex(HeartbeatValidationError, "ending in Z"):
            HeartbeatPayload.from_mapping(payload)

    def test_boolean_sequence_is_rejected(self) -> None:
        payload = valid_payload()
        payload["sequence"] = True
        with self.assertRaisesRegex(HeartbeatValidationError, "non-negative integer"):
            HeartbeatPayload.from_mapping(payload)

    def test_generator_signs_canonical_payload_and_increments_sequence(self) -> None:
        signing_preimages: list[bytes] = []

        def signer(preimage: bytes) -> bytes:
            signing_preimages.append(preimage)
            return b"x" * 64

        generator = HeartbeatGenerator(
            agent_id="primary-srv-01",
            boot_id=UUID("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"),
            signer=signer,
            next_sequence=7,
        )
        first = generator.generate(
            sent_at_utc=datetime(2026, 8, 19, 10, 14, 5, tzinfo=timezone.utc),
            last_event_sequence=931,
            last_event_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        second = generator.generate(
            sent_at_utc=datetime(2026, 8, 19, 10, 14, 10, tzinfo=timezone.utc),
            last_event_sequence=932,
            last_event_hash="0" * 64,
        )

        self.assertEqual((first.sequence, second.sequence), (7, 8))
        self.assertEqual(generator.next_sequence, 9)
        self.assertEqual(base64.b64decode(first.signature), b"x" * 64)
        self.assertEqual(signing_preimages[0], first.signing_bytes())
        self.assertNotIn(b'"signature"', signing_preimages[0])
        self.assertTrue(signing_preimages[0].startswith(b'{"agent_health":'))

    def test_generator_rejects_invalid_signer_output_without_advancing(self) -> None:
        generator = HeartbeatGenerator(
            agent_id="primary-srv-01",
            boot_id=UUID("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"),
            signer=lambda _: b"short",
        )
        with self.assertRaisesRegex(HeartbeatValidationError, "signer must return"):
            generator.generate(
                sent_at_utc=datetime(2026, 8, 19, 10, 14, 5, tzinfo=timezone.utc),
                last_event_sequence=0,
                last_event_hash="0" * 64,
            )
        self.assertEqual(generator.next_sequence, 0)


class HeartbeatWatchdogTests(unittest.TestCase):
    def test_transitions_after_exactly_three_missed_five_second_heartbeats(self) -> None:
        watchdog = HeartbeatWatchdog()
        watchdog.start(100.0)

        self.assertEqual(watchdog.evaluate(104.999), WatchdogState.HEALTHY)
        self.assertEqual(watchdog.missed_heartbeats(105.0), 1)
        self.assertEqual(watchdog.evaluate(114.999), WatchdogState.HEALTHY)
        self.assertEqual(watchdog.missed_heartbeats(115.0), 3)
        self.assertEqual(watchdog.evaluate(115.0), WatchdogState.TELEMETRY_LOSS)

    def test_heartbeat_resets_timer_and_recovers_telemetry_state(self) -> None:
        watchdog = HeartbeatWatchdog()
        watchdog.start(0.0)
        self.assertEqual(watchdog.evaluate(15.0), WatchdogState.TELEMETRY_LOSS)
        self.assertEqual(watchdog.record_heartbeat(16.0), WatchdogState.HEALTHY)
        self.assertEqual(watchdog.evaluate(30.999), WatchdogState.HEALTHY)
        self.assertEqual(watchdog.evaluate(31.0), WatchdogState.TELEMETRY_LOSS)

    def test_loss_without_intrusion_evidence_is_only_operational_warning(self) -> None:
        watchdog = HeartbeatWatchdog()
        watchdog.start(0.0)
        watchdog.evaluate(15.0)
        loss_at = datetime(2026, 8, 19, 10, 15, tzinfo=timezone.utc)

        disposition = watchdog.assess_telemetry_loss(
            loss_detected_at_utc=loss_at,
            latest_high_confidence_intrusion_at_utc=None,
        )
        self.assertEqual(disposition, TelemetryLossDisposition.OPERATIONAL_WARNING)

    def test_recent_intrusion_evidence_requires_human_candidate_review(self) -> None:
        watchdog = HeartbeatWatchdog()
        watchdog.start(0.0)
        watchdog.evaluate(15.0)
        loss_at = datetime(2026, 8, 19, 10, 15, tzinfo=timezone.utc)

        disposition = watchdog.assess_telemetry_loss(
            loss_detected_at_utc=loss_at,
            latest_high_confidence_intrusion_at_utc=loss_at - timedelta(seconds=120),
        )
        self.assertEqual(
            disposition,
            TelemetryLossDisposition.CANDIDATE_CATEGORY_II_REVIEW_REQUIRED,
        )

    def test_stale_or_future_intrusion_evidence_remains_operational_warning(self) -> None:
        watchdog = HeartbeatWatchdog()
        watchdog.start(0.0)
        watchdog.evaluate(15.0)
        loss_at = datetime(2026, 8, 19, 10, 15, tzinfo=timezone.utc)

        for intrusion_at in (
            loss_at - timedelta(seconds=120.001),
            loss_at + timedelta(seconds=1),
        ):
            with self.subTest(intrusion_at=intrusion_at):
                disposition = watchdog.assess_telemetry_loss(
                    loss_detected_at_utc=loss_at,
                    latest_high_confidence_intrusion_at_utc=intrusion_at,
                )
                self.assertEqual(disposition, TelemetryLossDisposition.OPERATIONAL_WARNING)

    def test_detailed_operational_warning_carries_no_statutory_clock(self) -> None:
        watchdog = HeartbeatWatchdog()
        watchdog.start(0.0)
        watchdog.evaluate(15.0)
        loss_at = datetime(2026, 8, 19, 10, 15, tzinfo=timezone.utc)

        assessment = watchdog.assess_telemetry_loss_detailed(
            loss_detected_at_utc=loss_at,
            latest_high_confidence_intrusion_at_utc=None,
        )
        self.assertIsInstance(assessment, TelemetryLossAssessment)
        self.assertEqual(assessment.disposition, TelemetryLossDisposition.OPERATIONAL_WARNING)
        self.assertFalse(assessment.requires_human_confirmation)
        self.assertIsNone(assessment.proposed_noticed_at_utc)
        self.assertIsNone(assessment.statutory_category)

    def test_detailed_candidate_proposes_noticed_at_and_requires_confirmation(self) -> None:
        watchdog = HeartbeatWatchdog()
        watchdog.start(0.0)
        watchdog.evaluate(15.0)
        loss_at = datetime(2026, 8, 19, 10, 15, tzinfo=timezone.utc)
        intrusion_at = loss_at - timedelta(seconds=90)

        assessment = watchdog.assess_telemetry_loss_detailed(
            loss_detected_at_utc=loss_at,
            latest_high_confidence_intrusion_at_utc=intrusion_at,
        )
        self.assertEqual(
            assessment.disposition,
            TelemetryLossDisposition.CANDIDATE_CATEGORY_II_REVIEW_REQUIRED,
        )
        # A candidate is never auto-confirmed: it proposes a clock-start but
        # still demands a human reviewer's sign-off.
        self.assertTrue(assessment.requires_human_confirmation)
        self.assertEqual(assessment.proposed_noticed_at_utc, loss_at)
        self.assertIn("Category (ii)", assessment.statutory_category)
        self.assertEqual(
            assessment.latest_high_confidence_intrusion_at_utc, intrusion_at
        )

    def test_evaluation_requires_monitoring_baseline(self) -> None:
        watchdog = HeartbeatWatchdog()
        with self.assertRaisesRegex(RuntimeError, "start"):
            watchdog.evaluate(15.0)

    def test_clock_cannot_move_backwards(self) -> None:
        watchdog = HeartbeatWatchdog()
        watchdog.start(10.0)
        with self.assertRaisesRegex(ValueError, "backwards"):
            watchdog.evaluate(9.0)


if __name__ == "__main__":
    unittest.main()
