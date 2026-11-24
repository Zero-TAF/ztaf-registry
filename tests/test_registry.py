"""Registry cycle tests, including ztaf_mandate.StatusChecker integration."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for sibling in ("ztaf-mandate",):
    sibling_path = ROOT.parent / sibling
    if sibling_path.exists():
        sys.path.insert(0, str(sibling_path))
sys.path.insert(0, str(ROOT))

from ztaf_mandate.keys import generate_key  # noqa: E402
from ztaf_mandate.revocation import StatusChecker  # noqa: E402

from ztaf_registry.registry import FileRegistry, RegistryError  # noqa: E402

NOW = datetime(2026, 11, 24, 12, 0, 0, tzinfo=timezone.utc)


class TestRegistryCycle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.reg = FileRegistry(Path(self.tmp.name) / "registry.json")
        self.private, self.public = generate_key(bytes.fromhex("cc" * 32))
        self.reg.publish_mandate("ZT-MND-A", "zt-sha256:" + "11" * 32, "desk")
        self.reg.publish_mandate("ZT-MND-B", "zt-sha256:" + "22" * 32, "agent-1",
                                 parent_id="ZT-MND-A")
        self.reg.publish_mandate("ZT-MND-C", "zt-sha256:" + "33" * 32, "agent-1-sub",
                                 parent_id="ZT-MND-B")

    def tearDown(self):
        self.tmp.cleanup()

    def test_publish_resolve(self):
        entry = self.reg.resolve("ZT-MND-A")
        self.assertEqual(entry["status"], "valid")
        self.assertIsNone(self.reg.resolve("ZT-MND-Z"))

    def test_revoke_propagates_down_chain(self):
        self.reg.revoke_mandate("ZT-MND-B")
        self.assertEqual(self.reg.resolve("ZT-MND-B")["status"], "revoked")
        self.assertEqual(self.reg.resolve("ZT-MND-C")["status"], "revoked",
                         "descendants must fall with the parent (MAN-6)")
        self.assertEqual(self.reg.resolve("ZT-MND-A")["status"], "valid",
                         "ancestors survive a descendant revocation")

    def test_revoke_unknown_raises(self):
        with self.assertRaises(RegistryError):
            self.reg.revoke_mandate("ZT-MND-Z")

    def test_status_list_verifies_and_reflects_revocation(self):
        self.reg.revoke_mandate("ZT-MND-B")
        status = self.reg.build_status_list(self.private, "test-issuer", NOW)
        checker = StatusChecker(status, self.public, NOW + timedelta(minutes=5))
        self.assertFalse(checker("ZT-MND-A"))
        self.assertTrue(checker("ZT-MND-B"))
        self.assertTrue(checker("ZT-MND-C"))

    def test_stale_status_list_is_rejected(self):
        status = self.reg.build_status_list(self.private, "test-issuer", NOW)
        with self.assertRaises(Exception):
            StatusChecker(status, self.public, NOW + timedelta(hours=25))

    def test_agent_and_capability_entries(self):
        self.reg.register_agent("agent-1", card={"zt_card_version": "0.1.0"},
                                mandate_id="ZT-MND-B", required_grade="TG-2")
        self.reg.add_capability("payments-api", "payments-co",
                                "zt-sha256:" + "44" * 32)
        self.assertEqual(self.reg.data["agents"]["agent-1"]["required_grade"], "TG-2")
        self.assertEqual(self.reg.data["capabilities"]["payments-api"]["publisher"],
                         "payments-co")


if __name__ == "__main__":
    unittest.main()
