"""The Zero-TAF registry reference.

A file-backed registry holding three kinds of entries — agents, mandates,
capability provenance — plus revocation state, and the signed status lists
the decision point checks (MAN-6, SEC-7). Persistence is a single JSON
document; production registries implement the same operations over real
storage and an availability story on the decision point's fail-closed path
(ENF-3: registry unavailability denies).

Agent entries are shaped to carry the Agentic Operations bootstrap output
(subject, card reference, mandate binding) — see ztaf-reference-harness
`ztaf_harness.ao.bootstrap`.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ztaf_mandate.canonical import digest
from ztaf_mandate.keys import sign

REGISTRY_VERSION = "0.1.0"
STATUS_VERSION = "0.1.0"


class RegistryError(Exception):
    pass


class FileRegistry:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        if self.path.exists():
            self.data = json.loads(self.path.read_text())
        else:
            self.data = {"zt_registry_version": REGISTRY_VERSION,
                         "agents": {}, "mandates": {}, "capabilities": {}}

    def save(self) -> None:
        self.path.write_text(json.dumps(self.data, indent=2, ensure_ascii=False) + "\n")

    # -- mandates ----------------------------------------------------------
    def publish_mandate(self, mandate_id: str, mandate_hash: str, subject: str,
                        parent_id: Optional[str] = None) -> dict:
        entry = {"mandate_hash": mandate_hash, "subject": subject,
                 "parent_id": parent_id, "status": "valid", "published_at":
                 datetime.now(timezone.utc).isoformat(timespec="seconds")}
        self.data["mandates"][mandate_id] = entry
        self.save()
        return entry

    def revoke_mandate(self, mandate_id: str) -> dict:
        if mandate_id not in self.data["mandates"]:
            raise RegistryError(f"unknown mandate: {mandate_id}")
        entry = self.data["mandates"][mandate_id]
        if entry["status"] != "revoked":
            entry["status"] = "revoked"
            entry["revoked_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            # MAN-6: revocation propagates down-chain by parent linkage.
            for mid, other in self.data["mandates"].items():
                if other.get("parent_id") == mandate_id and other["status"] != "revoked":
                    self.revoke_mandate(mid)
        self.save()
        return entry

    def resolve(self, mandate_id: str) -> Optional[dict]:
        return self.data["mandates"].get(mandate_id)

    # -- agents and capabilities --------------------------------------------
    def register_agent(self, subject: str, card: Optional[dict] = None,
                       profile_ref: Optional[str] = None,
                       mandate_id: Optional[str] = None,
                       required_grade: Optional[str] = None) -> dict:
        entry = {"card": card, "profile_ref": profile_ref, "mandate_id": mandate_id,
                 "required_grade": required_grade}
        self.data["agents"][subject] = entry
        self.save()
        return entry

    def add_capability(self, tool: str, publisher: str, artifact_hash: str) -> dict:
        entry = {"publisher": publisher, "artifact_hash": artifact_hash,
                 "registered_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        self.data["capabilities"][tool] = entry
        self.save()
        return entry

    # -- signed status lists -------------------------------------------------
    def build_status_list(self, private, issuer_key_id: str, now: datetime) -> dict:
        """Build and sign a status list covering every known mandate
        (entries default 'valid'; revoked mandates carry 'revoked'). The
        format is the one `ztaf_mandate.revocation.StatusChecker` verifies."""
        body = {
            "zt_status_version": STATUS_VERSION,
            "updated": now.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "entries": {mid: ("revoked" if e["status"] == "revoked" else "valid")
                        for mid, e in self.data["mandates"].items()},
            "issuer_key_id": issuer_key_id,
        }
        signature = sign(private, digest(body))
        return {**body, "issuer_signature": base64.b64encode(signature).decode("ascii")}
