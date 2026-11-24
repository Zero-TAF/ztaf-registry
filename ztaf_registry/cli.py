"""The ztaf-registry CLI.

    python -m ztaf_registry.cli init            [--registry REG]
    python -m ztaf_registry.cli publish         --registry REG --mandate-file M.json
    python -m ztaf_registry.cli revoke          --registry REG --mandate-id ID
    python -m ztaf_registry.cli register-agent  --registry REG --subject S --mandate-id ID [--grade G] [--card C] [--profile-ref P]
    python -m ztaf_registry.cli add-capability  --registry REG --tool T --publisher P --hash H
    python -m ztaf_registry.cli status-list     --registry REG --key-seed HEX --kid KID [--out OUT]
    python -m ztaf_registry.cli resolve         --registry REG --mandate-id ID
    python -m ztaf_registry.cli agents          --registry REG
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from ztaf_mandate.keys import generate_key
from ztaf_mandate.mandate import body_of, mandate_hash

from .registry import FileRegistry


def _load_mandate(path: str) -> dict:
    mandate = json.loads(Path(path).read_text())
    return mandate


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="ztaf-registry")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init")
    p.add_argument("--registry", default="registry.json")
    p.set_defaults(fn=lambda a: (FileRegistry(a.registry).save(), print(f"initialised {a.registry}")) or 0)

    p = sub.add_parser("publish")
    p.add_argument("--registry", required=True)
    p.add_argument("--mandate-file", required=True)
    def _publish(a):
        mandate = _load_mandate(a.mandate_file)
        body = body_of(mandate)
        reg = FileRegistry(a.registry)
        entry = reg.publish_mandate(body["mandate_id"], mandate_hash(mandate),
                                    body["subject"], body.get("parent", {}).get("mandate_id"))
        print(f"published {body['mandate_id']} status={entry['status']}")
        return 0
    p.add_argument("--mandate-file", required=True)
    p.set_defaults(fn=_publish)

    p = sub.add_parser("revoke")
    p.add_argument("--registry", required=True)
    p.add_argument("--mandate-id", required=True)
    def _revoke(a):
        entry = FileRegistry(a.registry).revoke_mandate(a.mandate_id)
        print(f"revoked {a.mandate_id} (down-chain propagation included)")
        return 0
    p.set_defaults(fn=_revoke)

    p = sub.add_parser("register-agent")
    p.add_argument("--registry", required=True)
    p.add_argument("--subject", required=True)
    p.add_argument("--mandate-id", required=True)
    p.add_argument("--grade", default=None)
    p.add_argument("--card", default=None, help="path to a discovery-card JSON")
    p.add_argument("--profile-ref", default=None)
    def _register(a):
        card = json.loads(Path(a.card).read_text()) if a.card else None
        entry = FileRegistry(a.registry).register_agent(
            a.subject, card=card, profile_ref=a.profile_ref,
            mandate_id=a.mandate_id, required_grade=a.grade)
        print(f"registered agent {a.subject}")
        return 0
    p.set_defaults(fn=_register)

    p = sub.add_parser("add-capability")
    p.add_argument("--registry", required=True)
    p.add_argument("--tool", required=True)
    p.add_argument("--publisher", required=True)
    p.add_argument("--hash", required=True)
    def _cap(a):
        FileRegistry(a.registry).add_capability(a.tool, a.publisher, a.hash)
        print(f"capability {a.tool} registered")
        return 0
    p.set_defaults(fn=_cap)

    p = sub.add_parser("status-list")
    p.add_argument("--registry", required=True)
    p.add_argument("--key-seed", required=True, help="32-byte hex seed of the list signer")
    p.add_argument("--kid", required=True)
    p.add_argument("--out", default="status-list.json")
    def _status(a):
        reg = FileRegistry(a.registry)
        private, _ = generate_key(bytes.fromhex(a.key_seed))
        status = reg.build_status_list(private, a.kid, datetime.now(timezone.utc))
        Path(a.out).write_text(json.dumps(status, indent=2))
        print(f"status list written to {a.out} ({len(status['entries'])} mandates)")
        return 0
    p.set_defaults(fn=_status)

    p = sub.add_parser("resolve")
    p.add_argument("--registry", required=True)
    p.add_argument("--mandate-id", required=True)
    def _resolve(a):
        entry = FileRegistry(a.registry).resolve(a.mandate_id)
        print(json.dumps(entry, indent=2) if entry else f"unknown mandate: {a.mandate_id}")
        return 0 if entry else 1
    p.set_defaults(fn=_resolve)

    p = sub.add_parser("agents")
    p.add_argument("--registry", required=True)
    def _agents(a):
        print(json.dumps(FileRegistry(a.registry).data["agents"], indent=2))
        return 0
    p.set_defaults(fn=_agents)

    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
