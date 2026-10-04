"""设计签名封装服务命令行。

示例：
  python3 -m app.envelope_cli keygen
  python3 -m app.envelope_cli demo --db /tmp/env.db
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import ed25519
from .envelope import EnvelopeService
from .envelope_store import EnvelopeStore


def p(obj):
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def keygen(args):
    p(EnvelopeService(EnvelopeStore(args.db)).generate_signer_key())


def register(args):
    svc = EnvelopeService(EnvelopeStore(args.db))
    p(svc.register_signer(args.kid, args.signer, args.role, args.public_key,
                          args.by, args.replaces))


def rotate_root(args):
    p(EnvelopeService(EnvelopeStore(args.db)).rotate_root(args.by))


def revoke(args):
    p(EnvelopeService(EnvelopeStore(args.db)).revoke_signer(args.kid, args.by, args.reason))


def create(args):
    p(EnvelopeService(EnvelopeStore(args.db)).create_session(
        args.by, args.role, args.parent, json.loads(args.metadata or "{}"), args.session))


def add_file(args):
    svc = EnvelopeService(EnvelopeStore(args.db))
    data = Path(args.file).read_bytes()
    if args.kind in ("constraints", "modules", "signoffs"):
        # 允许 JSON 文件以对象形式保存；网表按原始字节。
        try:
            content = json.loads(data)
        except json.JSONDecodeError:
            content = data.decode()
    else:
        content = data.decode()
    p(svc.add_inline_artifact(args.session, args.slot, args.kind, content,
                              json.loads(args.detail or "{}"), args.by))


def upload_file(args):
    svc = EnvelopeService(EnvelopeStore(args.db))
    data = Path(args.file).read_bytes()
    u = svc.init_upload(args.session, args.slot, args.kind, args.chunk_size,
                        len(data), {}, args.by)
    uid = u["id"]
    for i in range(0, len(data), args.chunk_size):
        part = data[i:i + args.chunk_size]
        if not args.resume or i // args.chunk_size in u["missing_indexes"]:
            u = svc.put_chunk(uid, i // args.chunk_size, part, by=args.by)
    p(svc.complete_upload(uid, args.by))


def prepare(args):
    p(EnvelopeService(EnvelopeStore(args.db)).prepare(args.session, args.by))


def sign(args):
    store = EnvelopeStore(args.db)
    svc = EnvelopeService(store)
    challenge = svc.challenge(args.session, args.kid)
    env = svc.envelope(challenge["envelope_id"])
    message = {
        "schema": "design-envelope-signature/1",
        "envelope_id": challenge["envelope_id"],
        "content_hash": env["content_hash"],
        "merkle_root": env["merkle_root"],
        "kid": args.kid,
        "signed_at": challenge["signed_at"],
    }
    sig = ed25519.sign(bytes.fromhex(args.seed),
                       json.dumps(message, ensure_ascii=False, sort_keys=True,
                                  separators=(",", ":")).encode()).hex()
    p(svc.submit_signature(args.session, challenge, sig, args.by))


def seal(args):
    p(EnvelopeService(EnvelopeStore(args.db)).seal(args.session, args.by))


def publish(args):
    p(EnvelopeService(EnvelopeStore(args.db)).publish(args.session, args.name, args.by))


def verify(args):
    svc = EnvelopeService(EnvelopeStore(args.db))
    if args.bundle:
        p(svc.verify_offline_bundle(Path(args.bundle).read_bytes(), args.trusted_root))
    else:
        p(svc.verify_envelope(args.envelope, args.trusted_root))


def export(args):
    svc = EnvelopeService(EnvelopeStore(args.db))
    Path(args.out).write_bytes(svc.export_bundle(args.envelope))
    p({"ok": True, "out": args.out, "envelope_id": args.envelope})


def lineage(args):
    p(EnvelopeService(EnvelopeStore(args.db)).lineage(args.name, args.envelope))


def proofs(args):
    svc = EnvelopeService(EnvelopeStore(args.db))
    if args.subject:
        p(svc.inclusion_proof(args.envelope, args.leaf_type, args.subject))
    else:
        p(svc.proofs(args.envelope))


def list_items(args):
    svc = EnvelopeService(EnvelopeStore(args.db))
    kind = args.kind
    if kind == "sessions":
        p({"sessions": svc.list_sessions()})
    elif kind == "envelopes":
        p({"envelopes": svc.list_envelopes()})
    else:
        p({"publications": svc.list_publications()})


def demo(args):
    import tempfile
    from datetime import datetime, timezone

    with tempfile.TemporaryDirectory() as td:
        store = EnvelopeStore(f"{td}/env.db", f"{td}/blobs", seed=True)
        svc = EnvelopeService(store)
        keys = []
        roles = ["TIMING_LEAD", "METHODOLOGY_LEAD"]
        people = ["timing.chen", "method.li"]
        for role, person in zip(roles, people):
            k = svc.generate_signer_key()
            svc.register_signer(k["kid"], person, role, k["public_key"], "admin")
            keys.append((k, role, person))
        s = svc.create_session("ci", roles, metadata={"project": "demo"})
        svc.add_inline_artifact(s["id"], "netlist/core.v", "netlist",
                                "MODULE core; CELL DEMO; ENDMODULE\n")
        svc.add_inline_artifact(s["id"], "constraints/top.sdc", "constraints",
                                {"clk_period_ns": 1.0})
        svc.add_inline_artifact(s["id"], "modules.json", "modules",
                                ["core", "alu"])
        svc.add_inline_artifact(s["id"], "signoffs/record.json", "signoffs",
                                {"record": "CI signoff package",
                                 "at": datetime.now(timezone.utc).isoformat()})
        prepared = svc.prepare(s["id"], "ci")
        sid, eid = s["id"], prepared["envelope_id"]
        for k, role, person in keys:
            ch = svc.challenge(sid, k["kid"])
            env = svc.envelope(eid)
            msg = {"schema": "design-envelope-signature/1", "envelope_id": eid,
                   "content_hash": env["content_hash"], "merkle_root": env["merkle_root"],
                   "kid": k["kid"], "signed_at": ch["signed_at"]}
            raw = json.dumps(msg, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":")).encode()
            sig = ed25519.sign(bytes.fromhex(k["private_seed"]), raw).hex()
            svc.submit_signature(sid, ch, sig, person)
        svc.seal(sid, "ci")
        pub = svc.publish(sid, "demo-release", "ci")
        out = Path(td) / "release.zip"
        out.write_bytes(svc.export_bundle(eid))
        verified = svc.verify_offline_bundle(out.read_bytes())
        p({"session": sid, "envelope_id": eid, "publication": pub,
           "offline_verify": verified, "lineage": svc.lineage("demo-release"),
           "bundle": str(out)})


def build_parser():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="data/envelope.db")
    sub = ap.add_subparsers(dest="cmd", required=True)
    x = sub.add_parser("keygen"); x.set_defaults(func=keygen)
    x = sub.add_parser("rotate-root"); x.add_argument("--by", default="admin")
    x.set_defaults(func=rotate_root)
    x = sub.add_parser("register"); x.add_argument("kid"); x.add_argument("signer")
    x.add_argument("role"); x.add_argument("public_key"); x.add_argument("--by", default="admin")
    x.add_argument("--replaces"); x.set_defaults(func=register)
    x = sub.add_parser("revoke"); x.add_argument("kid"); x.add_argument("--by", default="admin")
    x.add_argument("--reason", default="REVOKED"); x.set_defaults(func=revoke)
    x = sub.add_parser("create"); x.add_argument("--by", default="cli"); x.add_argument("--session")
    x.add_argument("--role", action="append", dest="role")
    x.add_argument("--parent"); x.add_argument("--metadata"); x.set_defaults(func=create)
    x = sub.add_parser("add-file"); x.add_argument("session"); x.add_argument("slot")
    x.add_argument("kind"); x.add_argument("file"); x.add_argument("--by", default="cli")
    x.add_argument("--detail"); x.set_defaults(func=add_file)
    x = sub.add_parser("upload-file"); x.add_argument("session"); x.add_argument("slot")
    x.add_argument("kind"); x.add_argument("file"); x.add_argument("--chunk-size", type=int,
                                                                    default=64 * 1024)
    x.add_argument("--resume", action="store_true"); x.add_argument("--by", default="cli")
    x.set_defaults(func=upload_file)
    for name, fn in [("prepare", prepare), ("seal", seal)]:
        x = sub.add_parser(name); x.add_argument("session"); x.add_argument("--by", default="cli")
        x.set_defaults(func=fn)
    x = sub.add_parser("sign"); x.add_argument("session"); x.add_argument("kid")
    x.add_argument("seed"); x.add_argument("--by", default="signer"); x.set_defaults(func=sign)
    x = sub.add_parser("publish"); x.add_argument("session"); x.add_argument("name")
    x.add_argument("--by", default="cli"); x.set_defaults(func=publish)
    x = sub.add_parser("verify"); x.add_argument("envelope", nargs="?")
    x.add_argument("--bundle"); x.add_argument("--trusted-root"); x.set_defaults(func=verify)
    x = sub.add_parser("export"); x.add_argument("envelope"); x.add_argument("out")
    x.set_defaults(func=export)
    x = sub.add_parser("lineage"); x.add_argument("--name"); x.add_argument("--envelope")
    x.set_defaults(func=lineage)
    x = sub.add_parser("proofs"); x.add_argument("envelope")
    x.add_argument("--leaf-type"); x.add_argument("--subject"); x.set_defaults(func=proofs)
    x = sub.add_parser("list"); x.add_argument("kind", choices=["sessions", "envelopes",
                                                                "publications"])
    x.set_defaults(func=list_items)
    x = sub.add_parser("demo"); x.set_defaults(func=demo)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
