"""命令行：直接打开本地存储（与 HTTP 服务共享同一个 SQLite 库）。

用法示例：
  python -m mdc.cli --db ./data import packet.json --as u_admin
  python -m mdc.cli --db ./data reserve --tool TOOL-xx --set MS-XXXX --mask M1 \
      --start 2026-10-10T08:00:00Z --end 2026-10-10T10:00:00Z --as u_disp1 --op OP-123
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .domain import DomainError
from .service import Service
from .store import Store


def _print(obj):
    print(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=False))


def _err(e: DomainError):
    print(json.dumps({"error": e.code, "message": e.message, "detail": e.detail},
                     ensure_ascii=False, indent=2), file=sys.stderr)
    sys.exit(2)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mdc", description="光罩投片交付中心 CLI")
    p.add_argument("--db", default="./mdc-data", help="数据目录（SQLite+CAS）")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("serve"); sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=8080)

    sub.add_parser("people")
    sub.add_parser("artifacts")
    sub.add_parser("releases")
    sub.add_parser("sets")
    sub.add_parser("tools")
    sub.add_parser("windows")
    sub.add_parser("lots")
    sub.add_parser("packages")
    sub.add_parser("quarantine")
    sub.add_parser("arbitrations")
    sp = sub.add_parser("audit"); sp.add_argument("--target"); sp.add_argument("--op")

    sp = sub.add_parser("upload")
    sp.add_argument("file"); sp.add_argument("--name", required=True)
    sp.add_argument("--kind", default="OTHER")
    sp.add_argument("--sha256"); sp.add_argument("--as", dest="actor", required=True)

    sp = sub.add_parser("import")
    sp.add_argument("packet_json"); sp.add_argument("--as", dest="actor", required=True)

    sp = sub.add_parser("release"); sp.add_argument("id")
    sp = sub.add_parser("set"); sp.add_argument("key")
    sp = sub.add_parser("artifact"); sp.add_argument("key")

    sp = sub.add_parser("mktool"); sp.add_argument("name")
    sp.add_argument("--as", dest="actor", default="u_disp1")
    sp = sub.add_parser("mklot"); sp.add_argument("name")
    sp.add_argument("--as", dest="actor", default="u_disp1")

    sp = sub.add_parser("reserve")
    sp.add_argument("--tool", required=True); sp.add_argument("--set", required=True)
    sp.add_argument("--mask", required=True)
    sp.add_argument("--start", required=True); sp.add_argument("--end", required=True)
    sp.add_argument("--lot"); sp.add_argument("--op")
    sp.add_argument("--as", dest="actor", required=True)

    sp = sub.add_parser("cancel"); sp.add_argument("window"); sp.add_argument("--op")
    sp.add_argument("--as", dest="actor", default="u_disp1")
    sp = sub.add_parser("expose"); sp.add_argument("window"); sp.add_argument("--op")
    sp.add_argument("--as", dest="actor", default="u_disp1")
    sp = sub.add_parser("bind"); sp.add_argument("lot"); sp.add_argument("--set", required=True)
    sp.add_argument("--op"); sp.add_argument("--as", dest="actor", default="u_disp1")

    sp = sub.add_parser("replace-request")
    sp.add_argument("--set", required=True); sp.add_argument("--mask", required=True)
    sp.add_argument("--new-sha", required=True); sp.add_argument("--reason", default="")
    sp.add_argument("--op"); sp.add_argument("--as", dest="actor", required=True)
    sp = sub.add_parser("replace-approve"); sp.add_argument("replacement")
    sp.add_argument("--op"); sp.add_argument("--as", dest="actor", required=True)
    sp = sub.add_parser("replace-reject"); sp.add_argument("replacement")
    sp.add_argument("--op"); sp.add_argument("--as", dest="actor", required=True)
    sp = sub.add_parser("replacements"); sp.add_argument("--status")

    sp = sub.add_parser("delta")
    sp.add_argument("--set", required=True)
    sp.add_argument("--change", action="append", required=True,
                    help="MASK=SHA，可多次")
    sp.add_argument("--note", default=""); sp.add_argument("--op")
    sp.add_argument("--as", dest="actor", default="u_mei")
    sp = sub.add_parser("rework")
    sp.add_argument("--lot", required=True); sp.add_argument("--delta", required=True)
    sp.add_argument("--note", default=""); sp.add_argument("--op")
    sp.add_argument("--as", dest="actor", default="u_mei")

    sp = sub.add_parser("build"); sp.add_argument("--set", required=True)
    sp.add_argument("--op"); sp.add_argument("--as", dest="actor", required=True)
    sp = sub.add_parser("download"); sp.add_argument("package"); sp.add_argument("--out")

    sp = sub.add_parser("quarantine-resolve")
    sp.add_argument("qid"); sp.add_argument("--decision", required=True,
                                            choices=["ACCEPT_AS_ALIAS", "REJECT"])
    sp.add_argument("--new-name"); sp.add_argument("--as", dest="actor", default="u_admin")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    svc = Service(Store(args.db))
    try:
        c = args.cmd
        if c == "serve":
            from .api import make_server
            httpd = make_server(args.host, args.port, svc.s)
            print(f"MaskCenter on http://{args.host}:{args.port}  (db={args.db})")
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                pass
            return 0
        if c == "people":
            _print(svc.list_people())
        elif c == "artifacts":
            _print(svc.list_artifacts())
        elif c == "releases":
            _print(svc.list_releases())
        elif c == "sets":
            _print(svc.list_sets())
        elif c == "tools":
            _print(svc.list_tools())
        elif c == "windows":
            _print(svc.list_windows())
        elif c == "lots":
            _print(svc.list_lots())
        elif c == "packages":
            _print(svc.list_packages())
        elif c == "quarantine":
            _print(svc.list_quarantine())
        elif c == "arbitrations":
            _print([dict(r) for r in svc.s.q_all(
                "SELECT * FROM arbitration ORDER BY decided_at DESC")])
        elif c == "audit":
            _print(svc.list_audit(target=args.target, op_id=args.op))
        elif c == "upload":
            data = Path(args.file).read_bytes()
            _print(svc.put_content(args.actor, args.name, args.kind, data, args.sha256))
        elif c == "import":
            packet = json.loads(Path(args.packet_json).read_text(encoding="utf-8"))
            _print(svc.import_release(packet, args.actor))
        elif c == "release":
            _print(svc.get_release(args.id))
        elif c == "set":
            _print(svc.get_set(args.key))
        elif c == "artifact":
            _print(svc.artifact_relations(
                sha=args.key if len(args.key) == 64 else None,
                name=None if len(args.key) == 64 else args.key))
        elif c == "mktool":
            _print(svc.create_tool(args.actor, args.name))
        elif c == "mklot":
            _print(svc.create_lot(args.actor, args.name))
        elif c == "reserve":
            _print(svc.reserve_window(args.actor, args.tool, args.set, args.mask,
                                      args.start, args.end, args.lot, args.op))
        elif c == "cancel":
            _print(svc.cancel_window(args.actor, args.window, args.op))
        elif c == "expose":
            _print(svc.expose(args.actor, args.window, args.op))
        elif c == "bind":
            _print(svc.bind_lot(args.actor, args.lot, args.set, args.op))
        elif c == "replace-request":
            _print(svc.request_replacement(args.actor, args.set, args.mask,
                                           args.new_sha, args.reason, args.op))
        elif c == "replace-approve":
            _print(svc.approve_replacement(args.actor, args.replacement, args.op))
        elif c == "replace-reject":
            _print(svc.reject_replacement(args.actor, args.replacement, args.op))
        elif c == "replacements":
            _print(svc.list_replacements(args.status))
        elif c == "delta":
            changes = []
            for item in args.change:
                mask, sha = item.split("=", 1)
                changes.append({"mask_name": mask, "new_sha": sha})
            _print(svc.create_delta(args.actor, args.set, changes, args.note, args.op))
        elif c == "rework":
            _print(svc.create_rework_plan(args.actor, args.lot, args.delta,
                                          args.note, args.op))
        elif c == "build":
            _print(svc.build_package(args.actor, args.set, args.op))
        elif c == "download":
            p, row = svc.get_package_file(args.package)
            out = Path(args.out or f"{args.package}.tar")
            out.write_bytes(p.read_bytes())
            _print({"saved": str(out), "sha256": row["sha256"]})
        elif c == "quarantine-resolve":
            _print(svc.resolve_quarantine(args.actor, args.qid, args.decision,
                                          args.new_name))
        else:  # pragma: no cover
            raise SystemExit(2)
        return 0
    except DomainError as e:
        _err(e)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
