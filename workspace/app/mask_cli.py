"""光罩投片交付中心命令行。

示例:
  python3 -m app.mask_cli --db data/mask.db init-release demo-chip
  python3 -m app.mask_cli upload REL --kind layermap --file layer.map --by u_op
  python3 -m app.mask_cli finalize REL --by u_op --op-id op-1
  python3 -m app.mask_cli book LOT --machine EXP-01 --node NODE --slot L01 \
      --start 2026-10-05T08:00Z --end 2026-10-05T10:00Z --by u_disp1 --op-id op-win-1
  python3 -m app.mask_cli demo      # 端到端演示（内存→临时库）
"""
from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from .mask_export import ExportService
from .mask_service import MaskError, MaskService, sha256_hex
from .mask_store import MaskStore


def _print(obj):
    print(json.dumps(obj, ensure_ascii=False, indent=2, default=str))


def _read_file(path: str) -> tuple[bytes, str]:
    data = Path(path).read_bytes()
    return data, sha256_hex(data)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mask_cli", description="光罩投片交付中心 CLI")
    p.add_argument("--db", default="data/mask.db")
    p.add_argument("--blob-dir", default=None)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("releases")
    sp = sub.add_parser("release")
    sp.add_argument("name")
    sp.add_argument("--by", default="u_op")

    sp = sub.add_parser("release-show")
    sp.add_argument("release_id")

    sp = sub.add_parser("upload")
    sp.add_argument("release_id")
    sp.add_argument("--kind", required=True,
                    choices=["layout", "layermap", "recipe", "die", "scribe", "corner"])
    sp.add_argument("--file", required=True)
    sp.add_argument("--name", default=None)
    sp.add_argument("--layer-no", type=int, default=None)
    sp.add_argument("--digest", default=None, help="声明 SHA-256（默认按文件实算）")
    sp.add_argument("--by", default="u_op")
    sp.add_argument("--op-id", default=None)

    sp = sub.add_parser("verify")
    sp.add_argument("release_id")

    sp = sub.add_parser("finalize")
    sp.add_argument("release_id")
    sp.add_argument("--by", default="u_op")
    sp.add_argument("--op-id", default=None)

    sp = sub.add_parser("make-set")
    sp.add_argument("release_id")
    sp.add_argument("--name", default="mask-set")
    sp.add_argument("--by", default="u_op")
    sp.add_argument("--op-id", default=None)

    sp = sub.add_parser("set-show")
    sp.add_argument("set_id")

    sp = sub.add_parser("sets")

    sp = sub.add_parser("quarantine-list")
    sp.add_argument("--all", action="store_true")

    sp = sub.add_parser("quarantine-resolve")
    sp.add_argument("quarantine_id")
    sp.add_argument("--resolution", required=True, choices=["REJECT_INCOMING", "ACCEPT_NEW"])
    sp.add_argument("--by", default="u_op")
    sp.add_argument("--note", default=None)

    sub.add_parser("machines")

    sp = sub.add_parser("lot-create")
    sp.add_argument("name")
    sp.add_argument("--by", default="u_disp1")

    sp = sub.add_parser("lot-show")
    sp.add_argument("lot_id")

    sp = sub.add_parser("lot-bind")
    sp.add_argument("lot_id")
    sp.add_argument("--set", dest="set_id", required=True)
    sp.add_argument("--by", default="u_disp1")
    sp.add_argument("--op-id", default=None)

    sp = sub.add_parser("book")
    sp.add_argument("lot_id")
    sp.add_argument("--machine", required=True)
    sp.add_argument("--node", required=True)
    sp.add_argument("--slot", required=True)
    sp.add_argument("--start", required=True)
    sp.add_argument("--end", required=True)
    sp.add_argument("--by", default="u_disp1")
    sp.add_argument("--op-id", required=True)

    sp = sub.add_parser("expose")
    sp.add_argument("window_id")
    sp.add_argument("--by", default="u_disp1")

    sp = sub.add_argument("cancel", add_help=False) if False else sub.add_parser("window-cancel")
    sp.add_argument("window_id")
    sp.add_argument("--by", default="u_disp1")

    sp = sub.add_parser("replace-request")
    sp.add_argument("release_id")
    sp.add_argument("--set", dest="set_id", required=True)
    sp.add_argument("--node", required=True)
    sp.add_argument("--slot", required=True)
    sp.add_argument("--file", required=True)
    sp.add_argument("--name", default=None)
    sp.add_argument("--reason", default="CLI 替换申请")
    sp.add_argument("--by", default="u_op")
    sp.add_argument("--op-id", default=None)

    sp = sub.add_parser("replace-approve")
    sp.add_argument("replacement_id")
    sp.add_argument("--role", required=True, choices=["ME", "LO"])
    sp.add_argument("--by", required=True)

    sp = sub.add_parser("rework")
    sp.add_argument("lot_id")
    sp.add_argument("--reason", required=True)
    sp.add_argument("--slot", required=True)
    sp.add_argument("--file", required=True)
    sp.add_argument("--name", default=None)
    sp.add_argument("--by", default="u_mei")
    sp.add_argument("--op-id", default=None)

    sp = sub.add_parser("export")
    sp.add_argument("node_id")
    sp.add_argument("--by", default="u_op")
    sp.add_argument("--op-id", default=None)
    sp.add_argument("--wait", action="store_true")

    sp = sub.add_parser("export-list")

    sp = sub.add_parser("audit")
    sp.add_argument("--entity", default=None)
    sp.add_argument("--action", default=None)
    sp.add_argument("--op-id", default=None)
    sp.add_argument("--limit", type=int, default=50)

    sp = sub.add_parser("recover")

    sub.add_parser("demo")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.cmd == "demo":
        return run_demo()
    store = MaskStore(args.db, blob_dir=args.blob_dir)
    svc = MaskService(store)
    exporter = ExportService(store)
    try:
        _dispatch(args, svc, exporter)
    except MaskError as e:
        print(json.dumps({"error": e.code, "message": e.message, "detail": e.extra},
                         ensure_ascii=False, indent=2))
        raise SystemExit(1)


def _dispatch(a, svc: MaskService, exporter: ExportService):
    if a.cmd == "releases":
        _print({"releases": svc.list_releases()})
    elif a.cmd == "release":
        _print(svc.create_release(a.name, a.by))
    elif a.cmd == "release-show":
        _print(svc.release_detail(a.release_id))
    elif a.cmd == "upload":
        data, digest = _read_file(a.file)
        _print(svc.add_artifact(a.release_id, a.kind, a.name or Path(a.file).name, data,
                                a.digest or digest, a.by, layer_no=a.layer_no, op_id=a.op_id))
    elif a.cmd == "verify":
        _print(svc.verify_release(a.release_id))
    elif a.cmd == "finalize":
        _print(svc.finalize_release(a.release_id, a.by, a.op_id))
    elif a.cmd == "make-set":
        _print(svc.create_mask_set(a.release_id, a.name, a.by, a.op_id))
    elif a.cmd == "set-show":
        _print(svc.mask_set_detail(a.set_id))
    elif a.cmd == "sets":
        _print({"mask_sets": svc.list_mask_sets()})
    elif a.cmd == "quarantine-list":
        _print({"quarantines": svc.list_quarantine(not a.all)})
    elif a.cmd == "quarantine-resolve":
        _print(svc.resolve_quarantine(a.quarantine_id, a.resolution, a.by, a.note))
    elif a.cmd == "machines":
        _print({"machines": svc.list_machines()})
    elif a.cmd == "lot-create":
        _print(svc.create_lot(a.name, a.by))
    elif a.cmd == "lot-show":
        _print(svc.lot_detail(a.lot_id))
    elif a.cmd == "lot-bind":
        _print(svc.bind_lot(a.lot_id, a.set_id, a.by, a.op_id))
    elif a.cmd == "book":
        _print(svc.book_window(a.lot_id, a.machine, a.node, a.slot, a.start, a.end, a.by,
                               a.op_id))
    elif a.cmd == "expose":
        _print(svc.expose_window(a.window_id, a.by))
    elif a.cmd == "window-cancel":
        _print(svc.cancel_window(a.window_id, a.by))
    elif a.cmd == "replace-request":
        data, digest = _read_file(a.file)
        _print(svc.request_replacement(a.release_id, a.set_id, a.node, a.slot,
                                       a.name or Path(a.file).name, data, digest, a.by, a.reason,
                                       a.op_id))
    elif a.cmd == "replace-approve":
        _print(svc.approve_replacement(a.replacement_id, a.role, a.by))
    elif a.cmd == "rework":
        data, digest = _read_file(a.file)
        _print(svc.create_rework(a.lot_id, a.reason, a.by,
                                 [{"slot": a.slot, "name": a.name or Path(a.file).name,
                                   "data": data, "declared_sha256": digest}], a.op_id))
    elif a.cmd == "export":
        e = exporter.enqueue(a.node_id, a.by, a.op_id)
        if a.wait or True:
            done = exporter.recover()
        _print(e)
    elif a.cmd == "export-list":
        _print({"exports": exporter.list_exports()})
    elif a.cmd == "audit":
        _print({"events": svc.audit_log(a.entity, a.action, a.op_id, a.limit)})
    elif a.cmd == "recover":
        _print({"exports": [e["id"] for e in exporter.recover()],
                **svc.recover_pending_ops()})


# ---------------- 端到端演示 ----------------

def _layermap():
    return ("LAYERMAP chip-A\nLAYER 1 diff\nLAYER 2 poly\nLAYER 3 metal1\n").encode()


def _recipe():
    return ("RECIPE FAB-X12-R3\nLAYER 1\nLAYER 2\nLAYER 3\n"
            "CORNER ss_0p81v_m40c\nCORNER ff_0p99v_125c\n").encode()


def _layer(n: int):
    return (f"# GDS placeholder L{n}\n@LAYER {n}\n").encode()


def _corner(name: str):
    return f"CORNER {name}\nvdd=0.81\ntemp=-40\n".encode()


def run_demo():
    tmp = tempfile.mkdtemp(prefix="mask-demo-")
    store = MaskStore(f"{tmp}/mask.db", blob_dir=f"{tmp}/blobs")
    svc = MaskService(store)
    exporter = ExportService(store, export_root=f"{tmp}/exports")

    rel = svc.create_release("chip-A", "u_op")["id"]
    print("① 创建发行:", rel)
    files = [("layermap", "layer.map", _layermap(), None),
             ("recipe", "fab.recipe", _recipe(), None),
             ("die", "die.dim", b"DIE 5000 3000\n", None),
             ("scribe", "scribe.cfg", b"SCRIBE WIDTH 80\n", None),
             ("corner", "ss.corner", _corner("ss_0p81v_m40c"), None),
             ("corner", "ff.corner", _corner("ff_0p99v_125c"), None),
             ("layout", "L01.gds", _layer(1), 1),
             ("layout", "L02.gds", _layer(2), 2),
             ("layout", "L03.gds", _layer(3), 3)]
    for kind, name, data, lno in files:
        art = svc.add_artifact(rel, kind, name, data, sha256_hex(data), "u_op", layer_no=lno)
        print(f"   收料 {art['slot']:20s} {name}  v{art['version']}")
    vrf = svc.verify_release(rel)
    print("② 核验结论:", vrf["verdict"], f"({len(vrf['findings'])} 条 findings)")
    fin = svc.finalize_release(rel, "u_op", "demo-finalize-1")
    print("③ 稳定交付编号:", fin["delivery_no"])

    ms = svc.create_mask_set(rel, "chip-A 主光罩", "u_op")["id"]
    master = svc.mask_set_detail(ms)["nodes"][0]["id"]
    print("④ 主版 mask set:", ms, "节点", master)

    lot = svc.create_lot("WAFER-LOT-7788", "u_disp1")["id"]
    svc.bind_lot(lot, ms, "u_disp1", "demo-bind-1")
    slots = [s["slot"] for s in svc.node_detail(master)["slots"]
             if s["slot"].startswith("L")]
    t0, t1 = 0, 2
    wins = []
    for slot in slots:
        w = svc.book_window(lot, "EXP-01", master, slot,
                            f"2026-10-05T{8+t0:02d}:00Z", f"2026-10-05T{8+t1:02d}:00Z",
                            "u_disp1", f"demo-book-{slot}")
        wins.append(w["id"])
        t0 += 2; t1 += 2
    print("⑤ 排程", len(wins), "个窗口（先后次序）")

    # 曝光第一个窗口后尝试原地改写 → 必须拒绝
    svc.expose_window(wins[0], "u_disp1")
    print("⑥ 首个窗口已曝光")
    try:
        svc.request_replacement(rel, ms, master, "L02", "L02.gds", b"tampered",
                                sha256_hex(b"tampered"), "u_op", "试改")
    except MaskError as e:
        print("⑦ 曝光后原地改写被拒绝:", e.code)

    rw = svc.create_rework(lot, "L01 颗粒缺陷返工", "u_mei",
                           [{"slot": "L01", "name": "L01-r1.gds",
                             "data": b"# GDS placeholder L1 rev1\n@LAYER 1\n",
                             "declared_sha256": None}], "demo-rework-1")
    print("⑧ 创建 delta 返工计划:", rw["delta_set_id"])

    e = exporter.enqueue(rw["delta_node_id"], "u_op", "demo-export-1")
    exporter.recover()
    done = exporter.export_detail(e["id"])
    print("⑨ 只读交付包:", done["state"], done["zip_path"], done["package_sha256"][:16], "…")
    print("演示完成，临时目录:", tmp)


if __name__ == "__main__":
    main()
