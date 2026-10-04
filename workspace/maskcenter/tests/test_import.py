"""导入与规范化：稳定交付编号、去重、各类拒收定位、同名隔离。"""
import json

from mdc.domain import DomainError, canonical_bytes
from tests.helpers import BaseCase


class TestImport(BaseCase):
    def test_valid_delivery_number_stable_and_dedup(self):
        p = self.valid_packet("A")
        r1 = self.svc.import_release(p, "u_admin")
        self.assertEqual(r1["status"], "VALID")
        self.assertTrue(r1["delivery_no"].startswith("MS-"))
        r2 = self.svc.import_release(p, "u_admin")
        self.assertTrue(r2["replayed"])
        self.assertEqual(r1["delivery_no"], r2["delivery_no"])
        self.assertEqual(r1["mask_set_id"], r2["mask_set_id"])

    def test_canonical_is_field_order_insensitive(self):
        p1 = self.valid_packet("A")
        p2 = json.loads(json.dumps(p1))
        # 调整 entries 顺序（规范化应折叠）
        p2["entries"] = list(reversed(p2["entries"]))
        self.assertEqual(
            self.svc.import_release(p1, "u_admin")["delivery_no"],
            self.svc.import_release(p2, "u_admin")["delivery_no"])

    def test_declared_digest_mismatch_rejected(self):
        with self.assertRaises(DomainError) as cm:
            self.svc.put_content("u_admin", "x.gds", "GDS", b"abc", "f" * 64)
        self.assertEqual(cm.exception.code, "DIGEST_MISMATCH")

    def test_cas_tamper_detected_and_located(self):
        p = self.valid_packet("T")
        g = next(e for e in p["entries"] if e["role"] == "GDS")
        path = self.svc.s.cas_path(g["sha256"])
        original = path.read_bytes()
        try:
            path.write_bytes(original + b"X")
            r = self.svc.import_release(p, "u_admin")
            self.assertEqual(r["status"], "INVALID")
            f = next(x for x in r["findings"] if x["code"] == "DIGEST_TAMPERED")
            self.assertEqual(f["locator"]["id"], g["logical_name"])
            self.assertEqual(f["locator"]["role"], "GDS")
        finally:
            path.write_bytes(original)

    def test_missing_mask_file(self):
        p = self.valid_packet("M")
        p["entries"] = [e for e in p["entries"] if e["role"] != "MASK:M_IL"]
        r = self.svc.import_release(p, "u_admin")
        codes = {f["code"] for f in r["findings"]}
        self.assertIn("MISSING_MASK_FILE", codes)
        f = next(x for x in r["findings"] if x["code"] == "MISSING_MASK_FILE")
        self.assertEqual(f["locator"]["id"], "M_IL")

    def test_dependency_inversion_recipe(self):
        p = self.valid_packet("I")
        bad = {"recipe_id": "FAB12-RCP-7", "fab": "FAB12",
               "corners": ["TT_0p90_25C"],
               "masks": [
                   {"name": "M_MAIN", "role_type": "MASTER", "layer": "L100.0",
                    "depends_on": ["M_OPC"]},
                   {"name": "M_OPC", "role_type": "CORRECTED", "layer": "L101.0",
                    "depends_on": []},
                   {"name": "M_IL", "role_type": "DERIVED", "layer": "L200.0",
                    "depends_on": ["M_OPC"]}]}
        up = self.svc.put_content("u_admin", "bad.json", "RECIPE",
                                  canonical_bytes(bad))
        for e in p["entries"]:
            if e["role"] == "RECIPE":
                e["logical_name"], e["sha256"] = up["logical_name"], up["sha256"]
        r = self.svc.import_release(p, "u_admin")
        self.assertIn("DEPENDENCY_INVERSION",
                      {f["code"] for f in r["findings"]})

    def test_corner_not_in_recipe(self):
        p = self.valid_packet("C")
        p["corner"] = "NOPE"
        r = self.svc.import_release(p, "u_admin")
        self.assertIn("CORNER_NOT_IN_RECIPE",
                      {f["code"] for f in r["findings"]})

    def test_recipe_id_mismatch(self):
        p = self.valid_packet("R")
        p["foundry_recipe_id"] = "OTHER"
        r = self.svc.import_release(p, "u_admin")
        self.assertIn("RECIPE_MISMATCH", {f["code"] for f in r["findings"]})

    def test_missing_layermap_layer(self):
        p = self.valid_packet("L")
        lm = next(e for e in p["entries"] if e["role"] == "LAYERMAP")
        obj = json.loads(self.svc.s.get_blob(lm["sha256"]))
        obj["mappings"] = [m for m in obj["mappings"] if m["mask"] != "M_IL"]
        u = self.svc.put_content("u_admin", "lm2.json", "LAYERMAP",
                                 canonical_bytes(obj))
        for e in p["entries"]:
            if e["role"] == "LAYERMAP":
                e["logical_name"], e["sha256"] = u["logical_name"], u["sha256"]
        r = self.svc.import_release(p, "u_admin")
        codes = {f["code"] for f in r["findings"]}
        # M_IL 的 L200.0 失去映射 → MISSING_LAYER_MAPPING
        self.assertIn("MISSING_LAYER_MAPPING", codes)

    def test_same_logical_name_different_content_quarantined(self):
        a = self.svc.put_content("u_admin", "same.gds", "GDS", self.gds_bytes())
        b = self.svc.put_content("u_admin", "same.gds", "GDS",
                                 self.gds_bytes(((999, 0),)))
        self.assertFalse(a["quarantined"])
        self.assertTrue(b["quarantined"])

    def test_same_release_name_different_content_quarantined(self):
        p = self.valid_packet("S")
        r1 = self.svc.import_release(p, "u_admin")
        self.assertEqual(r1["status"], "VALID")
        p2 = json.loads(json.dumps(p))
        p2["scribe_um"] = 123
        r2 = self.svc.import_release(p2, "u_admin")
        self.assertEqual(r2["status"], "QUARANTINED")
        self.assertIn("RELEASE_NAME_COLLISION",
                      {f["code"] for f in r2["findings"]})
        q = next(x for x in self.svc.list_quarantine()
                 if x["reason"] == "RELEASE_NAME_COLLISION")
        self.svc.resolve_quarantine("u_admin", q["id"], "ACCEPT_AS_ALIAS",
                                    new_name=r2["release_name"] + "-ALT")
        rel = self.svc.get_release(r2["release_id"])
        self.assertEqual(rel["status"], "VALID")
        self.assertNotEqual(rel["delivery_no"], r1["delivery_no"])

    def test_gds_scanner_finds_layers(self):
        from mdc.domain import scan_gds_layers
        layers = scan_gds_layers(self.gds_bytes())
        self.assertEqual(layers, ["L100.0", "L101.0", "L200.0"])

    def test_gds_tamper_breaks_parse(self):
        from mdc.domain import scan_gds_layers, LayoutScanError
        with self.assertRaises(LayoutScanError):
            scan_gds_layers(self.gds_bytes()[:7] + b"\xff\xff")
