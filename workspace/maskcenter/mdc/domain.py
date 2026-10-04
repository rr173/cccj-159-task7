"""领域通用：错误码、规范化指纹、GDSII/OASIS 层清单解析。"""
from __future__ import annotations

import hashlib
import json
import struct
from typing import Any

# ---------------------------------------------------------------- 错误
class DomainError(Exception):
    """所有业务拒收都带稳定原因码，便于 CLI/API/界面定位。"""

    def __init__(self, code: str, message: str, http_status: int = 409, detail: Any = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status
        self.detail = detail if detail is not None else {}


# ---------------------------------------------------------------- 规范化
def canonical_bytes(obj: Any) -> bytes:
    """确定性 JSON：sort_keys + 无多余空白 + 无 ASCII 转义差异。"""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def canonical_hash(obj: Any) -> str:
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()


def delivery_number(canonical_hex: str) -> str:
    """完整资料规范化后的稳定交付编号：MS- + 16 位 base32hex（0-9A-V）。

    同一规范化资料永远得到同一编号；编号即身份，重复导入不复制实体。
    """
    digest = hashlib.sha256(b"maskcenter/delivery/v1\x00" + bytes.fromhex(canonical_hex)).digest()
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
    n = int.from_bytes(digest[:10], "big")
    out = []
    for _ in range(16):
        out.append(alphabet[n & 31])
        n >>= 5
    return "MS-" + "".join(reversed(out))


# ---------------------------------------------------------------- GDSII 最小解析
# GDSII 记录：2 字节大端长度（含长度自身），1 字节 rectype，1 字节 datatype，
# 后接 (len-4) 字节数据。我们只需要版面里出现的 (layer, datatype) 组合。
_GDS_NO_DATA = {0x00, 0x01, 0x03, 0x06}          # HEADER/BGNLIB/LIBNAME 等不关心
_GDS_REC_LAYER = 0x0D
_GDS_REC_DATATYPE = 0x0E
_GDS_REC_XY = 0x10
_GDS_REC_ENDEL = 0x11
_GDS_REC_BOUNDARY = 0x08
_GDS_REC_PATH = 0x09
_GDS_REC_SREF = 0x0A
_GDS_REC_AREF = 0x0B
_GDS_REC_TEXT = 0x0C
_GDS_REC_BOX = 0x2D
_ELEMENT_RECS = {_GDS_REC_BOUNDARY, _GDS_REC_PATH, _GDS_REC_SREF,
                 _GDS_REC_AREF, _GDS_REC_TEXT, _GDS_REC_BOX}
# SREF/AREF 不带 LAYER/DATATYPE（结构引用），跳过收集
_LAYERED_ELEMENTS = {_GDS_REC_BOUNDARY, _GDS_REC_PATH, _GDS_REC_TEXT, _GDS_REC_BOX}


class LayoutScanError(Exception):
    pass


def scan_gds_layers(data: bytes) -> list[str]:
    """提取 GDSII 中实际使用的 "L<layer>.<datatype>" 清单（排序去重）。

    解析器只做最小结构遍历：长度不合法即判定为损坏/被篡改。
    """
    layers: set[tuple[int, int]] = set()
    pos = 0
    n = len(data)
    in_layered = False
    cur_layer = None
    cur_dt = 0
    # 至少要有 HEADER + BGNLIB + LIBNAME... 不做强校验，按记录流扫描
    if n < 4:
        raise LayoutScanError("GDS_TOO_SHORT")
    while pos + 4 <= n:
        (rlen,) = struct.unpack_from(">H", data, pos)
        if rlen < 4 or pos + rlen > n:
            raise LayoutScanError(f"GDS_BAD_RECORD_AT_{pos}")
        rtype = data[pos + 2]
        rdtype = data[pos + 3]
        body = data[pos + 4:pos + rlen]
        if rtype in _ELEMENT_RECS:
            in_layered = rtype in _LAYERED_ELEMENTS
            cur_layer, cur_dt = None, 0
        elif rtype == _GDS_REC_ENDEL:
            in_layered = False
        elif in_layered and rtype == _GDS_REC_LAYER and rdtype == 0x02 and len(body) >= 2:
            cur_layer = struct.unpack(">h", body[:2])[0]
        elif in_layered and rtype == _GDS_REC_DATATYPE and rdtype == 0x02 and len(body) >= 2:
            cur_dt = struct.unpack(">h", body[:2])[0]
        elif in_layered and rtype == _GDS_REC_XY:
            if cur_layer is not None:
                layers.add((cur_layer, cur_dt))
            in_layered = False
        pos += rlen
    if pos != n:
        raise LayoutScanError(f"GDS_TRAILING_BYTES_{pos}_OF_{n}")
    return [f"L{l}.{d}" for (l, d) in sorted(layers)]


def scan_oasis_layers(data: bytes) -> list[str] | None:
    """OASIS 不解析压缩流；仅识别我们自己的 sidecar 清单。

    真实产线由 DRC/lvlp 工具产出层清单；本中心要求随附
    `<name>.layers.json`（["L100.0", ...]）。没有清单时返回 None，
    由调用方决定按声明信息放行/告警。
    """
    return None


def parse_layer_inventory(raw: bytes | str) -> list[str]:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    obj = json.loads(raw)
    if not isinstance(obj, list) or not all(isinstance(x, str) for x in obj):
        raise LayoutScanError("INVENTORY_NOT_STRING_LIST")
    return sorted(set(obj))


def build_gds_for_test(layers: list[tuple[int, int]]) -> bytes:
    """测试辅助：合成一个最小合法 GDSII，含 HEADER/BGNLIB/LIBNAME/UNITS/
    BGNSTR/STRNAME/各 (BOUNDARY,LAYER,DATATYPE,XY,ENDEL)/ENDSTR/ENDLIB。"""
    def rec(rtype: int, rdtype: int, body: bytes = b"") -> bytes:
        return struct.pack(">HBB", 4 + len(body), rtype, rdtype) + body

    def str_name(s: str, rtype: int) -> bytes:
        b = s.encode("ascii")
        if len(b) % 2:
            b += b"\0"
        return rec(rtype, 0x06, b)

    out = rec(0x00, 0x02, struct.pack(">h", 600))          # HEADER 6.0
    out += rec(0x01, 0x02, struct.pack(">12h", 2026, 1, 1, 0, 0, 0,
                                       2026, 1, 1, 0, 0, 0))  # BGNLIB
    out += str_name("TESTLIB", 0x02)                        # LIBNAME
    out += rec(0x03, 0x05, struct.pack(">2d", 0.001, 1e-9))  # UNITS
    out += rec(0x05, 0x02, struct.pack(">12h", 2026, 1, 1, 0, 0, 0,
                                       2026, 1, 1, 0, 0, 0))  # BGNSTR
    out += str_name("TOP", 0x06)                            # STRNAME
    for (layer, dt) in layers:
        out += rec(0x08, 0x00)                              # BOUNDARY
        out += rec(0x0D, 0x02, struct.pack(">h", layer))    # LAYER
        out += rec(0x0E, 0x02, struct.pack(">h", dt))       # DATATYPE
        out += rec(0x10, 0x03, struct.pack(">8i", 0, 0, 1000, 0, 1000, 1000, 0, 1000))
        out += rec(0x11, 0x00)                              # ENDEL
    out += rec(0x07, 0x00)                                  # ENDSTR
    out += rec(0x04, 0x00)                                  # ENDLIB
    return out
