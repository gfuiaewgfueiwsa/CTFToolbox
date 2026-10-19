# -*- coding: utf-8 -*-
"""WebShell 流量取证分析（防御 / 蓝队 / CTF 取证向，纯离线）。

本模块只做“识别 + 解密 + 还原”：从 pcap 重组 HTTP 会话，识别常见 WebShell 管理工具
的通信指纹，解密其载荷并还原攻击者执行的命令 / 脚本，用于入侵取证、告警与 CTF 流量题。

明确不做（与工具箱《集成工具清单》边界一致）：
  - 不内置、不生成、不下发任何 WebShell 服务端马；
  - 不提供连接、发包、批量挂马 / 菜刀式文件管理能力；
  - 还原出的命令仅作为取证证据展示，不提供“一键重放 / 攻击”执行。

覆盖家族（均为公开协议特征）：
  1. 中国菜刀 China Chopper（z0/z1/z2 参数，base64 载荷）；
  2. 蚁剑 AntSword（antSword UA / 随机参数名，base64 PHP 载荷，响应随机前后缀）；
  3. 冰蝎 Behinder：
       v2 固定密钥 AES（默认 key=e45e3249cc9603fa，CBC，IV=key，body=base64(密文)）；
       v3 动态密钥（首包 16 字节明文 key，后续 AES，key 由协商密钥派生，裸二进制密文）；
  4. 顺带识别哥斯拉 Godzilla 的明显指纹（pass/key + base64 + 固定响应标记）。

输出写入 Report：家族、置信度、URL、UA、解密后的请求载荷 / 命令、响应明文，并落盘取证。
"""
import os
import re
import base64
import hashlib
from collections import defaultdict

from .common import Report, save_artifact, scan_flags, safe_name

# 冰蝎 v2 公开默认密钥（可在此扩展候选 key，不与任何具体题目绑定）
BEHINDER_V2_DEFAULT_KEYS = [
    b"e45e3249cc9603fa",
    b"rebeyond",            # 早期版本常见
    b"e45e3249cc9603fa\x00\x00\x00\x00\x00\x00\x00\x00",
]

# 蚁剑 PHP 载荷高辨识度片段（默认 / 常见编码器）
ANTSWORD_PHP_MARKERS = (
    '@ini_set("display_errors","0")',
    "@ini_set('display_errors','0')",
    "@set_time_limit(0)",
    "display_errors",
    "substr(md5(",
    "openssl_error_string",
)
# 菜刀载荷 / 参数特征
CHOPPER_PARAMS = ("z0", "z1", "z2")
# 哥斯拉指纹
GODZILLA_MARKERS = ("pass", "key", "Payload", "godzilla", "JavaPayload")

SHELL_EXT_RE = re.compile(r"\.(php|phtml|php5|jsp|jspx|asp|aspx|ashx|cer)(\?|$|/)", re.I)


# ============================================================================
# 基础工具
# ============================================================================
def _b64try(s):
    """宽松 base64 解码，失败返回 None。"""
    if not s:
        return None
    try:
        s = s.strip()
        pad = (-len(s)) % 4
        raw = base64.b64decode(s + "=" * pad, validate=False)
        return raw
    except Exception:
        return None


def _readable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    good = sum(1 for x in b if 9 <= x <= 13 or 32 <= x < 127 or x >= 0x80)
    return good / len(b)


def _text(b: bytes) -> str:
    if b is None:
        return ""
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            return b.decode(enc, "replace")
        except Exception:
            continue
    return repr(b)


def _aes_decrypt(cipher: bytes, key: bytes, mode: str, iv=None):
    try:
        from Crypto.Cipher import AES
    except Exception:
        return None
    if len(cipher) % 16 != 0 or len(cipher) == 0:
        return None
    for k in (_pad16(key), key[:16], key[:32]):
        if len(k) not in (16, 24, 32):
            continue
        try:
            if mode == "CBC":
                ivv = iv if iv and len(iv) == 16 else k[:16]
                pt = AES.new(k, AES.MODE_CBC, ivv).decrypt(cipher)
            else:
                pt = AES.new(k, AES.MODE_ECB).decrypt(cipher)
            pad = pt[-1]
            if 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad:
                pt = pt[:-pad]
            if _readable_ratio(pt) > 0.85 and any(c in pt for c in
                                                  (b"eval", b"system", b"exec", b"status",
                                                   b"cmd", b"{", b"<?", b"assert", b"base64")):
                return pt
        except Exception:
            continue
    return None


def _pad16(k: bytes) -> bytes:
    if len(k) >= 16:
        return k[:16]
    return k + b"\0" * (16 - len(k))


# ============================================================================
# HTTP 重组（按会话方向，支持 keep-alive 多请求 / Content-Length / chunked）
# ============================================================================
def _split_messages(buf: bytes, is_response: bool):
    """从一条方向字节流里切出若干 HTTP 消息的 (header_bytes, body_bytes, consumed)。"""
    msgs = []
    off = 0
    while True:
        sep = buf.find(b"\r\n\r\n", off)
        if sep < 0:
            break
        head = buf[off:sep]
        lines = head.split(b"\r\n")
        first = lines[0].decode("latin-1", "replace")
        if is_response and not first.startswith("HTTP/"):
            break
        if not is_response and not re.match(r"^[A-Z]{3,7} [^ ]+ HTTP/\d\.\d", first):
            break
        headers = {}
        for ln in lines[1:]:
            if b":" in ln:
                k, v = ln.split(b":", 1)
                headers[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1", "replace")
        body_start = sep + 4
        te = headers.get("transfer-encoding", "").lower()
        body = b""
        nxt = body_start
        if "chunked" in te:
            raw = buf[body_start:]
            decoded, used = _unchunk(raw)
            body = decoded
            nxt = body_start + used
        else:
            try:
                clen = int(headers.get("content-length", "0"))
            except ValueError:
                clen = 0
            if clen > 0:
                body = buf[body_start:body_start + clen]
                nxt = body_start + clen
                if len(body) < clen:        # 没收全
                    break
        msgs.append((first, headers, body))
        off = nxt
        if off >= len(buf):
            break
    return msgs


def _unchunk(raw: bytes):
    out = b""
    off = 0
    while True:
        nl = raw.find(b"\r\n", off)
        if nl < 0:
            break
        try:
            size = int(raw[off:nl].split(b";")[0], 16)
        except ValueError:
            break
        if size == 0:
            off = nl + 2
            if raw[off:off + 2] == b"\r\n":
                off += 2
            break
        out += raw[nl + 2:nl + 2 + size]
        off = nl + 2 + size + 2
    return out, off


def reassemble_http(path: str):
    """返回 [(meta, request(first,headers,body), response(first,headers,body) or None), ...]。"""
    try:
        from scapy.all import PcapReader, PcapNgReader, TCP, IP, IPv6, Raw
    except Exception:
        return []
    reader = None
    try:
        reader = (PcapNgReader(path) if open(path, "rb").read(4) == b"\x0a\x0d\x0d\x0a"
                  else PcapReader(path))
    except Exception:
        return []
    # 会话 key（端点排序）-> 每方向 seq->payload，并记录谁先发包（客户端）
    c2s = defaultdict(dict)
    s2c = defaultdict(dict)
    client_of = {}
    try:
        for pkt in reader:
            try:
                if TCP not in pkt or not (IP in pkt or IPv6 in pkt):
                    continue
                ip = pkt[IP] if IP in pkt else pkt[IPv6]
                t = pkt[TCP]
                a, b = (ip.src, t.sport), (ip.dst, t.dport)
                key = tuple(sorted([a, b]))
                payload = bytes(t.payload)
                flags = t.flags
                if (flags & 0x02) and not (flags & 0x10):   # 纯 SYN（非 SYN-ACK）-> 客户端
                    client_of[key] = a
                if a == client_of.get(key) or (key not in client_of and payload[:3] in
                                               (b"GET", b"POS", b"PUT", b"HEA", b"OPT")):
                    if key not in client_of:
                        client_of[key] = a
                    if payload:
                        c2s[key][t.seq] = payload
                else:
                    if payload:
                        s2c[key][t.seq] = payload
            except Exception:
                continue
    finally:
        try:
            reader.close()
        except Exception:
            pass

    out = []
    for key, reqsegs in c2s.items():
        req_stream = b"".join(reqsegs[s] for s in sorted(reqsegs))
        resp_stream = b"".join(s2c[key][s] for s in sorted(s2c[key])) if key in s2c else b""
        reqs = _split_messages(req_stream, False)
        resps = _split_messages(resp_stream, True)
        for i, req in enumerate(reqs):
            resp = resps[i] if i < len(resps) else None
            out.append(({"key": key}, req, resp))
    return out


# ============================================================================
# 载荷检测 / 解密
# ============================================================================
def _urlparse_body(body: bytes, ctype: str):
    """application/x-www-form-urlencoded -> {参数: 值(bytes 原文)}。"""
    params = {}
    try:
        from urllib.parse import parse_qsl
        for k, v in parse_qsl(body.decode("latin-1", "replace"), keep_blank_values=True):
            params[k] = v.encode("latin-1", "replace")
    except Exception:
        pass
    return params


def detect_chopper(params, body, ctype, ua):
    """菜刀：z0/z1/z2，z0 base64 解码为脚本/命令。"""
    hits = []
    keys = set(params.keys())
    if "z0" in keys and ({"z1"} & keys or len(body) > 20):
        z0 = params.get("z0", b"")
        dec = _b64try(z0.decode("latin-1", "replace"))
        if dec is not None and (_readable_ratio(dec) > 0.7 or b"eval" in dec or b"exec" in dec):
            z1 = _b64try(params.get("z1", b"").decode("latin-1", "replace"))
            hits.append({
                "family": "中国菜刀 China Chopper",
                "confidence": "高",
                "decrypted_request": _text(dec),
                "working_dir": _text(z1) if z1 else "",
            })
    return hits


def detect_antsword(params, body, ctype, ua, resp_body):
    """蚁剑：UA 或 base64 参数载荷特征 + 响应随机前后缀。"""
    hits = []
    ua_hit = "antsword" in ua.lower()
    decoded_blobs = []
    for k, v in params.items():
        vs = v.decode("latin-1", "replace")
        dec = _b64try(vs)
        if dec and len(dec) >= 12:
            txt = _text(dec)
            score = sum(1 for m in ANTSWORD_PHP_MARKERS if m in txt)
            if ua_hit or score >= 2 or (score >= 1 and ("eval" in txt or "assert" in txt)):
                decoded_blobs.append((k, txt))
    # 非表单（raw base64 body）
    if ua_hit and not decoded_blobs:
        dec = _b64try(body.decode("latin-1", "replace").strip())
        if dec and _readable_ratio(dec) > 0.7:
            decoded_blobs.append(("(raw)", _text(dec)))
    if decoded_blobs:
        resp_clean = _strip_antsword_response(resp_body)
        hits.append({
            "family": "蚁剑 AntSword",
            "confidence": "高" if ua_hit else "中",
            "decrypted_request": "\n".join(f"[{k}] {t}" for k, t in decoded_blobs)[:4000],
            "decrypted_response": resp_clean[:4000],
        })
    return hits


def _strip_antsword_response(resp_body: bytes) -> str:
    """蚁剑默认在结果外裹随机字符 / base64；尽力还原可读结果。"""
    if not resp_body:
        return ""
    txt = resp_body.decode("latin-1", "replace").strip()
    # 形如  <16位md5片段><结果><16位md5片段> 或随机前后缀，尝试 base64
    dec = _b64try(txt)
    if dec and _readable_ratio(dec) > 0.85:
        return _text(dec)
    # 去掉首尾成对的随机包裹（常见为固定长度随机串）
    m = re.match(r"^[0-9a-fA-F]{16}([\s\S]*?)[0-9a-fA-F]{16}$", txt)
    if m:
        return m.group(1)
    return txt


def detect_behinder(method, path, headers, body, resp_body):
    """冰蝎 v2/v3。返回命中 dict 列表。"""
    hits = []
    ctype = headers.get("content-type", "")
    lower_path = path.lower()
    is_shell_path = bool(SHELL_EXT_RE.search(path))

    # ---- v2：body=base64(AES-CBC(key,IV=key, 明文)) ----
    if body and len(body) > 24:
        candidate = body.strip()
        cipher = _b64try(candidate.decode("latin-1", "replace"))
        if cipher and len(cipher) % 16 == 0:
            for key in BEHINDER_V2_DEFAULT_KEYS:
                for mode in ("CBC", "ECB"):
                    pt = _aes_decrypt(cipher, key, mode)
                    if pt:
                        resp_pt = _decrypt_behinder_response(resp_body, key, mode)
                        hits.append({
                            "family": f"冰蝎 Behinder v2（固定密钥 {key.decode(errors='replace')}，AES-{mode}）",
                            "confidence": "高",
                            "decrypted_request": _text(pt)[:4000],
                            "decrypted_response": resp_pt[:4000],
                        })
                        return hits

    # ---- v3：首包 16 字节明文协商密钥，后续裸二进制 AES ----
    # 由会话层调用 detect_behinder_v3_session 处理（需要跨请求状态），此处仅标记疑似首包
    if is_shell_path and body and len(body.strip()) == 16:
        k = body.strip()
        if sum(1 for x in k if (48 <= x <= 57) or (65 <= x <= 90) or (97 <= x <= 122)) >= 14:
            hits.append({
                "family": "冰蝎 Behinder v3（疑似动态密钥协商首包）",
                "confidence": "中",
                "negotiated_key": k.decode("latin-1", "replace"),
                "decrypted_request": "首包为 16 字节协商密钥，后续 AES 载荷需在同会话内解密",
            })
    return hits


def _decrypt_behinder_response(resp_body, key, mode):
    if not resp_body:
        return ""
    cipher = _b64try(resp_body.decode("latin-1", "replace").strip())
    if cipher and len(cipher) % 16 == 0:
        pt = _aes_decrypt(cipher, key, mode)
        if pt:
            return _text(pt)
    if len(resp_body) % 16 == 0:
        pt = _aes_decrypt(resp_body, key, mode)
        if pt:
            return _text(pt)
    return ""


def detect_behinder_v3_session(messages):
    """对同一路径的请求序列做 v3 动态密钥解密。messages=[(headers,body,resp), ...]。"""
    hits = []
    key = None
    for headers, body, resp in messages:
        body = body or b""
        if key is None and len(body.strip()) == 16:
            k = body.strip()
            if sum(1 for x in k if (48 <= x <= 57) or (65 <= x <= 90) or (97 <= x <= 122)) >= 14:
                key = k
                continue
        if key and body and len(body) % 16 == 0 and len(body) >= 16:
            # 冰蝎3 PHP: AES key = md5(协商key) 前16；JSP/.NET: AES key = 协商key 本身
            cand_keys = [hashlib.md5(key).hexdigest()[:16].encode(), key,
                         hashlib.md5(key).digest()]
            for kk in cand_keys:
                pt = _aes_decrypt(body, kk, "CBC") or _aes_decrypt(body, kk, "ECB")
                if pt:
                    rpt = ""
                    if resp and len(resp) % 16 == 0:
                        rpt = _text(_aes_decrypt(resp, kk, "CBC") or _aes_decrypt(resp, kk, "ECB") or b"")
                    hits.append({
                        "family": "冰蝎 Behinder v3（动态密钥 AES）",
                        "confidence": "高",
                        "negotiated_key": key.decode("latin-1", "replace"),
                        "decrypted_request": _text(pt)[:4000],
                        "decrypted_response": rpt[:4000],
                    })
                    break
    return hits


def detect_godzilla(params, body, ctype, ua, resp_body):
    """哥斯拉明显指纹（保守识别，避免误报）。"""
    hits = []
    txt = body.decode("latin-1", "replace")
    if "pass" in params and "key" in params:
        dec = _b64try(params.get("pass", b"").decode("latin-1", "replace"))
        if dec:
            hits.append({
                "family": "哥斯拉 Godzilla（疑似）",
                "confidence": "中",
                "decrypted_request": _text(dec)[:4000],
            })
    return hits


# ============================================================================
# 单 HTTP 事务检测 + 会话级 v3 关联
# ============================================================================
def inspect_transaction(method, path, headers, body, resp_body):
    ctype = headers.get("content-type", "")
    ua = headers.get("user-agent", "")
    params = _urlparse_body(body, ctype) if "urlencoded" in ctype or body.count(b"=") else {}
    findings = []
    findings += detect_chopper(params, body, ctype, ua)
    findings += detect_antsword(params, body, ctype, ua, resp_body)
    findings += detect_behinder(method, path, headers, body, resp_body)
    findings += detect_godzilla(params, body, ctype, ua, resp_body)
    for f in findings:
        f.setdefault("url", path)
        f.setdefault("method", method)
        f.setdefault("ua", ua)
    return findings


def analyze_pcap(path: str, report: Report, outdir: str):
    """重组 pcap 中的 HTTP 并做 WebShell 取证；无命中静默返回。"""
    try:
        txs = reassemble_http(path)
    except Exception as e:
        report.add("warn", "WebShell 取证重组失败", f"{type(e).__name__}: {e}")
        return False
    if not txs:
        return False

    all_findings = []
    # 按 path 聚合请求体，供冰蝎 v3 会话级解密
    by_path = defaultdict(list)
    for _meta, req, resp in txs:
        first, headers, body = req
        m = re.match(r"^(\S+) (\S+)", first)
        method, url = (m.group(1), m.group(2)) if m else ("?", first)
        rbody = resp[2] if resp else b""
        by_path[url.split("?")[0]].append((headers, body, rbody))
        for f in inspect_transaction(method, url, headers, body, rbody):
            all_findings.append(f)

    # 冰蝎 v3：同路径会话序列
    for url, msgs in by_path.items():
        if len(msgs) >= 2 and SHELL_EXT_RE.search(url):
            for f in detect_behinder_v3_session(msgs):
                f["url"] = url
                all_findings.append(f)

    if not all_findings:
        return False

    ws_dir = os.path.join(outdir, "webshell_forensics")
    os.makedirs(ws_dir, exist_ok=True)
    lines = []
    families = defaultdict(int)
    for i, f in enumerate(all_findings):
        families[f["family"]] += 1
        block = [f"#{i} 【{f['family']}】 置信度={f.get('confidence','?')}",
                 f"  {f.get('method','')} {f.get('url','')}",
                 f"  UA: {f.get('ua','')}"]
        if f.get("negotiated_key"):
            block.append(f"  协商密钥: {f['negotiated_key']}")
        if f.get("working_dir"):
            block.append(f"  工作目录: {f['working_dir']}")
        if f.get("decrypted_request"):
            block.append("  --- 解密请求载荷 ---")
            block.append("  " + f["decrypted_request"].replace("\n", "\n  "))
        if f.get("decrypted_response"):
            block.append("  --- 解密响应(命令回显) ---")
            block.append("  " + f["decrypted_response"].replace("\n", "\n  "))
        lines.append("\n".join(block))
        for fl in scan_flags((f.get("decrypted_request", "") +
                              f.get("decrypted_response", "")).encode("utf-8", "replace")):
            report.add("flag", f"WebShell({f['family']}) 载荷中发现 flag", fl)

    summary = "; ".join(f"{k} x{v}" for k, v in families.items())
    fp = os.path.join(ws_dir, "webshell_findings.txt")
    save_artifact(fp, ("\n\n".join(lines)).encode("utf-8", "replace"))
    report.extracted.append(fp)
    report.add("flag" if any("flag" in l.lower() for l in lines) else "ok",
               f"检测到 WebShell 管理工具通信（{len(all_findings)} 条）",
               f"{summary}\n详见: {fp}", fp)
    return True
