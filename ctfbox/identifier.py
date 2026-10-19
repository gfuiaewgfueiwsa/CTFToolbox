# -*- coding: utf-8 -*-
"""文件类型识别：magic 签名 + 扩展名 + 文本探测 + 熵。"""
import os
import struct
from dataclasses import dataclass
from typing import Optional
from .common import shannon_entropy, try_decode_text

# (偏移, 签名bytes, 类型名, 大类)
MAGICS = [
    (0, b"MZ",                       "PE可执行文件(Windows)", "executable"),
    (0, b"\x7fELF",                  "ELF可执行文件(Linux/pwn)", "executable"),
    (0, b"\xfe\xed\xfa\xce",         "Mach-O 32位(macOS)", "executable"),
    (0, b"\xfe\xed\xfa\xcf",         "Mach-O 64位(macOS)", "executable"),
    (0, b"\xcf\xfa\xed\xfe",         "Mach-O 64位(macOS)", "executable"),
    (0, b"\xca\xfe\xba\xbe",         "Java class/胖二进制", "executable"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE复合文档(doc/xls/msi)", "document"),
    (0, b"PK\x03\x04",               "ZIP压缩包(zip/jar/apk/xlsx/docx)", "archive"),
    (0, b"PK\x05\x06",               "ZIP空包/分卷尾", "archive"),
    (0, b"Rar!\x1a\x07\x00",         "RAR压缩包(RAR4)", "archive"),
    (0, b"Rar!\x1a\x07\x01\x00",     "RAR压缩包(RAR5)", "archive"),
    (0, b"7z\xbc\xaf\x27\x1c",       "7z压缩包", "archive"),
    (0, b"\x1f\x8b",                 "GZIP压缩包", "archive"),
    (0, b"BZh",                      "BZIP2压缩包", "archive"),
    (0, b"\xfd7zXZ\x00",             "XZ压缩包", "archive"),
    (0, b"ZST",                      "Zstandard压缩包", "archive"),
    (0, b"(\xb5/\xfd",               "Zstandard压缩包", "archive"),
    (0, b"!<arch>\n",                "ar静态库/deb", "archive"),
    (257, b"ustar",                  "TAR归档", "archive"),
    (0, b"\x89PNG\r\n\x1a\n",        "PNG图片", "image"),
    (0, b"\xff\xd8\xff",             "JPEG图片", "image"),
    (0, b"GIF87a",                   "GIF图片", "image"),
    (0, b"GIF89a",                   "GIF图片", "image"),
    (0, b"BM",                       "BMP图片", "image"),
    (0, b"II*\x00",                  "TIFF图片", "image"),
    (0, b"MM\x00*",                  "TIFF图片", "image"),
    (0, b"RIFF",                     "RIFF容器(需进一步判断webp/wav/avi)", "media"),
    (0, b"\x00\x00\x01\x00",         "ICO图标", "image"),
    (0, b"\x00\x00\x02\x00",         "CUR光标", "image"),
    (0, b"fLaC",                     "FLAC音频", "media"),
    (0, b"ID3",                      "MP3音频", "media"),
    (0, b"\xff\xfb",                 "MP3音频", "media"),
    (0, b"OggS",                     "OGG音视频", "media"),
    (4, b"ftyp",                     "MP4/MOV视频(ISO-BMFF)", "media"),
    (0, b"\x1aE\xdf\xa3",           "MKV/WebM 视频(EBML)", "media"),
    (0, b"FLV",                      "FLV 视频", "media"),
    (0, b"FWS",                      "SWF Flash(未压缩)", "media"),
    (0, b"CWS",                      "SWF Flash(zlib压缩)", "media"),
    (0, b"%PDF",                     "PDF文档", "document"),
    (0, b"\xd4\xc3\xb2\xa1",         "PCAP流量包(小端)", "capture"),
    (0, b"\xa1\xb2\xc3\xd4",         "PCAP流量包(大端)", "capture"),
    (0, b"\x4d\x3c\xb2\xa1",         "PCAP流量包(纳秒)", "capture"),
    (0, b"\x0a\x0d\x0d\x0a",         "PCAPNG流量包", "capture"),
    (0, b"btsnoop\x00",              "Android蓝牙HCI日志(btsnoop)", "capture"),
    (0, b"SQLite format 3\x00",      "SQLite数据库", "database"),
    (0, b"-----BEGIN ",              "PEM密钥/证书", "crypto"),
    (0, b"ssh-rsa ",                 "SSH公钥", "crypto"),
    (0, b"ssh-ed25519 ",             "SSH公钥", "crypto"),
    (0, b"ecdsa-",                   "SSH公钥", "crypto"),
    (0, b"openpgp",                  "OpenPGP数据", "crypto"),
    (0, b"BitLocker",                "BitLocker加密卷", "crypto"),
    (0, b"TRUE",                     "TrueCrypt加密卷(疑似)", "crypto"),
    (0, b"regf",                     "Windows注册表hive", "forensic"),
    (0, b"ElfFile\x00",             "Windows事件日志evtx", "forensic"),
    (0, b"KDMV",                     "VMDK虚拟磁盘", "forensic"),
    (0, b"conectix",                 "VHD虚拟磁盘", "forensic"),
    (0, b"EVPV",                     "Windows密码缓存", "forensic"),
    (0, b"ntfshibern",              "Windows休眠文件", "forensic"),
    (0, b"hadoop",                   "未知容器", "unknown"),
]

# RIFF 细分
def _riff_subtype(head: bytes) -> Optional[str]:
    if len(head) >= 12 and head[:4] == b"RIFF":
        f = head[8:12]
        return {b"WAVE": "WAV音频", b"WEBP": "WEBP图片", b"AVI ": "AVI视频"}.get(f)
    return None

EXT_HINT = {
    ".pcap": ("PCAP流量包", "capture"), ".pcapng": ("PCAPNG流量包", "capture"),
    ".cap": ("抓包文件", "capture"),
    ".btsnoop": ("蓝牙btsnoop日志", "capture"), ".hci": ("蓝牙HCI日志", "capture"),
    ".h4": ("蓝牙HCI H4日志", "capture"),
    ".jpg": ("JPEG图片", "image"), ".jpeg": ("JPEG图片", "image"),
    ".png": ("PNG图片", "image"), ".gif": ("GIF图片", "image"),
    ".bmp": ("BMP图片", "image"), ".webp": ("WEBP图片", "image"),
    ".tif": ("TIFF图片", "image"), ".tiff": ("TIFF图片", "image"),
    ".zip": ("ZIP压缩包", "archive"), ".jar": ("JAR(zip)", "archive"),
    ".apk": ("APK(zip)", "archive"), ".rar": ("RAR压缩包", "archive"),
    ".7z": ("7z压缩包", "archive"), ".gz": ("GZIP", "archive"),
    ".bz2": ("BZIP2", "archive"), ".xz": ("XZ", "archive"),
    ".tar": ("TAR归档", "archive"), ".zst": ("ZSTD", "archive"),
    ".exe": ("PE可执行文件", "executable"), ".dll": ("PE DLL", "executable"),
    ".sys": ("PE驱动", "executable"), ".elf": ("ELF", "executable"),
    ".so": ("ELF共享库", "executable"), ".bin": ("裸二进制", "unknown"),
    ".class": ("Java class", "executable"), ".pyc": ("Python字节码", "executable"),
    ".pdf": ("PDF文档", "document"),
    ".doc": ("Word文档", "document"), ".xls": ("Excel文档", "document"),
    ".docx": ("Word文档(zip)", "document"), ".xlsx": ("Excel文档(zip)", "document"),
    ".db": ("数据库", "database"), ".sqlite": ("SQLite数据库", "database"),
    ".sqlite3": ("SQLite数据库", "database"),
    ".txt": ("文本文件", "text"), ".log": ("日志文本", "text"),
    ".pcap": ("PCAP", "capture"),
    # 取证 / 镜像 / 逆向
    ".vmdk": ("VMDK虚拟磁盘", "forensic"), ".vhd": ("VHD虚拟磁盘", "forensic"),
    ".vhdx": ("VHDX虚拟磁盘", "forensic"), ".vdi": ("VDI虚拟磁盘", "forensic"),
    ".ova": ("OVA虚拟设备", "forensic"), ".img": ("磁盘/内存镜像", "forensic"),
    ".raw": ("原始镜像", "forensic"), ".dd": ("dd镜像", "forensic"),
    ".e01": ("E01取证镜像", "forensic"), ".swp": ("vim交换文件", "forensic"),
    ".swo": ("vim交换文件", "forensic"), ".swn": ("vim交换文件", "forensic"),
    ".asar": ("Electron ASAR归档", "forensic"),
    ".evtx": ("Windows事件日志", "forensic"),
    ".pyc": ("Python字节码", "executable"), ".pyo": ("Python字节码", "executable"),
}


@dataclass
class FileInfo:
    path: str
    size: int
    ftype: str
    category: str
    entropy: float
    is_text: bool
    encoding: Optional[str]
    head_hex: str
    ext: str
    extra: dict

    def summary(self):
        return f"{self.ftype} | {self.category} | 熵={self.entropy:.3f} | {self.size}字节"


def identify(path: str, head_limit: int = 4096) -> FileInfo:
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        head = f.read(head_limit)
    ext = os.path.splitext(path)[1].lower()

    ftype, category = "未知二进制", "unknown"
    extra = {}

    for off, sig, name, cat in MAGICS:
        if len(head) >= off + len(sig) and head[off:off + len(sig)] == sig:
            ftype, category = name, cat
            break

    # RIFF 细分
    sub = _riff_subtype(head)
    if sub:
        ftype = sub
        category = "image" if "图片" in sub else "media"

    # JPEG 缩略图/EXIF 等不动；ZIP 内空包等情况交给 archive 模块

    # 文本探测（无签名或扩展名是文本类）
    is_text, enc, _ = (False, None, None)
    if category in ("unknown",):
        is_text, enc, _ = try_decode_text(head)
        if is_text:
            ftype, category = f"文本文件({enc})", "text"

    # 扩展名兜底提示（签名冲突时记录）
    if ext in EXT_HINT:
        ename, ecat = EXT_HINT[ext]
        if category == "unknown":
            ftype, category = ename + "(按扩展名)", ecat
        extra["ext_hint"] = ename

    # 熵（小文件全量，大文件头部+采样）
    if size <= 2 * 1024 * 1024:
        with open(path, "rb") as f:
            data = f.read()
    else:
        with open(path, "rb") as f:
            data = f.read(2 * 1024 * 1024)
    ent = shannon_entropy(data)
    extra["high_entropy"] = ent > 7.5

    # 加密/压缩无签名疑似
    if category == "unknown" and ent > 7.9 and size > 1024:
        extra["suspect_encrypted"] = True
        ftype = "高熵未知数据(疑似加密/压缩/镜像)"

    return FileInfo(
        path=path, size=size, ftype=ftype, category=category, entropy=ent,
        is_text=is_text, encoding=enc,
        head_hex=head[:64].hex(" "), ext=ext, extra=extra,
    )
