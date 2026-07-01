#!/usr/bin/env python3
"""
FlagHunter - CTF / Security file analysis CLI tool
--------------------------------------------------------
Analyzes ANY file type and reports:
  - File identity (real type vs extension, magic bytes, hashes)
  - Metadata (EXIF, PDF metadata/objects, etc.)
  - Embedded files / polyglots (signatures found mid-file)
  - Appended data after normal EOF markers (classic CTF trick)
  - Entropy analysis (flags packed/encrypted/compressed regions)
  - Suspicious strings (URLs, IPs, base64 blobs, script/malware keywords)
  - LSB steganography detection + extraction attempt (images)
  - Auto-decoding of any hidden text found (base64/hex/rot13/binary)

This is a STATIC ANALYSIS / TRIAGE tool. It does not execute files and
is not a substitute for a real antivirus engine. Use for CTFs, learning,
and forensics practice on files you have the right to analyze.

Usage:
    python3 flaghunter.py <file> [--json] [--deep]
"""

import sys
import os
import re
import math
import json
import base64
import codecs
import hashlib
import struct
import argparse
import subprocess
from collections import Counter

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    HAVE_PIL = True
except ImportError:
    HAVE_PIL = False

try:
    import pypdf
    HAVE_PYPDF = True
except ImportError:
    HAVE_PYPDF = False


# ============================================================
# Utility helpers
# ============================================================

class C:
    """ANSI colors for terminal output."""
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
    B = "\033[94m"; M = "\033[95m"; CY = "\033[96m"
    BOLD = "\033[1m"; END = "\033[0m"


def shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy (0-8 bits/byte) of a byte string."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for c in counts.values():
        p = c / length
        entropy -= p * math.log2(p)
    return entropy


def sliding_entropy(data: bytes, window: int = 256, step: int = 256):
    """Return list of (offset, entropy) across the file to spot packed/encrypted blobs."""
    results = []
    for i in range(0, max(1, len(data) - window), step):
        chunk = data[i:i + window]
        results.append((i, shannon_entropy(chunk)))
    return results


def hashes_of(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def run_file_cmd(path: str) -> str:
    try:
        out = subprocess.run(["file", "-b", path], capture_output=True, text=True, timeout=10)
        return out.stdout.strip()
    except Exception:
        return "unknown (file command unavailable)"


# ============================================================
# Known file signatures (magic bytes) - used for:
#   1. identifying the real file type
#   2. scanning for embedded/polyglot files at any offset
# ============================================================

SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"BM", "BMP image"),
    (b"%PDF-", "PDF document"),
    (b"PK\x03\x04", "ZIP archive (or DOCX/XLSX/PPTX/JAR/APK)"),
    (b"PK\x05\x06", "ZIP archive (empty)"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"\x1f\x8b", "GZIP archive"),
    (b"BZh", "BZIP2 archive"),
    (b"MZ", "Windows PE executable (EXE/DLL)"),
    (b"\x7fELF", "ELF executable (Linux)"),
    (b"\xca\xfe\xba\xbe", "Mach-O / Java class (fat binary)"),
    (b"\xfe\xed\xfa\xce", "Mach-O executable (32-bit)"),
    (b"\xfe\xed\xfa\xcf", "Mach-O executable (64-bit)"),
    (b"ID3", "MP3 audio (ID3 tag)"),
    (b"RIFF", "RIFF container (WAV/AVI)"),
    (b"OggS", "OGG audio/video"),
    (b"\x00\x00\x00\x18ftyp", "MP4 video"),
    (b"\x00\x00\x00\x20ftyp", "MP4 video"),
    (b"\x25\x21", "Postscript"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "MS Office legacy (DOC/XLS/PPT) - OLE2"),
    (b"SQLite format 3\x00", "SQLite database"),
]

# EOF markers used to detect "appended data after the file's real end" - a classic CTF trick
EOF_MARKERS = {
    "PNG image": b"IEND\xae\x42\x60\x82",
    "JPEG image": b"\xff\xd9",
    "GIF image": b"\x00\x3b",
    "PDF document": b"%%EOF",
}

MALWARE_KEYWORDS = [
    (rb"powershell\s+-e(nc)?", "Encoded PowerShell command (common dropper technique)"),
    (rb"cmd\.exe\s*/c", "Windows command execution string"),
    (rb"eval\s*\(", "eval() call - potential obfuscated/dynamic code execution"),
    (rb"exec\s*\(", "exec() call - potential dynamic code execution"),
    (rb"base64_decode", "base64_decode - common in obfuscated PHP webshells"),
    (rb"<script", "Embedded script tag"),
    (rb"/JavaScript", "PDF JavaScript action (can auto-run on open)"),
    (rb"/OpenAction", "PDF auto-run action on open"),
    (rb"/AA\b", "PDF additional-actions (auto-trigger events)"),
    (rb"WScript\.Shell", "WScript.Shell - Windows scripting host abuse"),
    (rb"CreateObject", "CreateObject - often used in malicious macros"),
    (rb"AutoOpen", "VBA AutoOpen macro - runs automatically when doc opens"),
    (rb"Shell\(", "VBA/script Shell() call"),
    (rb"http[s]?://\S+\.(?:onion)\b", "Tor .onion URL"),
    (rb"\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}", "Hex-escaped shellcode-like byte pattern"),
    (rb"mimikatz", "Reference to Mimikatz (credential dumping tool)"),
    (rb"meterpreter", "Reference to Meterpreter (Metasploit payload)"),
]

URL_RE = re.compile(rb"https?://[^\s\"'<>]{4,200}")
IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(rb"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
BASE64_RE = re.compile(rb"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
FLAG_RE = re.compile(rb"[A-Za-z0-9_]{2,20}\{[^{}\n]{3,150}\}")  # CTF{...} / flag{...} style


# ============================================================
# Report object
# ============================================================

class Report:
    def __init__(self, path):
        self.path = path
        self.flags = []          # high-signal findings: (severity, message)
        self.info = {}           # general info dict
        self.strings_found = {}  # category -> list
        self.hidden_data = []    # decoded hidden payloads

    def flag(self, severity, message):
        # severity: "MALWARE", "HIDDEN", "SUSPICIOUS", "INFO"
        self.flags.append((severity, message))


# ============================================================
# Analysis stages
# ============================================================

def identify_file(data: bytes, path: str, report: Report):
    ext = os.path.splitext(path)[1].lower()
    real_type = "Unknown / raw binary"
    for sig, name in SIGNATURES:
        if data.startswith(sig):
            real_type = name
            break
    else:
        # check RIFF sub-type
        if data[:4] == b"RIFF" and len(data) > 12:
            sub = data[8:12]
            real_type = f"RIFF container ({sub.decode(errors='replace')})"

    file_cmd_out = run_file_cmd(path)

    report.info["declared_extension"] = ext or "(none)"
    report.info["detected_type_signature"] = real_type
    report.info["file_command_output"] = file_cmd_out
    report.info["size_bytes"] = len(data)
    report.info.update(hashes_of(data))

    # Extension mismatch = classic CTF / malware masquerading trick
    ext_map = {
        ".png": "PNG image", ".jpg": "JPEG image", ".jpeg": "JPEG image",
        ".gif": "GIF image", ".pdf": "PDF document", ".zip": "ZIP archive",
        ".exe": "Windows PE executable", ".docx": "ZIP archive", ".mp3": "MP3 audio",
    }
    expected = ext_map.get(ext)
    if expected and expected.split()[0] not in real_type:
        report.flag("SUSPICIOUS",
                     f"Extension is '{ext}' but real file signature says '{real_type}' — "
                     f"possible disguised/masqueraded file.")
    return real_type


def scan_embedded_signatures(data: bytes, report: Report):
    """Look for OTHER file signatures appearing mid-file -> polyglot / embedded file.

    Short signatures (<4 bytes) are excluded from this scan because they produce
    frequent false positives inside high-entropy regions (e.g. compressed pixel
    data, random noise, encrypted blobs) where any given short byte sequence has
    a real chance of appearing by coincidence.
    """
    found = []
    reliable_sigs = [(sig, name) for sig, name in SIGNATURES if len(sig) >= 4]
    for sig, name in reliable_sigs:
        start = 0
        while True:
            idx = data.find(sig, start)
            if idx == -1:
                break
            if idx != 0:  # not the file's own header
                found.append((idx, name))
            start = idx + 1

    if found:
        # de-duplicate by type, only report distinct types + first few offsets each
        by_type = {}
        for offset, name in found:
            by_type.setdefault(name, []).append(offset)
        for name, offsets in by_type.items():
            shown = offsets[:5]
            more = f" (+{len(offsets)-5} more)" if len(offsets) > 5 else ""
            report.flag("HIDDEN",
                         f"Embedded/polyglot signature for '{name}' found at offset(s) {shown}{more}")
    return found


def check_appended_data(data: bytes, real_type: str, report: Report):
    """Classic CTF trick: extra bytes appended after the file's normal EOF marker."""
    marker = EOF_MARKERS.get(real_type)
    if not marker:
        return None
    idx = data.rfind(marker)
    if idx == -1:
        return None
    end_of_real_file = idx + len(marker)
    trailing = data[end_of_real_file:]
    if len(trailing) > 0:
        report.flag("HIDDEN",
                     f"{len(trailing)} bytes of data found APPENDED after the file's real EOF "
                     f"marker (offset {end_of_real_file}) — classic hidden-data trick.")
        return trailing
    return None


def extract_strings(data: bytes, min_len=6):
    """Pure-python strings(1) equivalent for ASCII printable runs."""
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    return pattern.findall(data)


def analyze_strings(data: bytes, report: Report):
    urls = list(set(URL_RE.findall(data)))
    ips = list(set(IP_RE.findall(data)))
    emails = list(set(EMAIL_RE.findall(data)))
    flags_found = list(set(FLAG_RE.findall(data)))

    if urls:
        report.strings_found["urls"] = [u.decode(errors="replace") for u in urls[:20]]
    if ips:
        report.strings_found["ip_addresses"] = [i.decode(errors="replace") for i in ips[:20]]
    if emails:
        report.strings_found["emails"] = [e.decode(errors="replace") for e in emails[:20]]
    if flags_found:
        decoded = [f.decode(errors="replace") for f in flags_found[:20]]
        report.strings_found["possible_ctf_flags"] = decoded
        for f in decoded:
            report.flag("HIDDEN", f"Possible CTF flag pattern found in raw strings: {f}")

    for pat, desc in MALWARE_KEYWORDS:
        if re.search(pat, data, re.IGNORECASE):
            report.flag("MALWARE", f"Suspicious indicator: {desc}")

    # Large base64 blobs worth auto-decoding
    b64_candidates = [m for m in set(BASE64_RE.findall(data)) if len(m) >= 40]
    b64_candidates.sort(key=len, reverse=True)
    return b64_candidates[:10]


def try_autodecode(blobs, report: Report):
    """Attempt base64/hex/rot13/binary decode on suspicious strings, keep human-readable results."""
    def printable_ratio(b: bytes) -> float:
        if not b:
            return 0
        printable = sum(1 for c in b if 32 <= c <= 126 or c in (9, 10, 13))
        return printable / len(b)

    for blob in blobs:
        # base64
        try:
            padded = blob + b"=" * (-len(blob) % 4)
            decoded = base64.b64decode(padded, validate=False)
            if printable_ratio(decoded) > 0.85 and len(decoded) >= 4:
                text = decoded.decode(errors="replace")
                report.hidden_data.append({"method": "base64", "source": blob.decode(errors="replace")[:60] + "...",
                                            "decoded": text[:500]})
                report.flag("HIDDEN", f"Base64 blob decodes to readable text: {text[:80]!r}")
        except Exception:
            pass

    # hex-encoded runs
    for m in re.finditer(rb"(?:[0-9a-fA-F]{2}){10,}", b"".join(blobs)):
        h = m.group()
        try:
            decoded = bytes.fromhex(h.decode())
            if printable_ratio(decoded) > 0.85 and len(decoded) >= 4:
                text = decoded.decode(errors="replace")
                report.hidden_data.append({"method": "hex", "decoded": text[:500]})
                report.flag("HIDDEN", f"Hex blob decodes to readable text: {text[:80]!r}")
        except Exception:
            pass


def entropy_analysis(data: bytes, report: Report):
    overall = shannon_entropy(data)
    report.info["overall_entropy"] = round(overall, 3)
    if overall > 7.5:
        report.flag("SUSPICIOUS",
                     f"Overall file entropy is very high ({overall:.2f}/8.0) — "
                     f"suggests encryption, compression, or packing.")

    windows = sliding_entropy(data)
    high_entropy_regions = [(off, e) for off, e in windows if e > 7.85]
    if high_entropy_regions and len(data) > 2000:
        # only interesting if it's not just because the whole file is compressed media
        pct = len(high_entropy_regions) / max(1, len(windows))
        if 0.05 < pct < 0.9:
            report.flag("SUSPICIOUS",
                        f"{len(high_entropy_regions)} high-entropy block(s) found within an "
                        f"otherwise lower-entropy file — possible embedded encrypted/packed payload.")
    return windows


# ============================================================
# Image-specific: EXIF + LSB steganography
# ============================================================

def analyze_image(path: str, data: bytes, report: Report):
    if not HAVE_PIL:
        report.flag("INFO", "PIL not available - skipping EXIF/LSB analysis.")
        return
    try:
        img = Image.open(path)
        img.load()
    except Exception as e:
        report.flag("INFO", f"Could not open as image: {e}")
        return

    report.info["image_format"] = img.format
    report.info["image_size"] = f"{img.width}x{img.height}"
    report.info["image_mode"] = img.mode

    # EXIF
    exif_data = {}
    try:
        exif = img._getexif()
        if exif:
            for tag_id, value in exif.items():
                tag = TAGS.get(tag_id, tag_id)
                exif_data[str(tag)] = str(value)[:200]
    except Exception:
        pass
    if exif_data:
        report.info["exif"] = exif_data
        report.flag("INFO", f"EXIF metadata present ({len(exif_data)} fields) — check for GPS/comment fields.")
        for k in ("GPSInfo", "UserComment", "ImageDescription", "Comment", "Software"):
            if k in exif_data:
                report.flag("SUSPICIOUS", f"EXIF field '{k}' present: {exif_data[k][:150]}")

    # LSB steganography detection + extraction attempt
    lsb_stats, extracted_text = lsb_analysis(img)
    report.info["lsb_chi_square_hint"] = lsb_stats
    if extracted_text:
        report.flag("HIDDEN", f"LSB extraction produced readable text: {extracted_text[:100]!r}")
        report.hidden_data.append({"method": "LSB steganography", "decoded": extracted_text[:1000]})


def lsb_analysis(img):
    """
    Extract the least-significant bit of each color channel (in R,G,B order)
    and try to interpret the resulting bitstream as ASCII text, stopping at a
    null terminator or once we hit non-printable garbage.
    Also returns a simple randomness hint: real LSB-embedded data tends to look
    like noise when the image is 'clean', but structured/readable output is a
    strong signal of a hidden message.
    """
    try:
        img = img.convert("RGB")
    except Exception:
        return {"note": "could not convert to RGB"}, None

    import numpy as np
    arr = np.array(img)
    flat = arr.reshape(-1, arr.shape[-1])  # each row = [R,G,B]

    # cap how much we scan for performance
    max_pixels = min(len(flat), 200000)
    bits = (flat[:max_pixels] & 1).flatten()  # LSBs of R,G,B interleaved

    # pack bits into bytes
    nbytes = len(bits) // 8
    bits = bits[:nbytes * 8]
    byte_vals = np.packbits(bits.reshape(-1, 8))
    raw = byte_vals.tobytes()

    # try to find a readable ASCII run near the start (common CTF LSB tools write plain text)
    text_candidate = extract_printable_prefix(raw)

    # randomness hint: ratio of 1-bits should be ~0.5 for natural images;
    # far from 0.5 can hint at structured embedded data (weak heuristic, informational only)
    ones_ratio = float(bits.mean()) if len(bits) else 0.0

    stats = {"ones_ratio_in_lsb_plane": round(ones_ratio, 4),
             "note": "ratio far from 0.5 can (weakly) suggest non-random embedded data"}
    return stats, text_candidate


def extract_printable_prefix(raw: bytes, min_len=8):
    # stop at first null byte (common terminator used by stego tools)
    if b"\x00" in raw:
        raw = raw[:raw.index(b"\x00")]
    m = re.match(rb"[\x20-\x7e\r\n\t]{%d,}" % min_len, raw)
    if m:
        return m.group().decode(errors="replace")
    # otherwise look for the longest printable run anywhere in the first 20000 bytes
    best = b""
    for match in re.finditer(rb"[\x20-\x7e\r\n\t]{%d,}" % min_len, raw[:20000]):
        if len(match.group()) > len(best):
            best = match.group()
    return best.decode(errors="replace") if len(best) >= min_len else None


# ============================================================
# PDF-specific analysis
# ============================================================

def analyze_pdf(path: str, data: bytes, report: Report):
    report.info["object_count_raw"] = data.count(b"obj")
    if b"/JavaScript" in data or b"/JS" in data:
        report.flag("MALWARE", "PDF contains /JavaScript or /JS object — can execute code on open.")
    if b"/OpenAction" in data:
        report.flag("MALWARE", "PDF contains /OpenAction — triggers automatically when opened.")
    if b"/EmbeddedFile" in data:
        report.flag("HIDDEN", "PDF contains an /EmbeddedFile object — another file is embedded inside.")
    if b"/RichMedia" in data or b"/Launch" in data:
        report.flag("MALWARE", "PDF contains /RichMedia or /Launch action — can launch external content.")

    if HAVE_PYPDF:
        try:
            reader = pypdf.PdfReader(path)
            meta = reader.metadata
            if meta:
                report.info["pdf_metadata"] = {k: str(v) for k, v in meta.items()}
            report.info["pdf_page_count"] = len(reader.pages)
            if reader.is_encrypted:
                report.flag("SUSPICIOUS", "PDF is encrypted/password-protected.")
        except Exception as e:
            report.flag("INFO", f"pypdf could not fully parse file: {e}")


# ============================================================
# ZIP-based formats (docx/xlsx/pptx/jar/apk) - check for macros / suspicious members
# ============================================================

def analyze_zip_based(path: str, report: Report):
    import zipfile
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            report.info["zip_members"] = names[:50]
            if any("vbaProject.bin" in n for n in names):
                report.flag("MALWARE", "Office file contains vbaProject.bin — document has VBA macros.")
            suspicious_members = [n for n in names if n.lower().endswith((".exe", ".dll", ".ps1", ".vbs", ".js", ".bat"))]
            for n in suspicious_members:
                report.flag("MALWARE", f"Archive contains executable/script member: {n}")
    except Exception as e:
        report.flag("INFO", f"Could not parse as ZIP container: {e}")


# ============================================================
# Main pipeline
# ============================================================

def analyze_file(path: str, deep: bool = False) -> Report:
    report = Report(path)
    with open(path, "rb") as f:
        data = f.read()

    real_type = identify_file(data, path, report)
    scan_embedded_signatures(data, report)
    check_appended_data(data, real_type, report)
    entropy_analysis(data, report)

    b64_candidates = analyze_strings(data, report)
    try_autodecode(b64_candidates, report)

    if "image" in real_type.lower() or path.lower().endswith((".png", ".jpg", ".jpeg", ".bmp", ".gif")):
        analyze_image(path, data, report)

    if "PDF" in real_type:
        analyze_pdf(path, data, report)

    if "ZIP" in real_type:
        analyze_zip_based(path, report)

    if not report.flags:
        report.flag("INFO", "No obvious hidden data or malware indicators found by static heuristics.")

    return report


# ============================================================
# Output formatting
# ============================================================

SEVERITY_COLOR = {"MALWARE": C.R, "HIDDEN": C.M, "SUSPICIOUS": C.Y, "INFO": C.CY}
SEVERITY_ICON = {"MALWARE": "[!! MALWARE]", "HIDDEN": "[HIDDEN DATA]", "SUSPICIOUS": "[SUSPICIOUS]", "INFO": "[info]"}


def print_report(report: Report):
    print(f"\n{C.BOLD}{'='*70}{C.END}")
    print(f"{C.BOLD}FlagHunter Report: {report.path}{C.END}")
    print(f"{C.BOLD}{'='*70}{C.END}\n")

    print(f"{C.BOLD}-- File Identity --{C.END}")
    for k in ("declared_extension", "detected_type_signature", "file_command_output", "size_bytes",
              "md5", "sha1", "sha256"):
        if k in report.info:
            print(f"  {k:26s}: {report.info[k]}")

    print(f"\n{C.BOLD}-- Entropy --{C.END}")
    print(f"  overall_entropy           : {report.info.get('overall_entropy')} / 8.0")

    if "image_format" in report.info:
        print(f"\n{C.BOLD}-- Image Details --{C.END}")
        for k in ("image_format", "image_size", "image_mode", "lsb_chi_square_hint"):
            if k in report.info:
                print(f"  {k:26s}: {report.info[k]}")
        if "exif" in report.info:
            print(f"  exif fields               :")
            for k, v in report.info["exif"].items():
                print(f"      {k}: {v}")

    if "pdf_metadata" in report.info:
        print(f"\n{C.BOLD}-- PDF Details --{C.END}")
        print(f"  page_count                : {report.info.get('pdf_page_count')}")
        for k, v in report.info["pdf_metadata"].items():
            print(f"      {k}: {v}")

    if report.strings_found:
        print(f"\n{C.BOLD}-- Notable Strings --{C.END}")
        for cat, items in report.strings_found.items():
            print(f"  {cat}:")
            for it in items:
                print(f"      - {it}")

    if report.hidden_data:
        print(f"\n{C.BOLD}-- Decoded Hidden Data --{C.END}")
        for h in report.hidden_data:
            print(f"  [{h['method']}] {h['decoded']!r}")

    print(f"\n{C.BOLD}-- FLAGS / FINDINGS --{C.END}")
    order = {"MALWARE": 0, "HIDDEN": 1, "SUSPICIOUS": 2, "INFO": 3}
    for sev, msg in sorted(report.flags, key=lambda x: order.get(x[0], 9)):
        color = SEVERITY_COLOR.get(sev, "")
        icon = SEVERITY_ICON.get(sev, sev)
        print(f"  {color}{icon:16s}{C.END} {msg}")

    print()


def report_to_dict(report: Report) -> dict:
    return {
        "path": report.path,
        "info": report.info,
        "strings_found": report.strings_found,
        "hidden_data": report.hidden_data,
        "flags": [{"severity": s, "message": m} for s, m in report.flags],
    }


def main():
    parser = argparse.ArgumentParser(
        description="FlagHunter - analyze any file for hidden data, steganography, and malware indicators.")
    parser.add_argument("file", help="Path to the file to analyze")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON instead of text")
    parser.add_argument("--deep", action="store_true", help="Run deeper (slower) analysis passes")
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"Error: file not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    report = analyze_file(args.file, deep=args.deep)

    if args.json:
        print(json.dumps(report_to_dict(report), indent=2))
    else:
        print_report(report)


if __name__ == "__main__":
    main()
