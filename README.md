# FlagHunter

A single-file Python CLI tool for CTF / security-student file analysis.
Point it at **any file** (image, PDF, archive, executable, random binary) and it will:

- Identify the **real** file type from magic bytes (not just the extension) and flag mismatches
- Compute MD5/SHA1/SHA256 hashes
- Scan for **embedded/polyglot files** hidden mid-file
- Detect **data appended after the file's real EOF marker** (a classic CTF trick — e.g. extra bytes after a PNG's `IEND` chunk)
- Run **Shannon entropy analysis** (whole-file + sliding window) to flag likely encrypted/packed/compressed regions
- Extract and classify **strings**: URLs, IPs, emails, and `flag{...}` / `CTF{...}` style patterns
- Flag **malware-style indicators**: PDF `/JavaScript`, `/OpenAction`, Office macros (`vbaProject.bin`), suspicious archive members, PowerShell/shell patterns, obfuscation keywords, etc.
- For images: pull **EXIF metadata** and run **LSB (least-significant-bit) steganography** extraction, auto-decoding any readable hidden text
- For PDFs: pull metadata, page count, detect embedded files/JS/launch actions
- For ZIP-based formats (docx/xlsx/pptx/jar/apk): list members, flag macros/scripts/executables inside
- Auto-attempt **base64 / hex decoding** on any large encoded blobs found in the raw bytes

Output as a readable colored report, or `--json` for machine-readable output you can pipe into other tools/scripts.

## Usage

```bash
python3 flaghunter.py suspicious_file.png
python3 flaghunter.py challenge.pdf --json
```

## Requirements

- Python 3.8+
- `Pillow`, `numpy`, `pypdf` (all optional — the tool degrades gracefully and skips
  image/PDF-specific checks if a library isn't installed; core analysis always works)
- The `file` command (present by default on Linux/macOS) for cross-checking type detection

```bash
pip install Pillow numpy pypdf
```

## How it flags things

| Severity     | Meaning                                                              |
|--------------|-----------------------------------------------------------------------|
| `MALWARE`    | Indicator commonly associated with malicious files (auto-run actions, macros, obfuscation keywords, dropped executables) |
| `HIDDEN`     | Concrete hidden data found (appended bytes, embedded files, decoded stego/base64/hex payloads, CTF flag patterns) |
| `SUSPICIOUS` | Something worth a human look (extension mismatch, high entropy, unusual EXIF fields) |
| `INFO`       | General notes, no action needed |

## Important notes / limitations

- This is a **static heuristic triage tool**, not an antivirus engine. A clean report
  does not guarantee a file is safe, and a flag does not guarantee malicious intent —
  always verify manually, especially before treating something as a real threat.
- It **never executes** the file it analyzes.
- Signature scanning only uses signatures ≥4 bytes for mid-file matches, to avoid
  false positives inside naturally high-entropy data (compressed images, encrypted
  blobs) where short byte sequences can appear by chance.
- LSB steganography detection assumes the common "plain ASCII packed into RGB LSBs,
  null-terminated" scheme used by most CTF stego challenges and tools like `zsteg`/
  `stegsolve` presets. More exotic embedding orders (e.g. only 1 channel, custom bit
  depth, encrypted payloads) won't be caught automatically — extend `lsb_analysis()`
  if you need those.

## Extending it

The whole tool is one readable file (`flaghunter.py`), organized into clear stages
(`identify_file`, `scan_embedded_signatures`, `check_appended_data`, `entropy_analysis`,
`analyze_strings`, `analyze_image`, `analyze_pdf`, `analyze_zip_based`). Good next
additions if you want to keep building this as a portfolio project:

- Chi-square LSB detection (proper statistical test, not just the bit-ratio heuristic)
- Audio steganography (spectrogram + WAV LSB)
- Volatility/PCAP integration for a "triage everything" mode
- A plugin system so each file-type analyzer is a drop-in module
