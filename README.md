```
█████ █      ███   ████ █   █ █   █ █   █ █████ █████ ████
█     █     █   █ █     █   █ █   █ ██  █   █   █     █   █
████  █     █████ █ ███ █████ █   █ █ █ █   █   ████  ████
█     █     █   █ █   █ █   █ █   █ █  ██   █   █     █ █
█     █     █   █ █   █ █   █ █   █ █   █   █   █     █  █
█     █████ █   █  ████ █   █  ███  █   █   █   █████ █   █
```

<div align="center">

### 🕵️ Static file forensics for CTFs — hidden data, steganography & malware indicators, all in one CLI report

![Python](https://img.shields.io/badge/python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-informational?style=for-the-badge)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos-lightgrey?style=for-the-badge)
![Status](https://img.shields.io/badge/status-active-success?style=for-the-badge)
![Made for](https://img.shields.io/badge/made%20for-CTFs-ff69b4?style=for-the-badge)

</div>

---

## 🔍 What it does

Point FlagHunter at **any file** — image, PDF, archive, executable, or unknown
binary — and it digs through it looking for the things CTF challenge authors
(and real attackers) like to hide:

```
$ python3 flaghunter.py mystery_file.png

======================================================================
FlagHunter Report: mystery_file.png
======================================================================

-- FLAGS / FINDINGS --
  [!! MALWARE]     Suspicious indicator: PDF JavaScript action (can auto-run on open)
  [HIDDEN DATA]    38 bytes of data found APPENDED after the file's real EOF marker
  [HIDDEN DATA]    LSB extraction produced readable text: 'CTF{lsb_stego_found_you}'
  [SUSPICIOUS]     Overall file entropy is very high (7.99/8.0)
```

> 🎯 In text-mode output, findings are **color-coded in your terminal**:
> 🔴 red = `MALWARE`, 🟣 magenta = `HIDDEN DATA`, 🟡 yellow = `SUSPICIOUS`, 🔵 cyan = `INFO`

---

## ✨ Features

| Category | What it catches |
|---|---|
| 🕵️ **File identity** | Real file type from magic bytes vs. the extension — catches disguised/masqueraded files |
| 🔐 **Hashes** | MD5 / SHA1 / SHA256, instantly |
| 🧩 **Polyglots** | Other file signatures buried mid-file |
| 📎 **Appended data** | Bytes tacked on after a file's real EOF marker — the #1 classic CTF trick |
| 📊 **Entropy analysis** | Whole-file + sliding-window, flags packed/encrypted/compressed regions |
| 🖼️ **LSB steganography** | Extracts + auto-decodes hidden text from image pixel data |
| 🏷️ **EXIF metadata** | GPS, comments, software tags — often overlooked |
| 📄 **PDF internals** | `/JavaScript`, `/OpenAction`, `/Launch`, embedded files |
| 🗜️ **Archive contents** | Office macros (`vbaProject.bin`), scripts/executables hidden in ZIP-based files |
| 🚩 **String triage** | URLs, IPs, emails, and `flag{...}` / `CTF{...}` patterns, auto-extracted |
| 🔓 **Auto-decoding** | Base64 / hex blobs decoded automatically if they look like text |

---

## 🚀 Quick start

```bash
pip install Pillow numpy pypdf

python3 flaghunter.py suspicious_file.png
python3 flaghunter.py challenge.pdf --json
```

<div align="center">

| Flag | Meaning |
|:---:|---|
| 🔴 `MALWARE` | Indicator commonly tied to malicious files |
| 🟣 `HIDDEN` | Concrete hidden data found |
| 🟡 `SUSPICIOUS` | Worth a human look |
| 🔵 `INFO` | General notes, no action needed |

</div>

---

## 🧠 How it works under the hood

```
 ┌────────────┐    ┌───────────────┐    ┌──────────────┐
 │  Identify  │ →  │  Scan for     │ →  │  Entropy +   │
 │  file type │    │  hidden data  │    │  strings     │
 └────────────┘    └───────────────┘    └──────────────┘
        │                  │                    │
        ▼                  ▼                    ▼
 ┌─────────────────────────────────────────────────────┐
 │     Type-specific deep dive (image / PDF / zip)      │
 └─────────────────────────────────────────────────────┘
        │
        ▼
 ┌─────────────────────────────────────────────────────┐
 │      Final report: sorted, flagged, actionable       │
 └─────────────────────────────────────────────────────┘
```

One readable Python file, organized into clear stages you can extend:
`identify_file` → `scan_embedded_signatures` → `check_appended_data` →
`entropy_analysis` → `analyze_strings` → `analyze_image` / `analyze_pdf` /
`analyze_zip_based` → report.

See **[EXAMPLES.md](EXAMPLES.md)** for full real input/output samples (text + JSON).

---

## ⚠️ Limitations

- Static heuristic triage tool — **not** an antivirus engine. A clean report
  isn't a safety guarantee, and a flag isn't proof of malice.
- Never executes the analyzed file.
- LSB detection assumes the common "plain ASCII in RGB LSBs" scheme used by
  most CTF stego tools — exotic embeddings need extending `lsb_analysis()`.

---

## 🛣️ Roadmap ideas

- [ ] Proper chi-square LSB statistical test
- [ ] Audio steganography (spectrogram + WAV LSB)
- [ ] PCAP / Volatility integration for full-triage mode
- [ ] Plugin architecture — one module per file type

---

<div align="center">

**Built for CTF players, by a CTF player.** 🚩

If FlagHunter helped you snag a flag, ⭐ star the repo.

</div>

## 📜 License

MIT License — see [`LICENSE`](LICENSE) for details. Use it, fork it, ship it.

<div align="center">

---

Made with 🎣 by [@realnishil](https://github.com/realnishil)

*Stay safe out there. Not every link is what it claims to be.*

</div>
