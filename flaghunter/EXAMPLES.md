# FlagHunter — Example Input & Output

This document shows exactly what FlagHunter produces, using two real test files
run through the actual tool (not hypothetical output).

---

## Example 1: A PNG image with hidden data (two different techniques at once)

**How the test file was built** (for reference — this is what a CTF challenge author
might do to you):
1. A 100x100 random-noise RGB PNG was created.
2. The message `CTF{lsb_stego_found_you}` was hidden bit-by-bit in the
   least-significant-bit of each color channel (classic LSB steganography).
3. The bytes `SECRET_APPENDED_FLAG{hidden_after_eof}` were appended to the very
   end of the file, after the PNG's real `IEND` chunk (classic "extra data after EOF" trick).

**Command:**
```bash
python3 flaghunter.py test_stego.png
```

**Output (text mode):**
```
======================================================================
FlagHunter Report: test_stego.png
======================================================================

-- File Identity --
  declared_extension        : .png
  detected_type_signature   : PNG image
  file_command_output       : PNG image data, 100 x 100, 8-bit/color RGB, non-interlaced
  size_bytes                : 30206
  md5                       : 5c5e0d9066f7b4e7683c42449734ea14
  sha1                      : f0f92d0e22166e4006de2eee938b7bc25177271a
  sha256                    : cc13d8c723dc9c49b1dc2c33530cf8a3edb838b77e27869cecc770b92912d896

-- Entropy --
  overall_entropy           : 7.99 / 8.0

-- Image Details --
  image_format              : PNG
  image_size                : 100x100
  image_mode                : RGB
  lsb_chi_square_hint       : {'ones_ratio_in_lsb_plane': 0.4961, 'note': 'ratio far from 0.5 can (weakly) suggest non-random embedded data'}

-- Notable Strings --
  possible_ctf_flags:
      - SECRET_APPENDED_FLAG{hidden_after_eof}

-- Decoded Hidden Data --
  [LSB steganography] 'CTF{lsb_stego_found_you}'

-- FLAGS / FINDINGS --
  [HIDDEN DATA]    38 bytes of data found APPENDED after the file's real EOF marker (offset 30168) — classic hidden-data trick.
  [HIDDEN DATA]    Possible CTF flag pattern found in raw strings: SECRET_APPENDED_FLAG{hidden_after_eof}
  [HIDDEN DATA]    LSB extraction produced readable text: 'CTF{lsb_stego_found_you}'
  [SUSPICIOUS]     Overall file entropy is very high (7.99/8.0) — suggests encryption, compression, or packing.
```

Notice both hidden pieces of data were found through completely different
mechanisms — the appended flag was caught by string-pattern matching, and the
LSB flag required actually extracting and decoding the pixel data.

**Same file, JSON mode** (for scripting / piping into other tools):
```bash
python3 flaghunter.py test_stego.png --json
```
```json
{
  "path": "test_stego.png",
  "info": {
    "declared_extension": ".png",
    "detected_type_signature": "PNG image",
    "file_command_output": "PNG image data, 100 x 100, 8-bit/color RGB, non-interlaced",
    "size_bytes": 30206,
    "md5": "5c5e0d9066f7b4e7683c42449734ea14",
    "sha1": "f0f92d0e22166e4006de2eee938b7bc25177271a",
    "sha256": "cc13d8c723dc9c49b1dc2c33530cf8a3edb838b77e27869cecc770b92912d896",
    "overall_entropy": 7.99,
    "image_format": "PNG",
    "image_size": "100x100",
    "image_mode": "RGB",
    "lsb_chi_square_hint": {
      "ones_ratio_in_lsb_plane": 0.4961,
      "note": "ratio far from 0.5 can (weakly) suggest non-random embedded data"
    }
  },
  "strings_found": {
    "possible_ctf_flags": [
      "SECRET_APPENDED_FLAG{hidden_after_eof}"
    ]
  },
  "hidden_data": [
    {
      "method": "LSB steganography",
      "decoded": "CTF{lsb_stego_found_you}"
    }
  ],
  "flags": [
    {
      "severity": "HIDDEN",
      "message": "38 bytes of data found APPENDED after the file's real EOF marker (offset 30168) — classic hidden-data trick."
    },
    {
      "severity": "SUSPICIOUS",
      "message": "Overall file entropy is very high (7.99/8.0) — suggests encryption, compression, or packing."
    },
    {
      "severity": "HIDDEN",
      "message": "Possible CTF flag pattern found in raw strings: SECRET_APPENDED_FLAG{hidden_after_eof}"
    },
    {
      "severity": "HIDDEN",
      "message": "LSB extraction produced readable text: 'CTF{lsb_stego_found_you}'"
    }
  ]
}
```

---

## Example 2: A PDF with an embedded auto-run JavaScript action

**How the test file was built:** a single-page PDF was generated with an
embedded JavaScript action (`app.alert("pwned")`) that fires automatically
when the document is opened — a real-world malicious PDF technique.

**Command:**
```bash
python3 flaghunter.py test_suspicious.pdf
```

**Output (text mode):**
```
======================================================================
FlagHunter Report: test_suspicious.pdf
======================================================================

-- File Identity --
  declared_extension        : .pdf
  detected_type_signature   : PDF document
  file_command_output       : PDF document, version 1.3, 1 page(s)
  size_bytes                : 644
  md5                       : 926e231be5fa393c36b6742f1e37a0bf
  sha1                      : 876d914bafad1a11c5b33e90e29b82c39667b2c3
  sha256                    : b60ab107ce64e7ce63846b3247aec94a8ae60a4f0b7707758f473274dc72cf9a

-- Entropy --
  overall_entropy           : 4.916 / 8.0

-- PDF Details --
  page_count                : 1
      /Producer: pypdf

-- FLAGS / FINDINGS --
  [!! MALWARE]     Suspicious indicator: PDF JavaScript action (can auto-run on open)
  [!! MALWARE]     PDF contains /JavaScript or /JS object — can execute code on open.
  [HIDDEN DATA]    1 bytes of data found APPENDED after the file's real EOF marker (offset 643) — classic hidden-data trick.
```

Note the low entropy (4.9/8.0) here compared to the PNG (7.99/8.0) — PDFs with
mostly text-based structure look very different from compressed image data,
which is exactly the kind of signal the entropy check is meant to surface.

---

## Reading the output

Every run has the same shape, in this order:

1. **File Identity** — hashes + real vs declared type
2. **Entropy** — a single overall-file number (per-file-type checks like image/PDF details appear here too, when applicable)
3. **Notable Strings** — URLs, IPs, emails, and CTF-flag-shaped patterns, if any were found
4. **Decoded Hidden Data** — anything the tool successfully extracted and decoded (LSB text, base64/hex blobs)
5. **FLAGS / FINDINGS** — the actionable summary, sorted so `MALWARE` findings always appear first, then `HIDDEN`, then `SUSPICIOUS`, then `INFO`

In JSON mode the same five categories map directly to the keys `info`,
`strings_found`, `hidden_data`, and `flags` — so you can pipe results into
another script, a CI pipeline, or a batch-scanning wrapper without any text parsing.
