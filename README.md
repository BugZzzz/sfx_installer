# SFX – Encrypted Self-Extracting Installer

![language](https://img.shields.io/badge/language-C-blue)
![platform](https://img.shields.io/badge/platform-Linux-lightgrey)
![openssl](https://img.shields.io/badge/crypto-OpenSSL-orange)

**SFX** is a minimal, **pure-C self-extracting installer** that packages an
**encrypted tar archive** into a **single ELF executable**.

At runtime, the executable decrypts, extracts, and optionally executes
an installer script — without relying on Python, makeself, or external frameworks.

---

## ✨ Features

- 📦 Single-file delivery (self-extracting ELF)
- 🔐 AES-256-CBC encrypted payload (OpenSSL)
- 🗜️ Auto-detects archive formats  
  (`tar`, `tar.gz`, `tar.xz`, `tar.bz2`, `tar.zst`)
- 🧭 Installer path relative to tar root
- 🧹 Automatic cleanup (logs preserved)
- 📤 Extract-only mode (`-x`)
- 🧩 Compatible with **legacy & modern OpenSSL**
- 🐧 Designed for **minimal / legacy Linux systems**
- ❌ No Python, no makeself, no shell glue

---

## 🎯 Intended Use

SFX is designed for **controlled distribution environments**, such as:

- Internal software delivery
- Air-gapped systems
- Legacy Linux distributions
- Minimal or recovery environments
- Situations where file structure should not be trivially inspectable

---

## 🚫 Non-Goals

SFX is **not** intended to:

- Provide strong cryptographic protection against skilled adversaries
- Replace full-featured packaging systems
- Act as a secure key distribution mechanism

If you need strong security guarantees, use dedicated encryption and key-management solutions.

---

## 🧱 Architecture Overview
