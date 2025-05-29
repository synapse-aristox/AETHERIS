# AETHERIS ▸ Network Reconnaissance Toolkit

![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Shell](https://img.shields.io/badge/Language-Bash-blue.svg)
![Version](https://img.shields.io/badge/Version-1.0.0-blue.svg)

> **Reconnaissance. Elegantly Executed.**  
> A minimalist, ethical, and precise network scanning tool.  
> Powered by **AETHERIS** // Operated by **NyxKraken**.

```
+-+-+-+-+-+-+-+-+
|A|E|T|H|E|R|I|S|
+-+-+-+-+-+-+-+-+
```

---

## 📜 Description

**AETHERIS** is a **minimalist and elegant Bash-based toolkit** designed for comprehensive network reconnaissance. Built with a strong emphasis on **ethics and precision**, it leverages `nmap` to perform various scan types, organizing reports meticulously by machine and timestamp. Whether you're a cybersecurity learner, a seasoned pentester, or a dedicated defender, AETHERIS provides a streamlined workflow for uncovering network insights.

> ⚠️ **Important:** This tool is strictly for **educational and authorized use only**. Ensure you have explicit permission before scanning any network.

---

## ✨ Key Features

- 🔍 **Comprehensive Scans:** Full reconnaissance (top 1000 ports), exhaustive scans (all 65535 ports), and specialized enumerations (SMB, HTTP, FTP, SSH).
- 🧭 **Host Discovery:** Identify active hosts within a local subnet.
- 🧪 **Custom Scan Support:** Run your own `nmap` commands.
- 📁 **Organized Reporting:** Timestamped folders per machine with `.nmap`, `.xml`, `.html` outputs.
- 📄 **HTML Report Generation:** Convert XML to readable HTML using `xsltproc`.
- 🌐 **Multilingual Interface:** English (EN) and Spanish (ES) support.
- 🧬 **Ethical Focus:** Designed for clean, responsible recon.
- 🧘 **Minimalist & Precise:** Efficient, no bloat.

---

## 🚀 Requirements

- Bash (tested on Kali, Parrot OS)
- `nmap`
- `xsltproc`

Install with:
```bash
sudo apt update
sudo apt install nmap xsltproc
```

---

## 🛠 Installation

```bash
git clone https://github.com/NyxKraken/aetheris.git
cd aetheris
chmod +x aetheris.sh
```

---

## ⚙️ Usage

```bash
sudo ./aetheris.sh
```

Follow the interactive menu to perform scans and view results.

---

## 📁 Output Structure

```
~/AETHERIS/
 └── target_machine/
     ├── 2025-05-29_14-33/
     │    ├── recon_full_top1000.nmap
     │    ├── recon_full_top1000.xml
     │    ├── recon_full_top1000.html
     │    └── ...
     ├── .history.txt
     └── notes.txt
```

---

## 🧬 Philosophy

> AETHERIS is not noise — it’s poetry in silence.  
> Born under the silent watch of Nyx, it aims to uncover hidden truths in the digital realm.

---

## 🌌 Inspirational Quotes

Each scan session ends with a quote:

- "The stars are silent. Yet they watch."
- "In the dark, precision is your only ally."
- "Recon is not noise, it's poetry in silence."
- "What cannot be seen, cannot be stopped."

---

## 🔮 Future Roadmap

- Integration with `masscan`, `amass`, and cloud recon tools
- JSON and other export formats
- Full Python version with plugins
- Lightweight GUI with Tauri or GTK/QT

---

## 🤝 Contribution

Pull requests, issues, and ideas are welcome.
Let’s evolve AETHERIS together.

---

## ⚖️ License

This project is licensed under the MIT License. See `LICENSE` for details.

---

## ⚡ Signature

```
:: Powered by AETHERIS // Operated by NyxKraken ::
```
