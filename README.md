# CamCrack — Network Security Orchestrator

CamCrack is an open-source graphical user interface (GUI) automation framework written in Python. It streamlines security auditing workflows by bridging host discovery tools, credential verification matrices, and post-exploitation framework listeners into a unified control console.

---

## ⚠️ Legal Disclaimer
**IMPORTANT: PLEASE READ CAREFULLY.**

This software is developed and distributed strictly for authorized infrastructure auditing, educational research, white-hat vulnerability verification, and defensive configuration checks. 

* **Do not** deploy this application against infrastructure or targets without explicit, documented authorization from the network owner.
* The developer assumes **zero liability** and holds no responsibility for systemic damages, network disruptions, data loss, or legal consequences resulting from the misuse of this tool.
* By cloning, executing, or distributing this repository, you agree to comply fully with your local jurisdiction's cyber security laws and regulations.

---

## 🛠️ Key Features
* **Network Target Mapping:** Asynchronous network ping sweeps utilizing `nmap` alongside specialized parallelized multi-protocol (`HTTP/HTTPS/RTSP`) live service inspection engines.
* **Credential Engine:** Seamless interaction array leveraging `hydra` to handle parallel authentication verification on multiple modules like `http-get`, `http-digest-get`, and `rtsp`.
* **Framework Layer Integration:** Built-in automation for compiling test deployment binaries via `msfvenom` and rapidly spawning active console handler listeners (`msfconsole`).

---

## 📋 System Prerequisites

To run this application successfully, your host operating system must have Python 3 installed along with the following network security tools available in your global system `PATH`:

1. **Nmap** (Network Mapper)
2. **Hydra** (Network Logon Cracker)
3. **Metasploit-Framework** (`msfconsole` and `msfvenom`)

### Install Dependencies (Debian/Ubuntu/Kali Linux Example)
```bash
sudo apt update
sudo apt install python3-tk nmap hydra metasploit-framework curl
```

---

## 🚀 Getting Started

1. **Clone the repository:**
   ```bash
   git clone https://github.com
   cd YOUR_REPO_NAME
   ```

2. **Run the application:**
   ```bash
   python3 app.py
   ```

3. **Usage Flow:**
   * **Tab 1 (Target Discovery):** Input your target CIDR range (e.g., `192.168.1.0/24`) and scan. Select an identified host to stage it for auditing.
   * **Tab 2 (Credential Verification):** Pick your dictionary wordlists, adjust threads, and run the verification suite to inspect account strength.
   * **Tab 3 (Auxiliary & Listeners):** Build test payload binaries or spin up localized background monitoring scripts instantly.

---

## 📄 License
This repository is published under the terms of the **MIT License**. For full coverage metrics, read the accompanying `LICENSE` file.
