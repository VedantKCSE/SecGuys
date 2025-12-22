# HITMAN – Predictive Ingestor (Phase-1)

## 📌 Overview

This project automates the pipeline from initial discovery to AI-driven risk assessment. It performs:

* **Automated service discovery** (Nmap)
* **Vulnerability scanning** (Nuclei)
* **Exploit correlation** (SearchSploit)
* **AI-based predictive risk analysis** (Gemini)


---

## ⚙️ Phase-1: Environment Setup

Phase-1 focuses on preparing the environment, ensuring all dependencies, tools, and permissions are correctly configured before starting the scanning and analysis phases.

---

### 🔹 Step 0: Clone the Project Repository

Clone the centralized vulnerability scanner project from GitHub:

```bash
git clone https://github.com/VedantKCSE/SecGuys.git
```

---

### 🔹 Step 1: Navigate to Project Directory

```bash
cd SecGuys
```

---

### 🔹 Step 2: Grant Execute Permission to Setup Script

```bash
chmod +x setup.sh
```

---

### 🔹 Step 3: Run the Setup Script

```bash
bash setup.sh
```

---

### 🔧 What the Setup Script Does

The `setup.sh` script performs the following tasks:

* Installs required system tools (Nmap, Nuclei, WhatWeb, SearchSploit, etc.)
* Installs required Python libraries
* Updates Nuclei templates to the latest version
* Fixes executable permissions for project scripts
* Ensures the environment is ready for scanning and analysis

---

## 🔍 Phase-2: Scanning & Normalization

Phase-2 focuses on executing multiple scanning engines and consolidating their outputs into a single, normalized data structure for further analysis.

---

### 🔹 Step 1: Grant Execute Permission

```bash
chmod +x scanner.sh
```

---

### 🔹 Step 2: Run the Centralized Scanner

```bash
./scanner.sh
```

The scanner sequentially executes:

* **WhatWeb** – Web technology fingerprinting
* **Nikto** – Web server misconfiguration and insecure file detection
* **Nmap** – Port and service discovery
* **Nuclei** – Web vulnerability detection
* **SearchSploit** – Exploit correlation

---

### 📂 Generated Outputs

* `scan_results/whatweb.json` – Web technology stack detection.
* `scan_results/nikto.txt` – Web server misconfigurations and insecure file findings.
* `scan_results/nmap.xml` – Raw network and service discovery data.
* `scan_results/nuclei.json` – Raw vulnerability scan findings.
* `scan_results/exploits_raw.json` – Correlated public exploit data.
* `final.json` – **Centralized, normalized, AI-ready vulnerability dataset.**

---

## 🤖 Phase-3: AI Analysis

Once `final.json` has been generated, run the analysis script to trigger the Gemini engine:

```bash
python3 analyze.py

```

**Generated Outputs:**

* **Console AI risk report:** Real-time summary.
* `ai_report.md`: A detailed markdown report for stakeholders.

---

## ⚠ Notes

> [!IMPORTANT]
> * **Environment:** Designed to run on **Kali Linux**.
> * **Connectivity:** Ensure stable network connectivity to the target environment.
> * **Rate Limiting:** The Free Gemini tier may rate-limit requests; this is handled automatically via exponential backoff in the code.
> 
> 

## 🧠 Author

**Internal Lab Automation** – Red Team Focused.

---

## 📂 Final Directory Structure

```text
secguy/
├── setup.sh
├── scanner.sh
├── analyze.py
├── scan_results/
│   ├── whatweb.json
│   ├── nikito.txt
│   ├── nmap.xml
│   ├── nuclei.json
│   └── exploits_raw.json
├── final.json
├── ai_report.md
└── README.md
```
* Ensure you have the necessary permissions to run network scans in your environment.


