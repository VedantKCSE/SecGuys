# HITMAN – Predictive Ingestor (Phase-1)

## 📌 Overview

This project automates the pipeline from initial discovery to AI-driven risk assessment. It performs:

* **Automated service discovery** (Nmap)
* **Vulnerability scanning** (Nuclei)
* **Exploit correlation** (SearchSploit)
* **AI-based predictive risk analysis** (Gemini)

**Phase-1** focuses on preparing the environment, ensuring all dependencies, tools, and permissions are correctly configured.

---

## ⚙ Phase-1: Environment Setup

### Step 1: Navigate to project directory

```bash
cd ~/projects/hitman/ready

```

### Step 2: Run Phase-1 setup

```bash
chmod +x phase1_setup.sh
./phase1_setup.sh

```

**The setup script will:**

* Install required system tools.
* Install Python dependencies.
* Update Nuclei templates.
* Fix executable permissions for scripts.

---

## 🔍 Phase-2: Scanning & Normalization

Run the main scanner to gather raw data:

```bash
./v2.2.sh

```

**Generated Outputs:**

* `scan_results/nmap.xml` – Raw network discovery data.
* `scan_results/nuclei.json` – Raw vulnerability findings.
* `scan_results/exploits_raw.json` – Correlated exploit data.
* `final.json` – **Normalized, AI-ready data.**

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
ready/
├── phase1_setup.sh
├── v2.2.sh
├── analyze.py
├── scan_results/
│   ├── nmap.xml
│   ├── nuclei.json
│   └── exploits_raw.json
├── final.json
├── ai_report.md
└── README.md

```
* Ensure you have the necessary permissions to run network scans in your environment.