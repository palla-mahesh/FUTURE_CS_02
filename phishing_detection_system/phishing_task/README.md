# Phishing Email Detection \& Awareness System

!\[Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
!\[FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)
!\[Kali Linux](https://img.shields.io/badge/Platform-Kali%20Linux-purple.svg)

## Overview

A full-stack Python application that analyzes `.eml` email files to detect phishing attempts. It identifies spoofed senders, malicious links, dangerous attachments, and social engineering tactics, then classifies the email as **Safe**, **Suspicious**, or **Phishing**.

Built as **Task 2: Phishing Email Detection \& Awareness System**.

## Key Features

* Identify Phishing Indicators (spoofed senders, fake domains, malicious links)
* Classify Emails: Safe / Suspicious / Phishing with risk score (0-100)
* Explain Techniques in plain business-friendly language
* Prevention Guidelines built-in
* Downloadable JSON Reports

## Tools \& Technologies

|Category|Tools|
|-|-|
|Language|Python 3.10+|
|Backend|FastAPI, Uvicorn|
|Parsing|Python `email`, BeautifulSoup4|
|Frontend|HTML5, CSS3, Bootstrap 5, JavaScript|
|OS|Kali Linux|

## Installation (Kali Linux)

### 1\. Clone the Repository

```bash
git clone https://github.com/YOUR\_USERNAME/phishing-detection-system.git
cd phishing-detection-system
```

### 2\. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3\. Install Dependencies

```bash
pip install -r requirements.txt
```

## Usage

### 1\. Start the Server

```bash
python phishing\_system.py
```

### 2\. Open the Web Interface

Navigate to: **http://localhost:8000**

### 3\. Upload an Email

Select a `.eml` file from the `samples/` folder.

### 4\. View Results

Classification, Risk Score, and Detailed Indicators.

### 5\. Download Report

Click "Download JSON Report".

## Project Structure

```
phishing-detection-system/
├── phishing\_system.py
├── README.md
├── requirements.txt
├── samples/
│   ├── sample\_phishing.eml
│   └── sample\_safe.eml
└── docs/
    ├── Awareness\_Report.md
    └── Prevention\_Guidelines.md
```

## Testing

* Sample 1: `samples/sample\_phishing.eml` → Expected: **Phishing (Score: 100)**
* Sample 2: `samples/sample\_safe.eml` → Expected: **Safe (Score: 0)**

## Detection Capabilities

|Indicator Type|Description|
|-|-|
|Display Name Spoofing|Name mimics brand but domain doesn't match|
|Reply-To Mismatch|Reply-To differs from sender|
|Raw IP URLs|URLs using IP addresses|
|URL Shorteners|bit.ly, tinyurl, etc.|
|Punycode Domains|Homograph attacks (xn--)|
|Mismatched Links|Link text differs from destination|
|Dangerous Attachments|.exe, .scr, .js, .vbs, etc.|
|Suspicious Keywords|"urgent", "verify", "account suspended"|

## Documentation

* [Awareness Report](docs/Awareness_Report.md)
* [Prevention Guidelines](docs/Prevention_Guidelines.md)

## Prevention Guidelines (Summary)

1. Check the sender's actual email address.
2. Hover over links before clicking.
3. Beware of urgency — "Act Now" is a phishing tactic.
4. Never open suspicious attachments.
5. Verify via official channels.

## License

MIT License

## Author

**\[Palla Venkata Mahesh]** - Task 2 Submission

