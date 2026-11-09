# TrustLens
> An explainable, multi-layered threat analysis platform engineered to detect phishing websites, malicious URLs, scam SMS messages, and weaponized QR codes before users fall victim.

---

## 1. Problem

Phishing and digital social engineering remain the leading initial access vectors for cyberattacks globally, causing billions in financial losses each year. Modern threat actors have evolved far beyond crude, easily detectable lures:

- **Visual Spoofing & Domain Cloaking**: Attackers weaponize Levenshtein brand lookalikes (e.g., `paypa1.com`, `hclfcbank.com`), internationalized domain name (IDN) homoglyphs with Punycode (`xn--`), abused disposable TLDs (`.top`, `.click`, `.xyz`), and deep subdomain nesting to bypass traditional signature filters.
- **Indian SMS Scam Epidemic (Smishing)**: Fraudsters exploit urgent social pretexts—such as immediate electricity disconnection, unverified bank KYC, tax refund lures, and lottery rewards. They routinely impersonate institutional authorities while sending messages from unregistered 10-digit personal mobile numbers or spoofed headers.
- **QR Code Phishing (Quishing)**: Attackers encode malicious URLs inside QR codes in physical places or PDF invoices. Because email security gateways cannot inspect pixel data without OCR, these bypass standard enterprise perimeter filters.
- **The "Black-Box" Usability Gap**: Existing security scanners provide binary verdicts ("Safe" or "Unsafe") without explaining *why*. When a user is given no transparent reasoning, they either ignore false alarms or fall into a false sense of security.
- **Cryptographic & Certificate Weaknesses**: Threat actors rapidly obtain free SSL/TLS certificates for ephemeral domains. Recent Certificate Authority audits (such as the eMudhra sub-CA security incident) highlight the critical need to inspect certificate age, signature algorithms, and key sizes rather than trusting HTTPS blindly.

---

## 2. Solution

TrustLens provides a transparent, zero-trust, multi-layered inspection platform that combines heuristic analysis, machine learning, and explainable AI:

- **4-Pillar URL Analysis Engine**:
  - *Lexical & Brand Heuristics*: Scans for typo-squatting, Levenshtein distance against known brand dictionaries, Punycode tricks, and empirical TLD risk scores.
  - *DNS & WHOIS Intelligence*: Resolves A/AAAA records and inspects domain registration age to identify newly registered domains (within the critical 7-day phishing window).
  - *TLS Cryptographic Audit*: Examines certificate expiration, SAN hostname matches, self-signed chains, weak RSA/EC keys (<2048-bit RSA), and deprecated signature algorithms.
  - *Security Headers & Safe HTML Parsing*: Audits HSTS, CSP, and X-Frame-Options, safely parsing DOM structures for off-domain password submission actions and hidden iframes without executing malicious JavaScript.
- **Indian SMS 5-Tier Hybrid Defense**:
  - *Negation-Aware Regex Rules*: Captures urgency, threats, and reward lures while recognizing warnings (e.g., "never share your OTP" is not flagged as an OTP demand).
  - *Local Machine Learning Model*: Zero-latency inference via a TF-IDF vectorizer + Logistic Regression model trained on 2,272 labeled Indian SMS samples (achieving 99.34% holdout accuracy).
  - *TRAI Header Verification*: Validates alphanumeric SMS sender headers (e.g., `VM-HDFCBK`) against claimed institutions, flagging bank alerts originating from 10-digit mobile numbers.
  - *Groq LLM Social Engineering NLP*: Assesses semantic pretexting and manipulative intent using LLaMA-3 / GPT-OSS models.
  - *Recursive Link Deep-Scan*: Automatically extracts up to 3 links from the message and submits them through the full URL inspection pipeline.
- **Camera & File QR Code Scanner**:
  - In-browser camera scanner powered by `jsQR` with fallback to native `BarcodeDetector`, alongside image upload capabilities.
- **Deterministic 0–100 Scoring & Fact-Bound AI Explanations**:
  - Risk points are summed strictly from observed findings (0–30: Low Risk, 31–60: Suspicious, 61+: High Risk, 90+: Confirmed Malicious). AI never assigns the score.
  - A dedicated explainer converts findings into plain English for non-technical users, protected by a strict hallucination firewall that discards any unevidenced claim.
- **Enterprise Standards Compliance (STIX 2.1)**:
  - Generates OASIS STIX 2.1 JSON Threat Intelligence bundles for direct integration with enterprise SIEM and SOAR platforms.

---

## 3. Demo Links and a Screenshot

- **Live Web Application**: [https://trustlens.onrender.com](https://trustlens.onrender.com) *(Deployed on Render)*
- **Local Interactive Dashboard**: `http://127.0.0.1:8000`

### Interface Preview
```
+-------------------------------------------------------------------------------+
|  TRUSTLENS   [ Workspace / Scan a link ]             SYSTEM OPERATIONAL (O)   |
+-------------------------------------------------------------------------------+
|                                                                               |
|   LINK SECURITY, MADE CLEAR                                                   |
|   Check before you trust.                                                     |
|                                                                               |
|   [ 01 Analyze a URL ]                               READY TO SCAN            |
|   +-----------------------------------------------------------------------+   |
|   | [ > ] https://sbi-kyc-update.top/login                [ Scan link -> ]|   |
|   +-----------------------------------------------------------------------+   |
|   OR [ Scan a QR Code ]  [ Open camera ]  [ Upload QR image ]                 |
|                                                                               |
|   [ 02 Scan result ]                                                          |
|   +-----------------------------------------------------------------------+   |
|   |  (!) HIGH RISK                                         Score: 85/100  |
|   |  [=========================================================-------]   |
|   |                                                                       |
|   |  Plain-English Summary:                                               |
|   |  This website impersonates State Bank of India using lookalike brand  |
|   |  patterns. It was registered 2 days ago on a high-risk .top domain   |
|   |  and contains a login password box that submits data off-domain.      |
|   |                                                                       |
|   |  Key Findings:                                                        |
|   |  • LOOKALIKE_BRAND: Mimics State Bank of India (+30 pts)              |
|   |  • VERY_NEW_DOMAIN: Domain registered 2 days ago (+25 pts)            |
|   |  • SUSPICIOUS_TLD: High-abuse .top top-level domain (+15 pts)         |
|   |  • LOGIN_FORM: Form submits credentials to third-party host (+25 pts) |
|   |                                                                       |
|   |  [ Export STIX 2.1 Bundle ]   [ Copy Summary ]                        |
|   +-----------------------------------------------------------------------+   |
+-------------------------------------------------------------------------------+
```

---

## 4. Tech Stack

- **Backend Framework**: Python 3.12, FastAPI, Uvicorn, Gunicorn
- **Machine Learning & NLP**: Scikit-Learn (TF-IDF Vectorizer, Logistic Regression), Joblib, RapidFuzz, Jellyfish
- **Network, DNS & Cryptography**: HTTPX, Cryptography (x509), DNSPython, python-whois, BeautifulSoup4, tldextract
- **Explainable AI**: Groq Cloud API (`openai/gpt-oss-20b`, `llama-3.3-70b-versatile`)
- **Database & Persistence**: MongoDB Atlas (`pymongo`) with local SQLite3 fallback
- **Frontend**: Vanilla HTML5, Modern CSS3 (CSS Variables, Flexbox/Grid, Dark Mode Theme), ES6+ JavaScript, `jsQR` (via CDN)
- **Deployment & Containers**: Render Web Service, Uvicorn ASGI Runner

---

## 5. Architecture

```
                                  +-----------------------------+
                                  |      TrustLens Web App      |
                                  |  HTML5 · CSS3 · Vanilla JS  |
                                  +--------------+--------------+
                                                 | HTTP / SSE / STIX
                                                 v
                                  +-----------------------------+
                                  |       FastAPI Gateway       |
                                  | SSRF Firewall · Cache Layer |
                                  +--------------+--------------+
                                                 |
                   +-----------------------------+-----------------------------+
                   v                                                           v
       [ URL Inspection Pillar ]                                   [ SMS Inspection Pillar ]
  • Lexical & Typo Brand Engine (Levenshtein)                 • Deterministic Regex Heuristics
  • DNS A/AAAA Resolution & WHOIS Age Checks                  • Negation Guard ("never share OTP")
  • TLS Cert Cryptography (eMudhra Audit)                     • Indian SMS ML (TF-IDF + LogReg)
  • Security Headers (HSTS, CSP, XFO)                         • TRAI SMS Sender Header Validator
  • Safe HTML Parser (Password boxes, Iframes)                • Groq LLM Social Engineering NLP
  • Collaborative Feeds (URLhaus, PhishTank)                  • Recursive Link Deep-Scan (up to 3)
                   |                                                           |
                   +-----------------------------+-----------------------------+
                                                 |
                                                 v
                                  +-----------------------------+
                                  | Deterministic Scoring (0-100|
                                  | Low · Suspicious · High Risk|
                                  +--------------+--------------+
                                                 |
                   +-----------------------------+-----------------------------+
                   v                                                           v
       [ Fact-Bound AI Explainer ]                                 [ STIX 2.1 Threat Intel ]
  • Groq LLaMA-3 / GPT-OSS Plain English                      • OASIS STIX 2.1 Indicator Objects
  • Hallucination Firewall & Safety Rule                      • Custom Extension Properties (x_score)
                   |                                                           |
                   +-----------------------------+-----------------------------+
                                                 |
                                                 v
                                  +-----------------------------+
                                  | Dual-Mode Persistence Layer |
                                  | MongoDB Atlas <-> SQLite3   |
                                  +-----------------------------+
```

---

## 6. Setup and Run Steps

### Prerequisites
- Python 3.10+ (Python 3.12 recommended)
- Git

### 1. Clone the Repository
```bash
git clone https://github.com/Arnab-07/TrustLens.git
cd trustlens
```

### 2. Set Up Virtual Environment
```bash
# Windows (PowerShell)
python -m venv .venv
.venv\Scripts\activate

# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r backend/requirements.txt
```

### 4. Configure Environment Variables
Copy the sample environment file:
```bash
cp backend/.env.example backend/.env
```
Populate `backend/.env` with your credentials:
```env
MONGODB_URI=mongodb+srv://<username>:<password>@cluster.mongodb.net/trustlens?retryWrites=true&w=majority
LLM_PROVIDER=groq
LLM_API_KEY=your_groq_api_key_here
LLM_MODEL=openai/gpt-oss-20b
LLM_BASE_URL=https://api.groq.com/openai/v1
PHISHTANK_APP_KEY=
```
*(Note: If `MONGODB_URI` or `LLM_API_KEY` are omitted, TrustLens automatically falls back to local SQLite3 and template-based explanations.)*

### 5. Run the Application Locally
```bash
cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```
Open your browser at **`http://127.0.0.1:8000`**. The FastAPI server directly hosts the full frontend application!

### 6. Run Smoke Tests & Verification
```bash
# In the backend directory:
python -m scripts.smoke
```

---

## 7. Disclosures (Libraries, Templates, AI Tools)

- **Open Source Libraries**:
  - `FastAPI`, `Uvicorn`, `Gunicorn` — Web framework and ASGI server
  - `Scikit-Learn`, `Joblib` — SMS classification machine learning model
  - `RapidFuzz`, `Jellyfish` — Levenshtein string distance & brand homoglyph matching
  - `tldextract` — Public suffix list parsing (configured with offline-safe defaults)
  - `dnspython`, `python-whois`, `cryptography` — Network protocols, DNS resolution, and X.509 certificate decoding
  - `BeautifulSoup4`, `httpx` — Safe HTML DOM parsing and async HTTP inspection
  - `jsQR` (CDN) — Client-side camera QR code decoding
- **Datasets**:
  - `anmolshrivastav/scam-ham-india` (Hugging Face) & IIIT-Delhi SMS Dataset — Used to train the Indian SMS scam model (`backend/data/scam_india_model.joblib`)
  - `abuse.ch URLhaus` & `PhishTank` — Collaborative threat intelligence feeds
  - `Spamhaus & APWG intelligence metrics` — Empirical TLD abuse risk indexing
- **Design & UI**:
  - 100% custom-written, dependency-free vanilla HTML5, CSS3, and JavaScript
  - Typography: Google Fonts (`DM Sans` and `Space Grotesk`)
- **AI & Automation Tools**:
  - `Groq Cloud API` (`openai/gpt-oss-20b`, `llama-3.3-70b-versatile`) — Runtime plain-English explanations and NLP message classification
  - Google DeepMind Antigravity AI pair programmer — Used during development for architecture structuring, debugging, and documentation generation

---

## 8. Track

- **Track**: **Cybersecurity & AI / Web Security**
- **Domain**: Automated Threat Detection, Social Engineering Defense, Phishing Prevention, and Explainable Security Intelligence
- **Team**:
  - **Arnab Datta** (Team Lead & System Architect)
  - **Deepraj**
  - **Rupam**
  - **Sumit**
