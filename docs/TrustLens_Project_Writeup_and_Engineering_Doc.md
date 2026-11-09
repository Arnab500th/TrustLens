# TrustLens — Engineering Whitepaper & Comprehensive Build Documentation
**Autonomous Threat Analysis, SMS Scam Detection & Forensic Intelligence Platform**

* **Lead Integrator & Architect**: Arnab Datta
* **Engineering Team**: Deepraj, Rupam, Sumit, Arnab
* **Project Scope**: 48-Hour Hackathon Prototype & Production-Ready Security Microservice
* **Repository**: TrustLens (`trustlens/`)
* **Live System**: FastAPI Backend (`http://127.0.0.1:8000`) & Cloud MongoDB Atlas

---

## Table of Contents
1. [Executive Summary & Problem Statement](#1-executive-summary--problem-statement)
2. [End-to-End System Architecture](#2-end-to-end-system-architecture)
3. [The Core Threat Verification Pillars](#3-the-core-threat-verification-pillars)
4. [Deep Dive: The SMS Scam Detection Challenge & Solution](#4-deep-dive-the-sms-scam-detection-challenge--solution)
   - *The Nature of Indian SMS Frauds*
   - *Why Pure Regex & Keyword Heuristics Failed*
   - *Machine Learning on the Indian SMS Dataset (`anmolshrivastav/scam-ham-india`)*
   - *Addressing the 99.34% Accuracy Question: Overfitting vs. Template Leakage*
   - *The Multi-Layered Defense-in-Depth Solution*
5. [Key Engineering Challenges & Hard-Fought Technical Fixes](#5-key-engineering-challenges--hard-fought-technical-fixes)
   - *Phonetic Brand Typosquatting vs. Edit Distance (Double Metaphone)*
   - *Statistical TLD Risk Scoring vs. Binary Blacklisting*
   - *Database Migration: SQLite to Cloud MongoDB Atlas with Silent Fallback*
   - *High-Latency Network Overhead & Instant Database Caching*
   - *Certificate Transparency & The eMudhra CA Sub-Authority Problem*
   - *Enterprise Threat Intelligence Interoperability (STIX 2.1)*
   - *Frontend Asynchronous Deadlocks, Browser Security & CSS Flexbox Bug*
6. [Data Dictionary: What Gets Persisted in the Database](#6-data-dictionary-what-gets-persisted-in-the-database)
7. [Slide-by-Slide Presentation Outline (Ready for PPT/Pitch)](#7-slide-by-slide-presentation-outline-ready-for-pptpitch)
8. [Conclusion & Future Roadmap](#8-conclusion--future-roadmap)

---

## 1. Executive Summary & Problem Statement

### The Problem
Digital deception in India has escalated from simple Nigerian prince emails to hyper-targeted, localized digital engineering attacks. Millions of citizens receive daily SMS messages, WhatsApp alerts, and QR codes claiming to be:
- Urgent **bank account deactivations** (SBI, HDFC, ICICI).
- **Electricity power disconnection warnings** requiring instant bill payments.
- **India Post parcel redelivery fees** demanding ₹25 payment links.
- **Mandatory KYC verifications** (PAN / Aadhaar expiry).

Traditional security safeguards fail completely against this vector:
1. **Network Firewalls and Antivirus** inspect files and local memory—they cannot see incoming text messages or evaluate social engineering pretexts.
2. **Browser Blacklists (Safe Browsing)** are reactive; phishing domains are spun up, harvest credentials for 4 to 8 hours, and shut down before public blacklists ever register them.
3. **The "Green Padlock" Illusion**: Over 85% of modern phishing sites now possess valid SSL/TLS certificates issued by automated Certificate Authorities (Let's Encrypt, ZeroSSL, eMudhra Sub-CAs). Users are trained to look for HTTPS, making them vulnerable to lookalike domains.

### The Solution: TrustLens
TrustLens is a lightweight, zero-trust digital fraud detection system. It provides layered, deterministic, and probabilistic risk evaluation for **URLs**, **QR codes**, and **raw SMS/social engineering messages**. 

Instead of binary "Safe" vs "Unsafe" claims (which create false confidence), TrustLens produces a normalized **0–100 Risk Score**, maps findings to **transparent evidence pillars**, generates plain-English explanations for non-technical users, and exports standardized **STIX 2.1 Threat Intelligence** for enterprise SOC operations.

---

## 2. End-to-End System Architecture

TrustLens is architected as an asynchronous, decoupled pipeline designed for fast sub-second client response:

```
                  ┌─────────────────────────────────────────────────────────┐
                  │                 TrustLens Client Layer                  │
                  │  (Vanilla HTML5 / Modern CSS / ES6 JavaScript / PWA)    │
                  └────────────┬─────────────────────────────┬──────────────┘
                               │                             │
                     POST /api/scan (URL / QR)     POST /api/message (SMS / Text)
                               │                             │
                               ▼                             ▼
                  ┌─────────────────────────────────────────────────────────┐
                  │            FastAPI Asynchronous Gateway                 │
                  │          (Uvicorn ASGI / High-Concurrency)              │
                  └────────────┬─────────────────────────────┬──────────────┘
                               │                             │
                     Cache Lookup (MongoDB Atlas)            │
                     [~200ms Hit -> Instant Replay]          │
                               │                             │
                  ┌────────────▼─────────────┐ ┌─────────────▼─────────────┐
                  │  URL & Domain Pipeline   │ │   Scam & NLP Message Engine │
                  │  - Phonetic Brand Match  │ │   - Local ML India Model   │
                  │  - Statistical TLD Score │ │   - TRAI Header Parser      │
                  │  - Certificate Deep-Scan │ │   - Negation-Aware Regex    │
                  │  - Headers & TLS Checks  │ │   - Groq Zero-Shot LLM      │
                  │  - URLhaus & PhishTank   │ │   - Embedded Link Extractor │
                  └────────────┬─────────────┘ └─────────────┬─────────────┘
                               │                             │
                               └──────────────┬──────────────┘
                                              ▼
                               ┌─────────────────────────────┐
                               │  Scoring & Synthesis Engine │
                               │  - Finding ID Normalization │
                               │  - 0–100 Point Accumulator  │
                               │  - Risk Band Labeling       │
                               │  - Plain-English Generator  │
                               └──────────────┬──────────────┘
                                              │
                      ┌───────────────────────┴───────────────────────┐
                      ▼                                               ▼
         ┌─────────────────────────┐                     ┌─────────────────────────┐
         │   Cloud MongoDB Atlas   │                     │  STIX 2.1 Threat Intel  │
         │ (Fallback: Local SQLite)│                     │    Export & CT Feed     │
         └─────────────────────────┘                     └─────────────────────────┘
```

### Component Breakdown
1. **Frontend (`frontend/`)**: Vanilla HTML/CSS/JavaScript with zero bloated runtime frameworks (no React or Angular overhead). Features camera QR streaming via `BarcodeDetector` / `jsQR`, manual QR image decoding, live dynamic risk meters, and breadcrumb view navigation.
2. **FastAPI Gateway (`backend/main.py`)**: Asynchronous REST API utilizing Python 3.12 `asyncio` and `httpx` to run network probes concurrently.
3. **Core Orchestrator (`backend/core/`)**: Standardizes findings into strictly defined schemas (`Finding`, `ModuleResult`, `ScanContext`), calculates multi-pillar risk scores, and synthesizes technical findings into plain-English explanations.
4. **Cloud Persistence (`backend/db.py`)**: Cloud MongoDB Atlas integration with automated failover to local SQLite for complete offline resilience.

---

## 3. The Core Threat Verification Pillars

TrustLens organizes risk signals into four distinct evidence pillars:

| Pillar | Technical Probes & Checks | Finding Examples | Max Impact |
| :--- | :--- | :--- | :--- |
| **Domain & URL Analysis** | Phonetic brand matching (Metaphone/Jaro-Winkler), structural subdomain depth, statistical TLD risk scoring, IP-as-host detection, `@` credential confusion syntax. | `LOOKALIKE_BRAND`, `BRAND_IN_SUBDOMAIN`, `SUSPICIOUS_TLD`, `LONG_URL` | Up to 35 pts |
| **Certificate Validation** | X.509 certificate extraction, issuer validation, lifespan/age calculation, self-signed validation, weak signature algorithms, Subject Alternative Name (SAN) coverage. | `CERT_EXPIRED`, `CERT_NAME_MISMATCH`, `CERT_NEW`, `CERT_SELF_SIGNED` | Up to 30 pts |
| **Web Security & Headers** | Live TLS handshake, cipher strength, HTTP Strict Transport Security (HSTS), Content Security Policy (CSP), clickjacking defenses (`X-Frame-Options`, `frame-ancestors`). | `INSECURE_HTTP`, `MISSING_HSTS`, `MISSING_CSP`, `MISSING_FRAME_PROTECTION` | Up to 25 pts |
| **Threat Intelligence** | Live query against abuse databases: abuse.ch URLhaus (malware distribution) and PhishTank verified database, combined with collaborative community reports. | `URLHAUS_LISTED`, `PHISHTANK_VERIFIED`, `REPEATED_REPORT` | **Overrides directly to Confirmed Malicious** |

---

## 4. Deep Dive: The SMS Scam Detection Challenge & Solution

### The Nature of Indian SMS Frauds
India's SMS threat landscape is distinct from Western phishing. Frauds exploit the Telecommunications Regulatory Authority of India (TRAI) commercial messaging framework, banking KYC guidelines, and widespread UPI payment systems.

### Why Pure Regex & Keyword Heuristics Failed
Our initial prototype utilized traditional keyword matching (`"urgent"`, `"kyc"`, `"otp"`, `"blocked"`). In testing, this failed dramatically:
1. **The Negation Catastrophe**: Legitimate security notices regularly state: *"Never share your OTP or password with bank executives"*. Naive regex flagged every legitimate bank warning as high-risk social engineering.
2. **Evasion through Character Obfuscation**: Attackers easily bypass regex with minor perturbations (`K.Y.C`, `A/C`, `1mmediately`, `Rs. 5O,OOO`).
3. **Context Blindness**: A message asking for money could be a friend splitting lunch or an extortionist demanding a release fee.

### Machine Learning on the Indian SMS Dataset (`anmolshrivastav/scam-ham-india`)
To solve this, we integrated an authentic Indian SMS corpus:
- **Dataset**: `anmolshrivastav/scam-ham-india` sourced from Hugging Face (2,272 unique samples: 1,377 ham, 895 scam/spam).
- **Architecture**: A pipeline pairing a `TfidfVectorizer` (sublinear term frequency scaling, unigram + bigram combinations, 8,000 max features) with an $L_2$-regularized `LogisticRegression` classifier (`C=1.5`, balanced class weighting).
- **Performance**: Achieved **99.34% test accuracy** (macro F1-score: 0.99) on a 20% stratified holdout split (455 unseen messages).
- **Artifact**: Exported as a self-contained 376 KB model file ([`backend/data/scam_india_model.joblib`](file:///d:/Personal/TrustLens/trustlens/backend/data/scam_india_model.joblib)).

### Addressing the 99.34% Accuracy Question: Overfitting vs. Template Leakage
When an NLP model scores 99%+, engineers must critically examine it: **Is it overfitted?**

1. **Why It Scores So High**: In SMS datasets, vocabulary separation is near-orthogonal. Normal Indian chat uses conversational words (*`ok`*, *`meeting`*, *`laptop`*, *`market`*, *`good`*), while scam messages are dense with transactional triggers (*`click`*, *`bit.ly`*, *`free`*, *`Rs`*, *`account`*, *`blocked`*).
2. **The Real Vulnerability — Template Leakage**: 
   Inspect the learned weights:
   - Positive (Scam): `your` (+5.26), `click` (+5.08), `rs` (+4.78), `free` (+4.14), `airtel` (+3.63), `bit ly` (+3.03).
   - Because the training corpus had many fake recharge scams, words like `airtel` and `vi` received strong positive coefficients. If a friend texts *"Can you recharge my Airtel number?"*, the ML model alone risks a false positive.

### The Multi-Layered Defense-in-Depth Solution
To build a bulletproof system, we engineered a 5-tier hybrid defense:

1. **TRAI Alphanumeric Sender Verification (`check_sender_rules`)**:
   - Institutional Indian alerts use registered 6-character TRAI headers (e.g., `VM-HDFCBK`, `AD-SBIINB`, `BZ-AMAZON`).
   - If a message claims to be from a bank, electricity board, or courier but arrives from an ordinary 10-digit mobile number (`+91 98765 43210`), it is immediately assigned `SENDER_PERSONAL_NUMBER` (+25 pts).
   - If the header letters do not match the claimed entity (e.g., header `VM-VKTRCK` claiming to be HDFC Bank), it flags `SENDER_NAME_MISMATCH` (+20 pts).
2. **Negation-Aware Heuristic Parser (`scan_text`)**:
   - Employs negative lookbehinds (25-character window) to ensure that *"do not share OTP"* or *"never disclose password"* are classified as legitimate security advice rather than requests.
3. **Trained Local ML Model (`classify_message_ml`)**:
   - Zero-latency local scoring. If scam probability exceeds 65%, flags `IMPERSONATION_CLAIM` (+20 to +25 pts) with embedded confidence telemetry.
4. **Groq Zero-Shot LLM Classifier (`classify_message_ai`)**:
   - Sends the message to Groq (`openai/gpt-oss-20b` or LLaMA 3) with a specialized system prompt to evaluate holistic linguistic subtlety and novel pretexts.
5. **Destination Link Deep-Scanning**:
   - Extracts all embedded URLs (`bit.ly`, `tinyurl`, `.xyz` links) and runs them through the full multi-module URL, DNS, Certificate, and Threat Intel pipeline.

---

## 5. Key Engineering Challenges & Hard-Fought Technical Fixes

### Challenge 1: Brand Typosquatting (Metaphone vs. Levenshtein)
* **Problem**: Phishers spoof brands with subtle character changes (`paypahl.com`, `amazn-support.in`, `sbii.co.in`). Standard Levenshtein distance fails when length differences or multiple substitutions occur.
* **Fix**: Built an ML phonetic brand matcher in [`backend/modules/url.py`](file:///d:/Personal/TrustLens/trustlens/backend/modules/url.py) using `jellyfish.metaphone` and `jellyfish.jaro_winkler_similarity`. It encodes the phonetic pronunciation of domain labels. If an unregistered domain sounds like an established financial brand (`paypahl` -> `PPLL` matching `paypal` -> `PPLL`) or shares a Jaro-Winkler metric $\ge 0.88$, it immediately flags `LOOKALIKE_BRAND` (+30 pts).

### Challenge 2: Statistical TLD Risk Scoring vs. Binary Blacklisting
* **Problem**: Binary blacklisting of top-level domains (e.g. banning all `.xyz` or `.top`) creates massive false positives for legitimate web developers while missing scams on `.com` or `.in`.
* **Fix**: Replaced binary rules with statistical reputation weights calibrated against Spamhaus and APWG quarterly threat reports (`.top`: 0.90, `.xyz`: 0.82, `.click`: 0.85, `.cfd`: 0.88). The engine dynamically calculates proportional risk points (15 to 25 pts) based on real-world abuse density.

### Challenge 3: Database Migration & Offline Failover (MongoDB Atlas + SQLite)
* **Problem**: Team members needed centralized cloud persistence to share scan history across different machines. However, if the MongoDB Atlas cluster encountered DNS/network timeouts or connection caps during a live demo, the entire server would throw unhandled exceptions and crash.
* **Fix**: Implemented a resilient dual-engine persistence layer in [`backend/db.py`](file:///d:/Personal/TrustLens/trustlens/backend/db.py). On startup, it attempts connection to MongoDB Atlas (`mongodb+srv://...`). If `MONGODB_URI` is missing, invalid, or the cluster is offline, it gracefully logs a warning and falls back to local SQLite (`trustlens.db`) without dropping a single scan or raising a 500 error.

### Challenge 4: Latency Bottlenecks & Instant Database Caching
* **Problem**: A full network scan (resolving DNS, negotiating TLS handshakes, querying RDAP registries, parsing HTML security headers, and fetching PhishTank/URLhaus APIs) takes between 1.5 to 3.5 seconds. For frequently scanned sites (e.g., `sbi.co.in`, `google.com`) or active phishing campaigns, repeated scans waste bandwidth and degrade responsiveness.
* **Fix**: Built an instant cache layer with `find_cached_scan(url, host)`. If a domain has been audited, TrustLens returns the cached record in **~200ms** with `"cached": true`. The UI highlights this with an orange `⚡ CACHED RESULT` tag. To preserve user autonomy, a "Rescan" button forces a fresh live network audit when requested.

### Challenge 5: Certificate Transparency & The Modern CA Problem
* **Problem**: Users are taught that HTTPS means "safe". In reality, phishers obtain valid SSL certificates within minutes using automated CAs or compromised sub-authorities (as highlighted in the 2025 eMudhra sub-CA incident).
* **Fix**: Evaluates SSL certificate age (`CERT_NEW`, +20 pts if issued < 14 days ago), self-signed status (`CERT_SELF_SIGNED`, +30 pts), and weak cryptographic keys. Furthermore, we created a live Certificate Transparency feed (`/api/feed`) that surfaces newly logged lookalike certificates in real-time.

### Challenge 6: Enterprise Interoperability via STIX 2.1
* **Problem**: Cybersecurity operations centers (SOCs) cannot ingest proprietary JSON schemas. Threat data must follow standard exchange formats.
* **Fix**: Built an automated STIX 2.1 bundle generator in [`backend/export/stix.py`](file:///d:/Personal/TrustLens/trustlens/backend/export/stix.py). Scans are transformed into OASIS STIX 2.1 JSON containing `indicator`, `infrastructure`, and `observed-data` objects. Users can export individual scans (`/api/scan/{id}/stix`) or dump recent high-risk indicators (`/api/export/stix`).

### Challenge 7: Frontend Async Streaming & UI Bug Elimination
* **Problem A (Browser Security on Camera)**: Modern browsers disable camera access (`getUserMedia`) on `file:///` URLs.
  * *Fix*: Mounted the `frontend/` directory directly into FastAPI via `app.mount("/", StaticFiles(directory=_frontend_dir, html=True))`, serving both client and API from `http://localhost:8000/`.
* **Problem B (Stalled Progress Bar)**: The UI stalled indefinitely on *"Analyzing the destination…"* because the code expected an SSE stream even when the backend returned complete scan objects synchronously.
  * *Fix*: Updated `requestScan` in [`frontend/script.js`](file:///d:/Personal/TrustLens/trustlens/frontend/script.js): `if (startData.verdict) return startData;`.
* **Problem C (CSS Specificity & Flexbox Clipping)**:
  * `.scan-progress { display: flex; }` was overriding the HTML `hidden` attribute. Fixed by adding `[hidden], .scan-progress[hidden] { display: none !important; }`.
  * Long URLs in history cards overflowed flex containers. Fixed by enforcing `min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex-shrink: 0;`.
* **Problem D (Deadlock from Syntax Error)**: A duplicate `catch` block on line 487 caused a runtime syntax error that broke all event listeners and froze navigation. Diagnosed via `node -c frontend/script.js` and resolved.

---

## 6. Data Dictionary: What Gets Persisted in the Database

Every scan and community report is saved in MongoDB Atlas across two collections:

### Collection 1: `scans`
```json
{
  "scan_id": "8f3b2a1c",
  "url": "http://sbi-kyc-update.xyz/login",
  "host": "sbi-kyc-update.xyz",
  "source": "message",
  "risk_score": 95,
  "verdict": "MALICIOUS",
  "label": "High Risk",
  "confidence": 0.96,
  "matched_brand": "State Bank of India",
  "explanation": "Multiple high-severity threats detected: lookalike brand targeting State Bank of India, unencrypted connection, and high-risk TLD.",
  "findings": [
    {
      "id": "SENDER_PERSONAL_NUMBER",
      "source": "scam",
      "description": "Message claiming to be from bank sent from personal number (+91 98765 43210)",
      "points": 25,
      "data": {"sender": "+91 98765 43210"}
    },
    {
      "id": "LOOKALIKE_BRAND",
      "source": "url",
      "description": "Domain phonetically imitates State Bank of India (sbi.co.in)",
      "points": 30,
      "data": {"matched": "sbi", "similarity": 0.94}
    },
    {
      "id": "IMPERSONATION_CLAIM",
      "source": "scam",
      "description": "Trained Indian SMS ML model flagged message as high-confidence scam (92% probability)",
      "points": 25,
      "data": {"ml_model": "scam-ham-india", "ml_scam_probability": 0.923}
    }
  ],
  "facts": {
    "certificate": {"issuer": "None", "self_signed": false, "days_remaining": 0},
    "dns": {"has_dns": true, "ips": ["198.51.100.24"], "age_days": 4},
    "headers_tls": {"tls_version": null, "hsts": false, "csp": false},
    "threat_intel": {"urlhaus_listed": false, "phishtank_listed": false},
    "scam": {
      "sender": "+91 98765 43210",
      "claim": "bank",
      "is_personal_sender": true,
      "ml_model": "scam-ham-india",
      "ml_scam_probability": 0.923,
      "ml_label": "scam",
      "ai_confidence": 0.97,
      "is_scam": true
    }
  },
  "created_at": "2026-11-09T06:20:41Z",
  "confirmed_malicious": false
}
```

### Collection 2: `reports`
```json
{
  "id": "rep-7f8a9b",
  "url": "http://sbi-kyc-update.xyz/login",
  "note": "Phishing link sent via SMS asking for PAN update. Fake SBI netbanking page.",
  "scan_id": "8f3b2a1c",
  "reported_at": "2026-11-09T06:22:15Z"
}
```

---

## 7. Slide-by-Slide Presentation Outline (Ready for PPT/Pitch)

Use this structured outline to create your presentation slide deck:

### Slide 1: Title & Hook
* **Title**: TrustLens — Smarter Than the Scammers
* **Subtitle**: Layered Phishing, SMS Fraud & Digital Threat Verification
* **Presenter**: Team TrustLens (Arnab Datta, Deepraj, Rupam, Sumit)
* **Hook Statement**: *"Over ₹7,000 Crores were lost to digital scam SMS and fake links in India last year. Traditional antivirus and browser filters miss them. TrustLens stops them before the user taps."*

### Slide 2: The Core Problem
* **The Attack Vector**: Scammers don't hack firewalls; they hack humans via SMS, WhatsApp, and QR codes.
* **Why Modern Tools Fail**:
  * 85%+ of scam sites now use valid HTTPS (green padlock illusion).
  * Safe Browsing blacklists take hours to update; phishing domains live for only 4 hours.
  * Firewalls cannot read text messages or inspect social engineering pretexts.

### Slide 3: Introducing TrustLens
* **What It Does**: Instant zero-trust analysis of URLs, QR codes, and SMS text.
* **Core Philosophy**:
  * **Never says "100% Safe"** — provides calibrated 0–100 Risk Scores.
  * **Multi-Pillar Evidence**: Evaluates Domains, SSL Certificates, Security Headers, Threat Feeds, and NLP.
  * **Plain-English Explanations**: Translates technical CVE/SSL flaws into clear guidance for ordinary citizens.

### Slide 4: System Architecture
* **Visual Diagram**: Frontend (Vanilla JS) -> FastAPI Gateway -> Asynchronous Inspection Pipelines -> Cloud MongoDB Atlas.
* **Key Stats**:
  * **~200ms** cached lookup response time.
  * **1.8s** full live multi-module scan.
  * **Zero bloated dependencies**; runs entirely as an efficient microservice.

### Slide 5: The Big Breakthrough: Cracking the SMS Scam Puzzle
* **The Challenge**: Indian SMS scams use unique phrasing (KYC, electricity cutoff, TRAI headers).
* **The Engineering Solution**:
  1. **Trained ML Model**: TF-IDF + Logistic Regression trained on 2,271 Indian SMS messages (99.34% accuracy).
  2. **TRAI Header Verification**: Differentiates 10-digit mobile numbers from official sender IDs (e.g. `VM-HDFCBK`).
  3. **Negation Heuristics**: Distinguishes *"never share OTP"* from *"share OTP"*.
  4. **Groq AI Layer**: Evaluates novel pretexts and conversational manipulation.

### Slide 6: Beyond Basic Checks: Advanced Forensics
* **Phonetic Brand Matching**: Double Metaphone & Jaro-Winkler catch auditory typosquats (`paypahl` -> PayPal).
* **Statistical TLD Scoring**: Continuous risk weights based on Spamhaus threat distributions.
* **Certificate Transparency Feed**: Real-time detection of newly issued lookalike certificates (eMudhra incident mitigation).
* **STIX 2.1 Export**: One-click threat intelligence bundles for enterprise SOC analysts.

### Slide 7: Hard Engineering Problems We Solved
* **Database Resilience**: Connected Cloud MongoDB Atlas with automatic, silent fallback to local SQLite.
* **Instant Caching Engine**: 200ms cached replay preventing redundant network stress.
* **Browser Security & Camera**: Solved webcam constraints by serving frontend over HTTP/localhost and building canvas fallback for image uploads.
* **Layout & Asynchronous Deadlocks**: Resolved CSS flexbox clipping and resolved SSE async race conditions.

### Slide 8: Live Product Demonstration
* **Demo 1**: Scanning an authentic banking alert (`VM-HDFCBK`) -> 0/100 Low Risk.
* **Demo 2**: Scanning a malicious KYC SMS with a personal mobile number -> 100/100 High Risk.
* **Demo 3**: Instant cached result demonstration (`⚡ CACHED RESULT`).
* **Demo 4**: Exporting a STIX 2.1 threat intelligence bundle into cyber defense tools.

### Slide 9: Impact & Future Roadmap
* **Target Audience**: Everyday consumers, university students, senior citizens, and enterprise SOC teams.
* **Next Milestones**:
  * Native Android/iOS SMS filter via TrustLens PWA.
  * Chrome/Edge browser extension for automated link hover inspection.
  * Integration with the Indian National Cybercrime Reporting Portal (1930 Helpline).

---

## 8. Conclusion & Future Roadmap

TrustLens demonstrates that effective cyber protection does not require heavy, opaque AI or clunky enterprise software. By synthesizing **local statistical machine learning**, **deterministic protocol forensics**, **TRAI regulatory intelligence**, and **cloud-scale threat aggregation**, TrustLens provides real-time digital protection that is transparent, explainable, and accessible to everyone.
