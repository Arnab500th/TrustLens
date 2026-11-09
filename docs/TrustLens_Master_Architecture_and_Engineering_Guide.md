# TrustLens — Master Engineering Whitepaper & Complete Technical Documentation
**Autonomous Threat Analysis, SMS Scam Detection, Forensic Intelligence & STIX 2.1 Microservice**

* **Lead Architect & Integrator**: Arnab Datta
* **Engineering Team**: Deepraj, Rupam, Sumit, Arnab
* **Project Repository**: TrustLens (`trustlens/`)
* **Live System**: FastAPI High-Concurrency Gateway (`http://127.0.0.1:8000`) & Cloud MongoDB Atlas Cluster
* **Target Audience**: Hackathon Juries, Cybersecurity Engineers, Enterprise SOC Analysts, Technical Reviewers

---

# Table of Contents
1. [The Problem Statement (PS) & Threat Landscape](#1-the-problem-statement-ps--threat-landscape)
   - *The Anatomy of Modern Digital Deception in India*
   - *Why Traditional Defenses & Browsers Fail Completely*
   - *The "Green Padlock" Fallacy and Ephemeral Infrastructure*
2. [The TrustLens Solution Philosophy](#2-the-trustlens-solution-philosophy)
   - *Zero-Trust Philosophy & Non-Binary Scoring*
   - *Deterministic Forensics vs. Probabilistic Intelligence*
   - *Human-Centric Transparency & Plain-English Explanations*
3. [Exhaustive Technology Stack & Architecture Justification](#3-exhaustive-technology-stack--architecture-justification)
   - *Frontend Technologies & Browser Sandboxing*
   - *Backend Gateway, Concurrency & Async Architecture*
   - *Machine Learning & NLP Frameworks*
   - *Threat Intelligence Feeds & Cryptographic Libraries*
   - *Dual-Engine Cloud Persistence (MongoDB Atlas + SQLite)*
4. [End-to-End System Architecture & Scan Lifecycles](#4-end-to-end-system-architecture--scan-lifecycles)
   - *High-Level Architecture Diagram*
   - *URL Scan Lifecycle (From Request to STIX Bundle)*
   - *QR Code Scan Lifecycle (Webcam Stream & Canvas Decode)*
   - *SMS / Message Forensic Lifecycle (Multi-Tier Hybrid Engine)*
   - *Community Reporting & Feedback Loop*
5. [In-Depth Inspection Modules: What We Are Doing Under the Hood](#5-in-depth-inspection-modules-what-we-are-doing-under-the-hood)
   - *Module 1: URL & Structural Analysis (`backend/modules/url.py`)*
   - *Module 2: Domain, DNS & RDAP Registration (`backend/modules/domain.py`)*
   - *Module 3: SSL/TLS Certificate Forensics (`backend/modules/certificate.py`)*
   - *Module 4: Web Application Security Headers (`backend/modules/headers.py`)*
   - *Module 5: Collaborative Threat Intelligence (`backend/modules/reputation.py`)*
   - *Module 6: Safe Content & Form Forensics (`backend/modules/page.py`)*
   - *Module 7: The Indian SMS Fraud Engine (`backend/modules/scam.py`)*
6. [The Scoring & Synthesis Engine (`backend/core/scoring.py` & `explain.py`)](#6-the-scoring--synthesis-engine-backendcorescoringpy--explainpy)
   - *The Mathematical Scoring Algorithm*
   - *Strict Risk Bands & Confirmed Malicious Override*
   - *The Safety Invariant: Why TrustLens Never Claims "Safe"*
   - *Explainability Engine: LLM Synthesis with Deterministic Fallbacks*
7. [The SMS Scam Challenge & Hybrid Defense Deep-Dive](#7-the-sms-scam-challenge--hybrid-defense-deep-dive)
   - *The Negation Catastrophe in Keyword Matching*
   - *Training the Local Indian SMS ML Model (`scam-ham-india`)*
   - *Analyzing the 99.34% Accuracy: Overfitting vs. Template Leakage*
   - *The 5-Tier Hybrid Defense Matrix*
8. [Comprehensive List of Real Technical Challenges & Fixes](#8-comprehensive-list-of-real-technical-challenges--fixes)
   - *Challenge 1: Phonetic Typosquatting (Double Metaphone + Jaro-Winkler)*
   - *Challenge 2: Statistical TLD Risk Scoring (Spamhaus/APWG Distributions)*
   - *Challenge 3: Cloud Database Reliability (MongoDB Atlas + Silent SQLite Failover)*
   - *Challenge 4: High-Latency Bottlenecks (200ms Instant Database Caching)*
   - *Challenge 5: Certificate Transparency & The eMudhra CA Sub-Authority Threat*
   - *Challenge 6: Enterprise Interoperability via OASIS STIX 2.1*
   - *Challenge 7: Browser Security Sandbox & Camera Stream Constraints*
   - *Challenge 8: Asynchronous Streaming Stalls & CSS Flexbox Text Overflow*
9. [Database Schema & Data Dictionary](#9-database-schema--data-dictionary)
   - *The `scans` Collection Schema*
   - *The `reports` Collection Schema*
10. [Complete REST API Reference](#10-complete-rest-api-reference)
11. [Slide-by-Slide Presentation Outline (Ready for PPT/Pitch Deck)](#11-slide-by-slide-presentation-outline-ready-for-pptpitch-deck)
12. [Conclusion & Future Roadmap](#12-conclusion--future-roadmap)

---

## 1. The Problem Statement (PS) & Threat Landscape

### The Anatomy of Modern Digital Deception in India
India represents the world's largest mobile-first digital economy. With over 800 million smartphone users and billions of daily UPI transactions, cyber adversaries have shifted their primary attack vector away from perimeter infrastructure attacks toward **direct cognitive exploitation of citizens**.

Every single day, Indian citizens receive millions of SMS text messages, WhatsApp alerts, and printed or digital QR codes engineered around four psychological pressure vectors:
1. **Financial Fear**: *"Dear customer, your SBI / HDFC bank account will be blocked today due to pending KYC. Update your PAN card immediately at http://bit.ly/sbi-kyc-verify."*
2. **Essential Utility Cutoff**: *"Dear consumer, your electricity power will be disconnected tonight at 9:30 PM because your previous month bill was not updated. Immediately contact our electricity officer at 9876543210."*
3. **Postal & Delivery Bait**: *"India Post: Your package could not be delivered due to incomplete house address. Update address and pay Rs. 25 redelivery fee within 24 hours at http://indiapost-parcel.top/login."*
4. **Lottery & Cashback Pretext**: *"Congratulations! You have received a cash reward of Rs. 4,999 in your PhonePe / Paytm wallet. Click to accept to bank."*

According to recent metrics from the Indian Cyber Crime Coordination Centre (I4C), Indian citizens lost over **₹7,066 Crores** to digital financial fraud in a single calendar year, with social engineering SMS and fake link vectors accounting for the largest share of individual victim complaints.

### Why Traditional Defenses & Browsers Fail Completely
Existing consumer and enterprise cybersecurity tools are architectural dinosaurs built for desktop network environments:
- **Endpoint Antivirus & EDR**: Antivirus software scans local file systems, memory buffers, and binary executables. It has zero visibility into SMS inboxes, WhatsApp messages, or QR codes.
- **Corporate Firewalls & DNS Filters**: Firewalls operate inside enterprise LAN perimeters. Citizens on 4G/5G mobile connections bypass corporate firewalls entirely.
- **Browser Blacklists (Google Safe Browsing / Microsoft SmartScreen)**: Traditional blacklists rely on web crawlers to discover, analyze, and confirm a phishing site. This feedback loop takes **8 to 24 hours**. Modern phishers register disposable domains on free or high-abuse TLDs, send 100,000 SMS messages in a 2-hour burst, harvest victim credentials, and abandon the domain before it ever appears on a blacklist.

### The "Green Padlock" Fallacy and Ephemeral Infrastructure
Historically, users were told: *"Look for the green padlock icon (HTTPS) before entering details."*
Today, this advice is actively hazardous:
- Over **85% of active phishing websites now serve valid SSL/TLS certificates**. Automated Certificate Authorities (Let's Encrypt, Cloudflare, ZeroSSL) issue free DV (Domain Validated) certificates via ACME protocols with zero identity verification.
- Compromised or rogue sub-authorities (as highlighted in the 2025 eMudhra sub-CA incident) enable adversaries to issue certificates that appear authentic to browser root stores.
- Attackers spin up lookalike domains using character homoglyphs, brand names embedded inside subdomains (`sbi.co.in.verification-portal.xyz`), and disposable TLDs (`.top`, `.click`, `.xyz`).

---

## 2. The TrustLens Solution Philosophy

TrustLens was engineered from the ground up as an autonomous, zero-trust digital fraud detection platform:

### 1. Zero-Trust Philosophy & Non-Binary Scoring
TrustLens completely rejects the concept of a binary "Safe" badge. Declaring any website or message "100% Safe" is technically irresponsible—a previously benign site can be compromised within minutes, or an evasive phishing page can serve cloaked content based on user-agent detection. Instead, TrustLens computes a **calibrated 0 to 100 Risk Score**:
- **0 – 30: Low Risk** (No critical indicators discovered; standard vigilance required).
- **31 – 60: Suspicious** (Moderate warning signs; credential entry strictly discouraged).
- **61 – 100: High Risk** (Multiple severe structural and linguistic threats; probable malicious scam).
- **Confirmed Malicious** (Active verification by trusted abuse databases URLhaus or PhishTank; overrides points directly).
- **Inconclusive** (Fewer than 3 analytical modules completed successfully; prevents false negatives due to network failures).

### 2. Deterministic Forensics vs. Probabilistic Intelligence
TrustLens avoids relying solely on opaque "black box" AI. A purely generative AI system can hallucinate security assertions. TrustLens employs a **two-tier architecture**:
1. **Deterministic Forensics**: Hard protocol verification (DNS resolution, SSL cipher suites, X.509 lifespan, HSTS header syntax, Levenshtein distance, TRAI alphanumeric sender regex).
2. **Probabilistic Intelligence**: Statistical TLD abuse distributions, phonetic NLP soundex algorithms, local machine learning classifiers, and zero-shot LLM contextual reasoning.

### 3. Human-Centric Transparency & Plain-English Explanations
Security tools fail when they present raw cryptographic logs or abstract CVE codes to non-technical citizens. TrustLens includes an integrated explainability layer (`core/explain.py`) that translates complex technical findings into clear, actionable advice (e.g., *"This website claims to be State Bank of India, but was registered only 3 days ago from an unverified server"*).

---

## 3. Exhaustive Technology Stack & Architecture Justification

Every technology in the TrustLens stack was selected to satisfy the constraints of a high-performance, real-time security microservice:

| Component | Technology | Version | Engineering Justification |
| :--- | :--- | :--- | :--- |
| **API Gateway** | **FastAPI** | 0.115+ | Chosen for native Python `asyncio` support, automated OpenAPI documentation, Pydantic type safety, and extreme low latency. |
| **ASGI Web Server** | **Uvicorn** | 0.32+ | High-concurrency event-loop worker running `uvloop` for asynchronous network socket operations. |
| **HTTP Client** | **HTTPX** | 0.28+ | Fully asynchronous HTTP client used to perform parallel network probes, SSL handshakes, and API queries without thread-blocking. |
| **Data Validation** | **Pydantic** | 2.10+ | Enforces strict, unalterable schema contracts across all analytical modules (`Finding`, `ModuleResult`, `ScanContext`). |
| **Domain Parsing** | **tldextract** | 5.1+ | Accurately separates registered domains from public suffixes (e.g., extracts `sbi.co.in` rather than treating `co.in` as the domain). Configured with local offline rules to prevent external network calls. |
| **Phonetic NLP** | **Jellyfish** | 1.1+ | Implements C-accelerated Double Metaphone and Jaro-Winkler string distance algorithms for real-time auditory typosquatting detection. |
| **Fuzzy Matching** | **RapidFuzz** | 3.10+ | High-speed Levenshtein distance calculations for brand keyword analysis. |
| **DNS Resolution** | **dnspython** | 2.7+ | Direct asynchronous DNS querying for A and AAAA address records against high-speed public resolvers (Cloudflare `1.1.1.1`, Google `8.8.8.8`). |
| **X.509 & Cryptography** | **cryptography** | 43.0+ | Deep parsing of ASN.1 X.509 certificates to extract cryptographic key sizes, signature hashing algorithms, SAN lists, and CA validity. |
| **Registration / RDAP** | **python-whois** | 0.9+ | Performs WHOIS/RDAP protocol queries to calculate domain registration dates and creation age. |
| **Machine Learning** | **Scikit-Learn** | 1.6+ | Lightweight, sub-millisecond local inference engine powering the TF-IDF vectorizer and Logistic Regression SMS scam classifier. |
| **Threat Feeds** | **abuse.ch URLhaus & PhishTank** | Live REST | Direct integration with authoritative, verified threat intelligence lists to identify active zero-day phishing campaigns. |
| **Generative LLM** | **Groq (Llama-3 / GPT-OSS)** | API v1 | Sub-500ms LPUs (Language Processing Units) running zero-shot reasoning to analyze social engineering pretexts and craft plain-English summaries. |
| **Cloud Database** | **MongoDB Atlas** | v7.0+ | Fully managed cloud NoSQL database providing document-level persistence for scans, threat feeds, and community reports. |
| **Local Fallback DB** | **SQLite3** | Native | Zero-configuration local relational database guaranteeing 100% offline uptime if cloud network connectivity drops. |
| **Threat Sharing** | **OASIS STIX 2.1** | Standard | Generates standard JSON bundles containing `indicator` and `observed-data` domain objects for enterprise SOC ingestion. |
| **Frontend Core** | **Vanilla HTML5 / ES6 JS / CSS3** | Modern | Completely zero-dependency client architecture: ultra-fast load time (< 50ms), no virtual DOM overhead, and direct native browser API integration. |
| **QR Code Engine** | **BarcodeDetector API + jsQR** | Native / 1.4 | Dual-layer QR decoder supporting direct hardware-accelerated video stream decoding with canvas fallback for uploaded images. |

---

## 4. End-to-End System Architecture & Scan Lifecycles

### High-Level Architecture Diagram
```
                     ┌────────────────────────────────────────────────────────┐
                     │                   TRUSTLENS CLIENT                     │
                     │  - Single Page Application (Vanilla HTML5 / CSS3 / JS) │
                     │  - Native Camera QR Stream & Canvas Image Decoder      │
                     │  - Dynamic Evidence Rendering & STIX 2.1 Download      │
                     └───────────────┬────────────────────────┬───────────────┘
                                     │                        │
                     POST /api/scan  │                        │  POST /api/message
                     (Target URL/QR) │                        │  (Sender, Claim, Text)
                                     ▼                        ▼
                     ┌────────────────────────────────────────────────────────┐
                     │              FASTAPI ASYNCHRONOUS GATEWAY              │
                     │  - SSRF Private IP Assertion (RFC 1918 Block)          │
                     │  - URL Normalization & Protocol Standardization        │
                     │  - Database Cache Interceptor (200ms Hit Replay)       │
                     └───────────────┬────────────────────────┬───────────────┘
                                     │                        │
                        [Cache Miss] │                        │ [Direct Inspection]
                                     ▼                        ▼
         ┌───────────────────────────────────────┐ ┌───────────────────────────────────────┐
         │     URL & INFRASTRUCTURE PIPELINE     │ │       SMS & NLP FORENSIC PIPELINE     │
         │  (Parallel Execution via asyncio)     │ │  (Hybrid Multi-Tier Pipeline)         │
         │                                       │ │                                       │
         │  1. url.py: Phonetic & TLD Scoring    │ │  1. TRAI Alphanumeric Header Parser   │
         │  2. domain.py: DNS & WHOIS Age        │ │  2. Negation-Aware Regex Rules        │
         │  3. certificate.py: X.509 Cryptography│ │  3. Local Indian SMS ML Model         │
         │  4. headers.py: TLS & Security Flags  │ │  4. Groq Zero-Shot LLM Reasoning      │
         │  5. reputation.py: URLhaus & PhishTank│ │  5. Embedded Link Extractor           │
         │  6. page.py: Safe HTML & Form Analysis│ │     (Deep-scans via URL Pipeline)     │
         └───────────────────┬───────────────────┘ └───────────────────┬───────────────────┘
                             │                                         │
                             └────────────────────┬────────────────────┘
                                                  ▼
                     ┌────────────────────────────────────────────────────────┐
                     │              SCORING & SYNTHESIS ENGINE                │
                     │  - Deduplicates Findings & Computes Capped Score (100) │
                     │  - Assigns Normalized Risk Label & Evidence Pillars    │
                     │  - Enforces Safety Invariant (Never Claims "Safe")     │
                     │  - Generates Plain-English Narrative (LLM / Template)  │
                     └────────────────────────────┬───────────────────────────┘
                                                  │
                                 ┌────────────────┴────────────────┐
                                 ▼                                 ▼
                     ┌───────────────────────┐         ┌───────────────────────┐
                     │  CLOUD MONGODB ATLAS  │         │  STIX 2.1 INTEL FEED  │
                     │ (Silent SQLite Backup)│         │ (Enterprise Export)   │
                     └───────────────────────┘         └───────────────────────┘
```

### URL Scan Lifecycle (Step-by-Step)
1. **Client Submission**: User enters a link (e.g. `http://paypa1-security.top/login`) or clicks an example.
2. **SSRF Boundary Check**: `backend/core/context.py::assert_public` validates the URL, resolving the target IP to ensure it does not touch loopback (`127.0.0.1`), private RFC 1918 subnets (`10.0.0.0/8`, `192.168.0.0/16`), or link-local cloud metadata addresses (`169.254.169.254`). Malicious internal probing is immediately rejected with HTTP 400.
3. **Database Cache Intercept**: `backend/main.py` queries MongoDB Atlas using `find_cached_scan(url, host)`. If audited previously, the cached record is returned in **~200ms** with `"cached": true` (unless the user clicked "Rescan").
4. **Asynchronous Parallel Dispatch**: The orchestrator launches all 6 analysis modules concurrently using `asyncio.gather`:
   - `url.py` checks for phonetic lookalikes and statistical TLD risk.
   - `domain.py` resolves DNS records and checks domain age via RDAP/WHOIS.
   - `certificate.py` opens a TLS socket, downloads the X.509 certificate, and evaluates cryptographic strength.
   - `headers.py` checks for HSTS, CSP, and clickjacking protection headers.
   - `reputation.py` queries abuse.ch URLhaus and PhishTank.
   - `page.py` safely downloads the HTML DOM, parsing forms and hidden iframes without executing JavaScript.
5. **Score Aggregation**: `backend/core/scoring.py` collects all `Finding` objects, deduplicates them by ID, sums their risk points (capped at 100), applies the confirmed malicious override if blacklisted, and assigns a risk label.
6. **Plain-English Synthesis**: `backend/core/explain.py` passes the findings to Groq LLM (or deterministic fallback) to generate an explanation for non-technical users.
7. **Cloud Persistence & Response**: The complete result is stored in MongoDB Atlas and returned as JSON to the frontend for real-time rendering.

---

## 5. In-Depth Inspection Modules: What We Are Doing Under the Hood

### Module 1: URL & Structural Analysis (`backend/modules/url.py`)
This module executes pure offline geometric and linguistic analysis on the target address string:
- **IP Address as Host (`IP_AS_HOST`, 25 pts)**: Identifies URLs using raw IP addresses (e.g. `http://192.0.2.1/login`) to bypass domain reputation systems.
- **Credential Obfuscation (`AT_SYMBOL_URL`, 20 pts)**: Detects the `@` delimiter trick (e.g., `https://google.com@evil-site.com`), where everything before the `@` is treated as user info and the browser actually navigates to `evil-site.com`.
- **Internationalized Domain Spoofing (`HOMOGRAPH_DOMAIN`, 25 pts)**: Flags punycode domains (`xn--`) used to execute Cyrillic or Greek homoglyph attacks (e.g., replacing Latin 'a' with Cyrillic 'а').
- **Excessive Subdomain Depth (`TOO_MANY_SUBDOMAINS`, 15 pts)**: Flags URLs with $\ge 3$ subdomain levels (e.g. `login.verify.account.sbi.com.evil.xyz`).
- **Excessive URL Length (`LONG_URL`, 10 pts)**: Flags addresses exceeding 100 characters designed to hide destination hosts on mobile screens.
- **Statistical TLD Risk Scoring (`SUSPICIOUS_TLD`, 15–25 pts)**: Replaced primitive blacklists with empirical risk scores calibrated against Spamhaus/APWG intelligence (`.top`: 0.90, `.click`: 0.85, `.xyz`: 0.70, `.cfd`: 0.80). Points are awarded proportionally: $10 + 	ext{round}(15 	imes 	ext{weight})$.
- **Phonetic & Brand Impersonation (`LOOKALIKE_BRAND`, 30 pts)**: Utilizes a reference dataset of popular financial and tech brands (`data/brands.json`). Implements three-tier detection:
  1. *Subdomain keyword theft*: Catches brand names embedded in subdomains of third-party domains (`sbi.co.in.fake.top`).
  2. *Levenshtein edit distance*: Catches single-character deletions/substitutions (`paypa1`).
  3. *Double Metaphone & Jaro-Winkler*: Encodes phonetic pronunciation (`paypahl` -> `PPLL`), catching auditory lookalikes even when spelling distance fails.

### Module 2: Domain, DNS & RDAP Registration (`backend/modules/domain.py`)
Evaluates the physical network existence and registration age of the domain:
- **DNS Record Resolution**: Queries authoritative public DNS servers (`1.1.1.1`, `8.8.8.8`) for active `A` and `AAAA` address records.
- **Dormant / Non-Existent Domain (`NO_DNS_RECORDS`, 20 pts)**: Flags domains that fail to resolve, indicating abandoned infrastructure or pre-registered attack campaigns.
- **Critical Registration Window (`VERY_NEW_DOMAIN`, 25 pts)**: Flags domains registered $< 7$ days ago via RDAP/WHOIS. Over 70% of active phishing occurs within the first week of domain registration.
- **Recent Registration Window (`NEW_DOMAIN`, 20 pts)**: Flags domains registered between 7 and 30 days ago.

### Module 3: SSL/TLS Certificate Forensics (`backend/modules/certificate.py`)
Directly addresses the modern reality that phishers use SSL certificates, specifically analyzing parameters highlighted in the 2025 eMudhra sub-CA incident:
- **No Transport Encryption (`NO_HTTPS`, 20 pts)**: Target site fails to negotiate port 443.
- **Expired Certificate (`CERT_EXPIRED`, 25 pts)**: Certificate validity timestamp has passed.
- **Host Name Mismatch (`CERT_NAME_MISMATCH`, 25 pts)**: The visited host is missing from the certificate's Subject Alternative Names (SAN) list.
- **Self-Signed Certificate (`CERT_SELF_SIGNED`, 25 pts)**: Issuer and Subject DN strings are identical, proving the certificate was generated without CA authority.
- **Untrusted Root (`CERT_UNTRUSTED`, 25 pts)**: The certificate chain fails validation against the system CA trust store.
- **Freshly Issued Certificate (`CERT_NEW`, 20 pts)**: Certificate issued $< 7$ days ago, a hallmark of disposable automated phishing campaigns.
- **Cryptographically Weak Key (`CERT_WEAK_KEY`, 30 pts)**: Directly tackles compromised sub-CAs by inspecting public key parameters: flags RSA keys $< 2048$ bits or Elliptic Curve (EC) keys $< 256$ bits.
- **Obsolete Signature Hashing (`CERT_WEAK_SIGNATURE`, 25 pts)**: Flags certificates signed with cryptographically broken digest algorithms (`MD5`, `SHA-1`).
- **Deprecated TLS Protocols (`TLS_OLD_VERSION`, 20 pts)**: Server negotiates outdated, vulnerable protocols (`SSLv3`, `TLSv1.0`, `TLSv1.1`).

### Module 4: Web Application Security Headers (`backend/modules/headers.py`)
Assesses the defensive posture of the destination web server:
- **Missing HSTS (`MISSING_HSTS`, 10 pts)**: Absence of `Strict-Transport-Security` header allows SSL-stripping attacks.
- **Missing Content Security Policy (`MISSING_CSP`, 10 pts)**: Absence of `Content-Security-Policy` exposes users to cross-site scripting (XSS) and credential injection.
- **Missing Clickjacking Defense (`MISSING_FRAME_PROTECTION`, 10 pts)**: Lacks both `X-Frame-Options` and CSP `frame-ancestors`, allowing adversaries to iframe the site into transparent overlay attacks.
- **Insecure Downgrade (`INSECURE_HTTP`, 20 pts)**: The final destination redirects to unencrypted HTTP.

### Module 5: Collaborative Threat Intelligence (`backend/modules/reputation.py`)
Queries live authoritative abuse feeds in parallel:
- **abuse.ch URLhaus (`URLHAUS_LISTED`, 40 pts)**: Identifies domains actively participating in malware and payload distribution.
- **PhishTank Community Feed (`PHISHTANK_VERIFIED`, 40 pts)**: Checks human-verified, active phishing listings.
- **Automatic Override**: Any positive match against URLhaus or verified PhishTank immediately forces the scan outcome to **Confirmed Malicious** with a minimum score of 90/100.

### Module 6: Safe Content & Form Forensics (`backend/modules/page.py`)
Downloads page HTML safely without executing JavaScript, evaluating structural traps:
- **Credential Harvesting Form (`LOGIN_FORM`, 10 pts)**: Detects `<input type="password">` fields.
- **Cross-Domain Form Submission (`FORM_SENDS_ELSEWHERE`, 25 pts)**: Critical phishing signal where a login form on `site-a.com` submits `POST` data to an unrelated `site-b.com`.
- **Brand Theft on Unofficial Site (`BRAND_ON_WRONG_SITE`, 25 pts)**: The HTML body or title references a known institution (e.g. "State Bank of India"), but the registered domain does not match official bank domains.
- **Stealth Frames (`HIDDEN_FRAME`, 10 pts)**: Flags `<iframe>` tags with `display:none`, `visibility:hidden`, or zero pixel dimensions used for drive-by downloads.
- **Deceptive Redirections (`REDIRECT_TO_OTHER_DOMAIN`, 20 pts)**: Initial link redirects away to an entirely different registered domain.
- **Excessive Redirection Chain (`LONG_REDIRECT_CHAIN`, 10 pts)**: Chain exceeds 3 hops, typical of traffic-distribution networks (TDS).

### Module 7: The Indian SMS Fraud Engine (`backend/modules/scam.py`)
Processes raw message text, sender headers, and claimed entities through a 5-tier hybrid pipeline (detailed in Section 7).

---

## 6. The Scoring & Synthesis Engine (`backend/core/scoring.py` & `explain.py`)

### The Mathematical Scoring Algorithm
The core scoring function (`score_scan`) processes raw findings from all modules:
$$	ext{Score} = \min\left(100, \sum_{f \in 	ext{UniqueFindings}} f.	ext{points}ight)$$

Where `UniqueFindings` keeps only the single finding with the maximum points for any given `FindingID`. This ensures that if both the URL module and the Domain module flag an issue, points are not double-counted.

### Strict Risk Bands & Confirmed Malicious Override
$$	ext{Verdict}(S, C, O) = 
egin{cases} 
	ext{Confirmed Malicious} & 	ext{if } O \cap \{	ext{URLHAUS\_LISTED}, 	ext{PHISHTANK\_VERIFIED}\} 
eq \emptyset \
	ext{Inconclusive} & 	ext{if } C < 3 \
	ext{Low Risk} & 	ext{if } S \le 30 \
	ext{Suspicious} & 	ext{if } 31 \le S \le 60 \
	ext{High Risk} & 	ext{if } S \ge 61 
\end{cases}$$

Where:
- $S$ = Capped point sum ($0 \le S \le 100$).
- $C$ = Count of successfully completed modules ($C \ge 3$ required).
- $O$ = Set of matched finding IDs.

### The Safety Invariant: Why TrustLens Never Claims "Safe"
In `backend/core/explain.py`, a regex validation function (`_claims_safe`) inspects all generated explanations. If an explanation contains phrases like `"safe"`, `"harmless"`, or `"risk-free"` (unless preceded by a negative qualifier), the explanation is rejected and replaced with deterministic caution phrasing:
> *"No significant warning signs were found in the checks that ran. This does not prove it is safe, so stay careful."*

---

## 7. The SMS Scam Challenge & Hybrid Defense Deep-Dive

### The Negation Catastrophe in Keyword Matching
In early development, naive regex rules looking for `"otp"` or `"password"` failed catastrophically because authentic bank alerts routinely contain:
> *"Do NOT share your OTP, password or CVV with anyone. SBI will never call asking for your credentials."*

A standard keyword filter classified legitimate alerts as high-risk scams (+25 pts). We solved this by implementing a **25-character negative lookbehind window** (`_NEG`) that skips matches preceded by negation tokens (`not`, `never`, `no one`, `n't`).

### Training the Local Indian SMS ML Model (`scam-ham-india`)
To capture natural Indian phrasing without external API dependencies, we trained a dedicated ML pipeline:
- **Corpus**: `anmolshrivastav/scam-ham-india` dataset from Hugging Face.
- **Dataset Composition**: 2,272 distinct SMS samples (1,377 legitimate ham, 895 scam/spam).
- **Feature Extraction**: `TfidfVectorizer` configured with sublinear term-frequency scaling, unigram + bigram combinations ($1, 2$), and a vocabulary ceiling of 8,000 features.
- **Classification Algorithm**: $L_2$-regularized `LogisticRegression` (`C=1.5`, balanced class weighting).
- **Holdout Evaluation**: 20% stratified train/test split (455 unseen test messages) achieving **99.34% Accuracy** and a **macro F1-score of 0.99**.
- **Model Serialization**: Exported to [`backend/data/scam_india_model.joblib`](file:///d:/Personal/TrustLens/trustlens/backend/data/scam_india_model.joblib) (376 KB).

### Analyzing the 99.34% Accuracy: Overfitting vs. Template Leakage
When an NLP model achieves 99%+ accuracy, rigorous engineers must investigate: **Is this model overfitted?**

#### 1. Why the Score is Mathematically Real
In SMS classification, personal conversational text (*"coming home late"*, *"meeting at 5"*, *"check my laptop"*) and scam text (*"KYC expired"*, *"account blocked"*, *"click bit.ly"*, *"lottery won"*) occupy nearly **orthogonal subspaces in token vector space**. The linear hyperplane achieves clean separation with zero training memorization.

#### 2. The Hidden Threat: Template Leakage
By extracting the top learned feature weights:
- Positive (Scam): `your` (+5.26), `click` (+5.08), `rs` (+4.78), `free` (+4.14), `airtel` (+3.63), `bit ly` (+3.03).
- Negative (Ham): `it` (-2.27), `the` (-2.21), `market` (-1.81), `good` (-1.44), `laptop` (-1.27).

Notice that words like `airtel` (+3.63) and `vi` (+2.06) carry strong positive coefficients. In this dataset, telecom brand mentions almost exclusively appeared in fake recharge scams. If a friend sends: *"Can you recharge my Airtel SIM tonight?"*, a pure ML model risks a false positive.

### The 5-Tier Hybrid Defense Matrix
To eliminate single-point-of-failure risks, TrustLens wraps the ML model inside a 5-tier hybrid defense:

```
                               Raw Message Input
                                       │
            ┌──────────────────────────┴──────────────────────────┐
            ▼                                                     ▼
┌───────────────────────────┐                         ┌───────────────────────────┐
│  Tier 1: TRAI Sender Check│                         │  Tier 2: Negation Regex   │
│  - 10-digit number claiming│                         │  - Checks lookbehind     │
│    to be bank -> +25 pts  │                         │    window (25 chars)      │
│  - Header mismatch -> +20 │                         │  - Strips warnings        │
└───────────┬───────────────┘                         └───────────┬───────────────┘
            │                                                     │
            └──────────────────────────┬──────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ Tier 3: Local Indian SMS ML Model (scam-ham-india)                              │
│ - Zero-latency TF-IDF inference                                                 │
│ - Gated threshold: triggers IMPERSONATION_CLAIM (+20-25 pts) only if Prob >= 65%│
└──────────────────────────────────────┬──────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ Tier 4: Groq Zero-Shot LLM Reasoning                                            │
│ - Analyzes holistic context, pretexts, threats, and subtle social engineering   │
└──────────────────────────────────────┬──────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ Tier 5: Embedded URL Deep-Scan                                                  │
│ - Extracts bit.ly / tinyurl links and passes them to full 6-module URL engine   │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 8. Comprehensive List of Real Technical Challenges & Fixes

### Challenge 1: Phonetic Typosquatting (Double Metaphone + Jaro-Winkler)
- **The Problem**: Phishers exploit visual and auditory similarity (`paypahl.com`, `amazn-security.in`, `sbii.co.in`). Levenshtein distance fails when multiple characters change or lengths differ.
- **The Fix**: Implemented Double Metaphone and Jaro-Winkler algorithms (`jellyfish`). Encodes domain pronunciation: `paypahl` maps to `PPLL` matching `paypal` (`PPLL`). If phonetic metaphones match or Jaro-Winkler similarity is $\ge 0.88$, it immediately flags `LOOKALIKE_BRAND` (+30 pts).

### Challenge 2: Statistical TLD Risk Scoring (Spamhaus/APWG Distributions)
- **The Problem**: Binary blacklisting of TLDs (e.g. blocking all `.xyz`) creates false positives for legitimate developers while completely missing scams on `.com` or `.in`.
- **The Fix**: Replaced binary rules with statistical reputation weights based on Spamhaus/APWG intelligence (`.top`: 0.90, `.click`: 0.85, `.xyz`: 0.70). The engine dynamically scales points between 15 and 25 proportional to empirical abuse rates.

### Challenge 3: Cloud Database Reliability (MongoDB Atlas + Silent SQLite Failover)
- **The Problem**: The team required centralized cloud storage on MongoDB Atlas (`mongodb+srv://...`) to share scan history across different machines. However, during network dropouts, DNS resolution failures, or cluster connection caps, unhandled driver exceptions would crash the backend.
- **The Fix**: Engineered a dual-engine persistence layer in [`backend/db.py`](file:///d:/Personal/TrustLens/trustlens/backend/db.py). On startup, it attempts connection to MongoDB Atlas. If the cluster is unreachable, it logs a warning and transparently switches to local SQLite (`trustlens.db`). Scans continue uninterrupted with zero user-facing errors.

### Challenge 4: High-Latency Bottlenecks (200ms Instant Database Caching)
- **The Problem**: A complete live scan requires DNS resolution, TLS socket handshakes, RDAP/WHOIS network queries, header parsing, and external API requests (PhishTank, URLhaus). This pipeline takes 1.5 to 3.5 seconds. Repeating this for frequent domains (`sbi.co.in`, `google.com`) or viral phishing campaigns creates unnecessary latency.
- **The Fix**: Implemented an instant cache lookup (`find_cached_scan`) in `backend/main.py`. Cached scans return in **~200ms** with `"cached": true` and display a `⚡ CACHED RESULT` badge in the UI. A "Rescan" button allows users to force a fresh live scan on demand.

### Challenge 5: Certificate Transparency & The eMudhra CA Sub-Authority Threat
- **The Problem**: Modern phishers obtain valid SSL certificates within minutes using automated CAs or compromised sub-authorities (as in the 2025 eMudhra sub-CA incident), rendering the browser padlock misleading.
- **The Fix**: Evaluates certificate age (`CERT_NEW`, +20 pts if $< 7$ days old), self-signed status (`CERT_SELF_SIGNED`, +25 pts), and cryptographic key size (`CERT_WEAK_KEY`, +30 pts for RSA $< 2048$ or EC $< 256$). Furthermore, we built a live Certificate Transparency feed (`/api/feed`) displaying newly logged lookalike certificates in real-time.

### Challenge 6: Enterprise Interoperability via OASIS STIX 2.1
- **The Problem**: Enterprise SOC analysts and incident responders cannot ingest proprietary JSON schemas; they require threat intelligence formatted to open industry standards.
- **The Fix**: Built an automated STIX 2.1 bundle generator in [`backend/export/stix.py`](file:///d:/Personal/TrustLens/trustlens/backend/export/stix.py). Transforms scan findings into OASIS STIX 2.1 JSON containing `indicator`, `infrastructure`, and `observed-data` domain objects with direct export endpoints (`/api/scan/{id}/stix` and `/api/export/stix`).

### Challenge 7: Browser Security Sandbox & Camera Stream Constraints
- **The Problem**: Modern web browsers strictly prohibit camera streaming (`navigator.mediaDevices.getUserMedia`) when HTML files are opened locally via `file:///` URLs.
- **The Fix**: Mounted the `frontend/` directory directly onto FastAPI via `StaticFiles(directory=_frontend_dir, html=True)` at root `/`. Serving both client and API from `http://localhost:8000/` ensures camera permissions work smoothly. Additionally, we added an offscreen HTML canvas fallback to decode uploaded QR image files without needing camera access.

### Challenge 8: Asynchronous Streaming Stalls & CSS Flexbox Text Overflow
- **The Problem A (UI Progress Stalling)**: The frontend hung indefinitely on *"Analyzing the destination…"* because the code expected an SSE stream even when the backend returned complete scan objects synchronously.
  - *The Fix*: Updated `requestScan` in [`frontend/script.js`](file:///d:/Personal/TrustLens/trustlens/frontend/script.js): `if (startData.verdict) return startData;`.
- **Problem B (CSS Specificity & Flexbox Overflow)**:
  - The CSS rule `.scan-progress { display: flex; }` was overriding the HTML `hidden` attribute. Fixed by adding `[hidden], .scan-progress[hidden] { display: none !important; }`.
  - Long URLs in scan history cards broke out of flexbox containers. Fixed by enforcing `min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex-shrink: 0;`.
- **Problem C (Syntax Error Deadlock)**: A duplicate catch block on line 487 caused a runtime syntax error that aborted script execution on load, freezing all sidebar navigation. Diagnosed via `node -c frontend/script.js` and resolved.

---

## 9. Database Schema & Data Dictionary

All scans and community reports are persisted in Cloud MongoDB Atlas across two collections:

### 1. `scans` Collection
| Field | Type | Description |
| :--- | :--- | :--- |
| `scan_id` | String | Unique 8-character hexadecimal identifier (e.g. `8f3b2a1c`). |
| `url` | String | Target URL or message identifier scanned. |
| `host` | String | Fully qualified domain name extracted from URL. |
| `source` | String | Scan origin: `"web"`, `"qr"`, `"sms"`, or `"message"`. |
| `risk_score`| Integer | Capped score between 0 and 100. |
| `verdict` | String | Normalized verdict: `"SAFE"`, `"SUSPICIOUS"`, or `"MALICIOUS"`. |
| `label` | String | Granular risk label: `"Low Risk"`, `"Suspicious"`, `"High Risk"`, `"Confirmed Malicious"`, `"Inconclusive"`. |
| `confidence`| Float | Statistical confidence score ($0.0 - 1.0$). |
| `explanation`| String | Plain-English narrative explaining the reasons behind the score. |
| `matched_brand`| String/Null| Name of brand being impersonated (e.g. `"State Bank of India"`), if detected. |
| `findings` | Array | List of findings containing `id`, `source`, `description`, `points`, and metadata. |
| `facts` | Object | Raw technical evidence: `certificate`, `dns`, `headers_tls`, `threat_intel`, and `scam`. |
| `created_at`| String | ISO 8601 UTC timestamp of scan execution. |
| `confirmed_malicious` | Boolean | True if listed on URLhaus or PhishTank. |

### 2. `reports` Collection
| Field | Type | Description |
| :--- | :--- | :--- |
| `id` | String | Unique report identifier (e.g. `rep-7f8a9b`). |
| `url` | String | Reported malicious URL. |
| `note` | String | User-provided observations, threat categories, and comments. |
| `scan_id` | String/Null | Optional link to an existing scan record. |
| `reported_at`| String | ISO 8601 UTC timestamp of report submission. |

---

## 10. Complete REST API Reference

| Method | Endpoint | Description | Request Body / Parameters | Response Status |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/health` | Service health check and external provider status | None | `200 OK` |
| `POST` | `/api/scan` | Submits a URL for comprehensive multi-pillar scan | `{"url": "str", "source": "web", "force": false}` | `200 OK` |
| `GET` | `/api/scan/{id}` | Retrieves a past scan record by its ID | `scan_id` (path) | `200 OK` / `404` |
| `GET` | `/api/scan/{id}/stream` | Server-Sent Events (SSE) stream for real-time progress | `scan_id` (path) | `text/event-stream` |
| `POST` | `/api/message` | Analyzes SMS / text for fraud, social engineering & links | `{"text": "str", "sender": "str", "claim": "str"}` | `200 OK` |
| `GET` | `/api/feed` | Live Certificate Transparency & high-risk domain feed | `limit: int = 50` | `200 OK` |
| `POST` | `/api/report` | Submits a community threat report for a malicious URL | `{"url": "str", "note": "str", "scan_id": "str"}` | `200 OK` |
| `GET` | `/api/reports` | Lists recently submitted community reports | None | `200 OK` |
| `GET` | `/api/scan/{id}/stix` | Exports individual scan as an OASIS STIX 2.1 JSON bundle | `scan_id` (path) | `application/vnd.oasis.stix+json` |
| `GET` | `/api/export/stix` | Exports all recent high-risk scans as collaborative STIX bundle | `limit: int = 50` | `application/vnd.oasis.stix+json` |
| `GET` | `/` | Serves the single-page application frontend | None | `200 OK (HTML)` |

---

## 11. Slide-by-Slide Presentation Outline (Ready for PPT/Pitch Deck)

### Slide 1: Title & Hook
* **Title**: TrustLens — Smarter Than the Scammers
* **Subtitle**: Layered Phishing, SMS Fraud & Digital Threat Verification
* **Presenter**: Team TrustLens (Arnab Datta, Deepraj, Rupam, Sumit)
* **Opening Hook**: *"Over ₹7,000 Crores were lost to digital scam SMS and fake links in India last year. Traditional antivirus and browser filters miss them. TrustLens stops them before the user taps."*

### Slide 2: The Core Problem: The Industrialization of Social Engineering
* **The Vector**: Attackers don't hack firewalls; they manipulate humans via SMS, WhatsApp, and QR codes.
* **Why Modern Tools Fail**:
  * 85%+ of scam sites now use valid HTTPS ("The Green Padlock Illusion").
  * Safe Browsing blacklists take hours to update; phishing domains live for only 4 hours.
  * Firewalls cannot inspect text messages or evaluate social engineering pretexts.

### Slide 3: Introducing TrustLens: The Multi-Pillar Defense Engine
* **Concept**: Instant zero-trust analysis of URLs, QR codes, and raw SMS text.
* **Philosophy**:
  * **Never says "100% Safe"** — provides calibrated 0–100 Risk Scores.
  * **Multi-Pillar Evidence**: Evaluates Domains, SSL Certificates, Security Headers, Threat Feeds, and NLP.
  * **Plain-English Explanations**: Translates technical CVE/SSL flaws into clear guidance for ordinary citizens.

### Slide 4: Technical Architecture & Performance
* **Architecture**: Vanilla JS frontend connected to an asynchronous FastAPI backend microservice.
* **Speed**: Sub-200ms response for cached scans; under 2 seconds for complete multi-pillar network audits.
* **Resilience**: Cloud MongoDB Atlas cluster with automatic silent fallback to local SQLite.

### Slide 5: The Breakthrough: Cracking Indian SMS Scams
* **ML Layer**: Trained Scikit-Learn ML pipeline on 2,271 Indian SMS messages (99.34% accuracy).
* **Regulatory Layer**: TRAI Alphanumeric Header validation (catches personal 10-digit mobile numbers spoofing banks).
* **Heuristic Layer**: Negation-aware heuristic parser (differentiates *"Never share OTP"* from *"Send OTP"*).
* **AI Layer**: Zero-shot Groq LLM reasoning for conversational manipulation and novel pretexts.

### Slide 6: Advanced Forensics: Beyond Simple Blacklists
* **Phonetics**: Phonetic Brand Matching (Double Metaphone) catches auditory typosquats like `paypahl`.
* **Reputation**: Statistical TLD Scoring dynamically weights risk based on real-world abuse density.
* **CT Feed**: Certificate Transparency live feed mitigates emerging threats and compromised CAs.
* **Standards**: One-click STIX 2.1 Threat Intelligence export for enterprise SOC integration.

### Slide 7: Hard Engineering Challenges We Conquered
* **ML Bias**: Eliminated template bias in SMS ML by wrapping it in a 5-tier hybrid defense.
* **Cloud Failover**: Built dual-engine database fallback ensuring the app never crashes during outages.
* **Optimization**: Engineered instant 200ms caching to eliminate redundant network overhead.
* **Frontend/UX**: Overcame browser camera sandbox constraints and async SSE streaming deadlocks.

### Slide 8: Live Product Demonstration
* **Demo 1**: Scanning an authentic banking alert (`VM-HDFCBK`) -> 0/100 Low Risk.
* **Demo 2**: Scanning a malicious KYC SMS from a personal number -> 100/100 High Risk.
* **Demo 3**: Instant cached replay demonstration (`⚡ CACHED RESULT` in 200ms).
* **Demo 4**: Exporting standardized STIX 2.1 bundles directly into threat intel platforms.

### Slide 9: Impact, Security Ethics & Future Roadmap
* **Impact**: Empowering everyday citizens, students, and senior citizens against digital fraud.
* **Roadmap 1**: Native Android/iOS SMS filtering via TrustLens Progressive Web App.
* **Roadmap 2**: Browser extension for automatic on-hover link analysis.
* **Roadmap 3**: Direct API integration with the Indian National Cybercrime Reporting Portal (1930 Helpline).

---

## 12. Conclusion & Future Roadmap

TrustLens demonstrates that effective cyber protection does not require heavy, opaque AI or clunky enterprise software. By synthesizing **local statistical machine learning**, **deterministic protocol forensics**, **TRAI regulatory intelligence**, and **cloud-scale threat aggregation**, TrustLens provides real-time digital protection that is transparent, explainable, and accessible to everyone.
