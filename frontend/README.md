# TrustLens — Vanilla HTML, CSS and JavaScript

This frontend is built with **plain HTML, CSS and JavaScript**. 

## Project files

- `index.html` — website structure and QR-scanner controls
- `style.css` — responsive styling, with comments and readable multi-line formatting
- `script.js` — navigation, URL scanning, QR camera/image decoding, API communication, results, history and reports

## Run the website

1. Install or enable the **Live Server** extension, then right-click `index.html` and choose **Open with Live Server**.
2. The site will open at a localhost address, usually similar to `http://127.0.0.1:5500`.

Camera access is normally available on **HTTPS or localhost**. When you press **Open camera**, allow the browser to use the camera. Use the rear-facing camera on a phone when available. You can also use **Upload QR image** to decode a saved QR-code picture.

## QR scanning flow

1. The browser requests camera access through `navigator.mediaDevices.getUserMedia()`.
2. Camera frames are drawn to a hidden canvas.
3. The `jsQR` library reads the canvas image data. The browser's native `BarcodeDetector` is used as a fallback where supported.
4. TrustLens extracts an HTTP or HTTPS address from the decoded text.
5. The URL is submitted to the backend with `source: "qr"`.
6. The QR destination is **not opened automatically**. The result page displays its verdict, risk score, confidence, explanation and findings returned by the backend.

The `jsQR` library is loaded from jsDelivr in `index.html`, so the browser needs internet access to download that library unless you replace the CDN script with a local copy. The native decoder fallback is browser-dependent.

## Connect the FastAPI backend

The default API address is:

```text
http://localhost:8000
```

Change `API_BASE` near the top of `script.js` if your backend runs elsewhere. The frontend follows the project blueprint API contract:

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/scan` | Starts a scan with `{ "url": "...", "source": "web" }` or source `qr` |
| `GET` | `/api/scan/{scan_id}/stream` | Receives `module_result` and `final` server-sent events |
| `GET` | `/api/scan/{scan_id}` | Polling fallback if the event stream is unavailable |
| `GET` | `/api/feed?limit=50` | Loads recent certificate-transparency feed items |
| `POST` | `/api/report` | Sends a community report with `{ "url": "...", "note": "..." }` |

The backend must allow requests from the frontend origin using CORS. If the frontend and backend use different origins, configure CORS in FastAPI.

## Test the interface without the backend

Open the site with `?mock=1`, for example:

```text
http://127.0.0.1:5500/?mock=1
```

Mock mode allows you to test the URL and QR interfaces, but its scores and verdicts are simulated. **They are not security assessments.** Connect the actual backend before presenting TrustLens as a working threat-detection system.

## Important limitations

- A QR code can contain many kinds of data. This frontend only submits HTTP and HTTPS website URLs for analysis; it does not open QR destinations or process payment, contact, Wi-Fi or other QR payloads.
- Real risk verdicts and potential-risk findings come from the FastAPI backend. The frontend displays the returned verdict, risk score, confidence, explanation, module status and findings; it does not independently determine whether a website is malicious.
- A low risk score is not proof that a website is safe. Review missing or unavailable analysis modules as well as the overall score.

## Message check and scan report pages

Two pages were added to the sidebar with the same pattern as the others (a `data-view` button plus a `<section class="view">`).

- **Check a message** (`view-message`): paste an SMS that claims to come from a bank, college, courier and so on. Five checks score it: sender, message wording, institute match, link structure and a trusted-source lookup. The first four run in the browser (`analyzeMessage()` and the `BRANDS` list in `script.js`). If the message has a link, only that link is sent to the backend through the normal `/api/scan` flow (`source: "web"`) so PhishTank, URLhaus and the other modules can look it up. If the backend cannot be reached, that lookup is listed under "checks that could not run". The message text is never sent to the backend.
- **Scan report** (`view-result`): the full result for the latest scan (link, QR or message), or for any item opened with **Report** in Scan history. It shows the risk label, total points, time of the check, the source of each finding, checks that could not run, what to do next, and the risk-label table.

Risk labels follow blueprint section 4 (`RISK_LABELS` in `script.js`): Low Risk 0 to 30 points, Suspicious 31 to 60, High Risk 61 or more, Confirmed Malicious (a trusted source lists the link; overrides the points) and Inconclusive (fewer than 3 checks worked). The interface never says "safe".

- Confirmed Malicious is shown when the backend sends `"confirmed_malicious": true` (optionally with `"confirmed_by": ["PhishTank"]`), or a high or critical finding whose `id` or `source` names PhishTank or URLhaus. Adjust `trustedListings()` if your backend contract differs.
- When a link lookup also returns a score, the message result uses the higher of the browser-rules points and the backend score.
- In `?mock=1` demo mode, any host containing `phish` simulates a trusted-source listing.
- Message results (sender and the first 200 characters of the text) are stored only in this browser's scan history. Use **Clear history** to remove them.
- Message checks are simple rules. A Low Risk message can still be a scam, so always confirm with the institute directly.

