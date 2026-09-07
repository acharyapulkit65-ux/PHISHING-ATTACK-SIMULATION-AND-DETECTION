# Phishing Detection Scanner

A heuristic-based Python tool that scans `.eml` email files and produces
a phishing-risk score (0-100) with the specific reasons behind it. Pure
stdlib for the core logic (`email`, `re`, `urllib`) — nothing to install.

## What it checks

| Category | Signals |
|---|---|
| **Headers** | Display-name/domain mismatch (e.g. "PayPal Support" from a `.ru` address), Reply-To ≠ From domain, SPF/DKIM/DMARC results from `Authentication-Results` |
| **Language** | Urgency/pressure phrasing ("verify immediately", "account suspended", "act now"...) |
| **Links** | Typosquat detection via edit-distance against known brand domains, brand name embedded in a non-brand domain, raw IP links, URL shorteners, suspicious TLDs, unusually deep subdomains |
| **Attachments** | Risky extensions (.exe, .scr, .js, .docm...), double-extension disguises (`invoice.pdf.exe`) |

Each signal adds points; the total is capped at 100 and mapped to
CLEAN / LOW / MEDIUM / HIGH.

## Usage

```bash
# Single file
python3 phishing_scanner.py --file suspicious_email.eml

# Whole folder, plus a machine-readable report
python3 phishing_scanner.py --dir /path/to/eml_folder --json report.json
```

### Getting a .eml file to test
Most mail clients let you export a single message:
- **Gmail**: open the email → ⋮ menu → "Show original" → "Download original"
- **Outlook**: open the email → File → Save As → choose .eml
- **Apple Mail**: drag the email from the list onto your desktop

Two sample files are included (`sample_phishing.eml`, `sample_legit.eml`)
so you can see the scoring in action immediately:

```bash
python3 phishing_scanner.py --dir . --json report.json
```

## Tuning it

- `brand_list.json` holds the brand domains, suspicious TLDs, URL
  shorteners, risky attachment extensions, and urgency keywords. Add
  your own organization's brand/domain to catch impersonation of *you*.
- Point weights live in `phishing_scanner.py` inside each `_check_*`
  method if you want to re-tune sensitivity.

## Limitations (important)

- **No live DNS/WHOIS lookups** — domain-age checks aren't included, to
  keep this dependency-free and runnable offline. Adding `python-whois`
  or `dnspython` would let you flag newly-registered domains, a strong
  phishing signal.
- **SPF/DKIM/DMARC results are read from the `Authentication-Results`
  header**, i.e. whatever your mail server already decided — this tool
  doesn't re-verify cryptographic signatures itself.
- Heuristic scoring will have false positives/negatives. Treat scores as
  triage priority, not a final verdict — especially in the LOW/MEDIUM band.

## Natural next steps
1. Add domain-age lookups (`python-whois`) — brand-new domains are a strong signal
2. Add a live IMAP/mailbox connector so it scans incoming mail automatically
3. Train a small ML classifier (e.g. on the public Nazario phishing corpus + Enron ham) to complement the heuristics
4. Add homoglyph detection (e.g. Cyrillic "а" vs Latin "a") for more sophisticated typosquats
