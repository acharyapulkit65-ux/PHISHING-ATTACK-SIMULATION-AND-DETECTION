#!/usr/bin/env python3
"""
Phishing Detection Scanner
===========================
Parses .eml files (standard email format) and produces a heuristic
phishing-risk score with the specific reasons behind it.

This is purely defensive / analytical: it reads and scores email files
you already have. It does not send anything, spoof anything, or generate
phishing content.

Usage:
    python3 phishing_scanner.py --file suspicious_email.eml
    python3 phishing_scanner.py --dir /path/to/eml_folder --json report.json

How to get a .eml file to test:
    Most mail clients (Outlook, Gmail, Apple Mail) let you export/download
    a single message as ".eml" via "Show original" / "Download message" /
    drag-and-drop onto the desktop.
"""

import argparse
import email
import json
import re
import sys
from dataclasses import dataclass, field
from email.message import Message
from pathlib import Path
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Load brand / keyword reference data
# ---------------------------------------------------------------------------

def load_brand_data(path: str) -> dict:
    with open(path, "r") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def levenshtein(a: str, b: str) -> int:
    """Simple edit-distance implementation (no external dependency)."""
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)

    prev_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        cur_row = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            cur_row.append(min(
                prev_row[j] + 1,      # deletion
                cur_row[j - 1] + 1,   # insertion
                prev_row[j - 1] + cost,  # substitution
            ))
        prev_row = cur_row
    return prev_row[-1]


def extract_domain(address_or_url: str) -> str:
    """Pull a bare domain out of an email address or URL."""
    address_or_url = address_or_url.strip().strip("<>")
    if "@" in address_or_url and "://" not in address_or_url:
        return address_or_url.split("@")[-1].lower()
    parsed = urlparse(address_or_url if "://" in address_or_url
                       else "http://" + address_or_url)
    return (parsed.netloc or parsed.path).lower().split(":")[0]


def find_urls(text: str) -> list:
    url_pattern = re.compile(r'https?://[^\s\'"<>\)\]]+')
    return url_pattern.findall(text or "")


def get_body_text(msg: Message) -> str:
    """Extract plain text (and stripped HTML) body from an email.message.Message."""
    parts = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition") or "")
            if "attachment" in disp:
                continue
            if ctype in ("text/plain", "text/html"):
                try:
                    payload = part.get_payload(decode=True)
                    charset = part.get_content_charset() or "utf-8"
                    parts.append(payload.decode(charset, errors="replace"))
                except Exception:
                    continue
    else:
        try:
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset() or "utf-8"
            if payload:
                parts.append(payload.decode(charset, errors="replace"))
        except Exception:
            pass
    return "\n".join(parts)


def get_attachments(msg: Message) -> list:
    names = []
    if msg.is_multipart():
        for part in msg.walk():
            disp = str(part.get("Content-Disposition") or "")
            filename = part.get_filename()
            if filename and ("attachment" in disp or part.get_content_maintype() != "text"):
                names.append(filename)
    return names


# ---------------------------------------------------------------------------
# Finding / result structures
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    points: int
    reason: str


@dataclass
class ScanResult:
    file: str
    subject: str = ""
    sender: str = ""
    score: int = 0
    risk_level: str = "low"
    findings: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "subject": self.subject,
            "sender": self.sender,
            "score": self.score,
            "risk_level": self.risk_level,
            "findings": [{"points": f.points, "reason": f.reason} for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

class PhishingScanner:
    def __init__(self, brand_data: dict):
        self.brands = brand_data["protected_brands"]
        self.suspicious_tlds = brand_data["suspicious_tlds"]
        self.shorteners = brand_data["url_shorteners"]
        self.risky_extensions = brand_data["risky_attachment_extensions"]
        self.urgency_keywords = [k.lower() for k in brand_data["urgency_keywords"]]

    def scan_file(self, filepath: str) -> ScanResult:
        with open(filepath, "rb") as f:
            msg = email.message_from_binary_file(f)

        result = ScanResult(file=filepath)
        result.subject = msg.get("Subject", "") or ""
        from_header = msg.get("From", "") or ""
        result.sender = from_header

        findings = []
        findings += self._check_headers(msg, from_header)
        findings += self._check_urgency_language(result.subject, get_body_text(msg))
        findings += self._check_urls(get_body_text(msg), from_header)
        findings += self._check_attachments(get_attachments(msg))

        result.findings = findings
        result.score = min(100, sum(f.points for f in findings))
        result.risk_level = self._score_to_level(result.score)
        return result

    @staticmethod
    def _score_to_level(score: int) -> str:
        if score >= 60:
            return "HIGH"
        if score >= 30:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return "CLEAN"

    # -- individual checks --------------------------------------------------

    def _check_headers(self, msg: Message, from_header: str) -> list:
        findings = []

        # Display-name / actual-address mismatch, e.g. "PayPal Support <x@evil.ru>"
        display_match = re.match(r'^"?([^"<]*)"?\s*<(.+)>$', from_header.strip())
        if display_match:
            display_name, actual_addr = display_match.groups()
            actual_domain = extract_domain(actual_addr)
            for brand in self.brands:
                if brand["name"].lower() in display_name.lower() and \
                        brand["domain"] not in actual_domain:
                    findings.append(Finding(
                        25,
                        f"Display name claims to be '{brand['name']}' but sending "
                        f"address domain is '{actual_domain}', not '{brand['domain']}'"
                    ))

        # Reply-To differs from From domain
        reply_to = msg.get("Reply-To")
        if reply_to:
            from_domain = extract_domain(from_header)
            reply_domain = extract_domain(reply_to)
            if from_domain and reply_domain and from_domain != reply_domain:
                findings.append(Finding(
                    15,
                    f"Reply-To domain ('{reply_domain}') differs from From domain "
                    f"('{from_domain}') -- replies get redirected elsewhere"
                ))

        # Authentication-Results header (SPF/DKIM/DMARC), if present
        auth_results = msg.get("Authentication-Results", "") or ""
        if auth_results:
            for mech in ("spf", "dkim", "dmarc"):
                m = re.search(rf'{mech}=(\w+)', auth_results, re.IGNORECASE)
                if m and m.group(1).lower() in ("fail", "softfail", "none"):
                    findings.append(Finding(
                        20,
                        f"{mech.upper()} check result: {m.group(1)}"
                    ))
        else:
            findings.append(Finding(
                5, "No Authentication-Results header found -- SPF/DKIM/DMARC "
                   "status could not be verified from this file"
            ))

        return findings

    def _check_urgency_language(self, subject: str, body: str) -> list:
        findings = []
        combined = f"{subject}\n{body}".lower()
        hits = [kw for kw in self.urgency_keywords if kw in combined]
        if hits:
            # cap contribution so one email full of buzzwords doesn't maximize alone
            points = min(25, 5 * len(hits))
            shown = ", ".join(sorted(set(hits))[:5])
            findings.append(Finding(
                points,
                f"Urgency/pressure language detected ({len(hits)} phrase(s), e.g. {shown})"
            ))
        return findings

    def _check_urls(self, body: str, from_header: str) -> list:
        findings = []
        urls = find_urls(body)
        if not urls:
            return findings

        sender_domain = extract_domain(from_header)
        seen_domains = set()

        for url in urls:
            domain = extract_domain(url)
            if not domain or domain in seen_domains:
                continue
            seen_domains.add(domain)

            # Raw IP address as the link target
            if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
                findings.append(Finding(20, f"Link points to a raw IP address: {domain}"))
                continue

            # URL shortener
            if domain in self.shorteners:
                findings.append(Finding(10, f"Link uses a URL shortener ({domain}), true destination is hidden"))

            # Suspicious TLD
            if any(domain.endswith(tld) for tld in self.suspicious_tlds):
                findings.append(Finding(10, f"Link domain uses a commonly-abused TLD: {domain}"))

            # Excessive subdomains (e.g. paypal.com.verify-login.ru)
            if domain.count(".") >= 3:
                findings.append(Finding(10, f"Link domain has an unusually deep subdomain structure: {domain}"))

            # Look-alike / typosquat of a known brand.
            # A domain that IS the brand's domain, or a genuine subdomain of it
            # (e.g. "www.amazon.com", "mail.amazon.com"), is legitimate -- skip it.
            bare_domain = domain[4:] if domain.startswith("www.") else domain
            for brand in self.brands:
                is_legit_subdomain = (bare_domain == brand["domain"] or
                                       bare_domain.endswith("." + brand["domain"]))
                if is_legit_subdomain:
                    continue

                dist = levenshtein(bare_domain, brand["domain"])
                if 0 < dist <= 2 and len(bare_domain) >= len(brand["domain"]) - 3:
                    findings.append(Finding(
                        30,
                        f"Link domain '{domain}' closely resembles known brand "
                        f"domain '{brand['domain']}' (edit distance {dist}) -- possible typosquat"
                    ))
                elif brand["domain"].split(".")[0] in bare_domain:
                    findings.append(Finding(
                        25,
                        f"Link domain '{domain}' contains brand name '{brand['name']}' "
                        f"but is not the real domain '{brand['domain']}'"
                    ))

            # Link domain doesn't match sender domain at all (weaker signal, small points)
            bare_sender = sender_domain[4:] if sender_domain.startswith("www.") else sender_domain
            if sender_domain and bare_domain != bare_sender and bare_sender not in bare_domain:
                findings.append(Finding(3, f"Link domain '{domain}' differs from sender domain '{sender_domain}'"))

        return findings

    def _check_attachments(self, attachments: list) -> list:
        findings = []
        for name in attachments:
            lower = name.lower()
            for ext in self.risky_extensions:
                if lower.endswith(ext):
                    findings.append(Finding(20, f"Risky attachment type: {name}"))
                    break
            # double-extension trick, e.g. invoice.pdf.exe
            if lower.count(".") >= 2:
                second_last_ext = "." + lower.rsplit(".", 2)[1]
                common_docs = (".pdf", ".doc", ".xls", ".jpg", ".png", ".txt")
                if second_last_ext in common_docs and any(lower.endswith(e) for e in self.risky_extensions):
                    findings.append(Finding(15, f"Double-extension disguise pattern: {name}"))
        return findings


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_report(result: ScanResult) -> None:
    print("=" * 70)
    print(f"File:    {result.file}")
    print(f"Subject: {result.subject}")
    print(f"From:    {result.sender}")
    print(f"Score:   {result.score}/100   Risk level: {result.risk_level}")
    print("-" * 70)
    if not result.findings:
        print("No phishing indicators detected.")
    else:
        for f in sorted(result.findings, key=lambda x: -x.points):
            print(f"  [+{f.points:>2}] {f.reason}")
    print("=" * 70)
    print()


def main():
    parser = argparse.ArgumentParser(description="Heuristic phishing email scanner")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", help="Path to a single .eml file")
    group.add_argument("--dir", help="Path to a directory of .eml files")
    parser.add_argument("--brands", default="brand_list.json",
                         help="Path to brand/keyword reference JSON")
    parser.add_argument("--json", help="Optional path to write full JSON report")
    args = parser.parse_args()

    brand_data = load_brand_data(args.brands)
    scanner = PhishingScanner(brand_data)

    files = []
    if args.file:
        files = [args.file]
    else:
        files = [str(p) for p in Path(args.dir).glob("*.eml")]
        if not files:
            print(f"No .eml files found in {args.dir}")
            sys.exit(1)

    results = []
    for filepath in files:
        try:
            result = scanner.scan_file(filepath)
        except Exception as e:
            print(f"Failed to parse {filepath}: {e}")
            continue
        results.append(result)
        print_report(result)

    if args.json:
        with open(args.json, "w") as f:
            json.dump([r.to_dict() for r in results], f, indent=2)
        print(f"Full JSON report written to {args.json}")


if __name__ == "__main__":
    main()
