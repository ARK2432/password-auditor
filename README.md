# Password Strength Auditor — NIST SP 800-63B

A Python CLI tool that audits password strength and enforces modern NIST SP 800-63B
password policy guidelines. Combines Shannon entropy analysis, realistic crack-time
estimation, HaveIBeenPwned breach checking via k-anonymity, and a custom NIST policy engine.

## Features

- **Entropy analysis** — calculates Shannon entropy in bits based on character set and length
- **zxcvbn scoring** — realistic crack-time estimation that simulates attacker strategies
- **HaveIBeenPwned integration** — checks passwords against 800M+ breached credentials using k-anonymity (your password never leaves your machine)
- **NIST 800-63B policy engine** — enforces length, breach, dictionary, sequential pattern, and context-word checks
- **Batch audit mode** — audit a full list of passwords from a file
- **Report export** — JSON and CSV reports with masked passwords (never plaintext)
- **Color-coded terminal output** — green/yellow/red feedback at a glance

## Installation

```bash
git clone https://github.com/yourusername/password-auditor.git
cd password-auditor
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Optional: download a common passwords wordlist

```bash
curl -o wordlists/common_passwords.txt \
  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt
```

## Usage

```bash
# Audit a single password
python auditor.py -p "YourPasswordHere"

# Batch audit from a file (one password per line)
python auditor.py -f sample_passwords.txt

# Skip HIBP check (offline / no internet)
python auditor.py -f sample_passwords.txt --no-hibp

# Audit and export JSON + CSV reports
python auditor.py -f sample_passwords.txt --export

# All options combined
python auditor.py -f sample_passwords.txt --no-hibp --export
```

## Sample output

```
Password : pa*******
----------------------------------------------------
  Length      : 8 characters
  Entropy     : 37.6 bits
  Strength    : Very weak  (zxcvbn score 0/4)
  Crack time  : less than a second  (offline slow hash)
  HIBP check  : BREACHED — seen 9,659,365 times in leaks

  NIST 800-63B: NON-COMPLIANT  (2/5 checks passed)
    FAIL — found in a known credential breach database (HIBP)
    FAIL — matches a commonly used password from known lists
    PASS — length 8 meets minimum (15+ chars recommended)
    PASS — no repetitive or sequential character patterns detected
    PASS — no context-specific words detected
----------------------------------------------------
```

## Project structure

```
password-auditor/
├── auditor.py          # main CLI entry point
├── entropy.py          # Shannon entropy + zxcvbn scoring
├── hibp.py             # HaveIBeenPwned k-anonymity API checker
├── nist_policy.py      # NIST 800-63B compliance rules
├── report.py           # JSON and CSV report generator
├── requirements.txt
├── NIST_COMPLIANCE.md  # full explanation of rules enforced
├── sample_passwords.txt
└── wordlists/
    └── common_passwords.txt
```

## NIST SP 800-63B compliance

See [NIST_COMPLIANCE.md](NIST_COMPLIANCE.md) for a full breakdown of which guidelines are
enforced, why NIST removed mandatory complexity rules, and how the HIBP k-anonymity model works.

## Key security concepts demonstrated

- Shannon entropy and password search-space analysis
- k-anonymity for privacy-preserving API queries
- Offline crack-time estimation using realistic attack models
- NIST 800-63B vs legacy complexity-based policies
- Safe password handling (masking, no plaintext logging)

## License

MIT
