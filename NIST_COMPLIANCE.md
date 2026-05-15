# NIST SP 800-63B Compliance Summary

## What is NIST SP 800-63B?

NIST Special Publication 800-63B (2017) is the US government's digital identity guideline
for authentication and password management. It replaced the older 800-63-2 standard and
fundamentally changed how organizations should think about password security.

## Rules enforced by this tool

| # | Rule | NIST Guideline | Implementation |
|---|------|---------------|----------------|
| 1 | Minimum length | At least 8 characters; 15+ recommended | `nist_policy.py` length check |
| 2 | Breach database check | Screen against known compromised passwords | HIBP k-anonymity API (`hibp.py`) |
| 3 | Dictionary / common password check | Block commonly used passwords | SecLists top-10k wordlist |
| 4 | No sequential/repetitive characters | Reject "1234", "aaaa", "qwerty" etc. | Pattern matching in `nist_policy.py` |
| 5 | No context-specific words | Reject "password", "admin", "welcome" etc. | Context word list check |

## What NIST 800-63B does NOT require (and why)

| Old rule | Why NIST removed it |
|----------|---------------------|
| Mandatory complexity (upper + lower + digit + symbol) | Users respond with predictable patterns: `P@ssw0rd1` |
| Forced password expiration | Causes users to increment: `Password1` → `Password2` |
| Password hints | Hints often reveal the password or make it guessable |
| Knowledge-based authentication (security questions) | Answers are often publicly available on social media |
| Restricting special characters | Reduces the searchable password space unnecessarily |

## Why this matters for security

The old NIST 800-63-2 guidelines — mandatory complexity, forced rotation every 90 days —
caused a generation of predictable passwords. Users learned to satisfy requirements with
minimum effort: `Summer2024!` technically passes complexity rules but is trivially guessable.

The 2017 update (800-63B) shifts focus to:
- **Length over complexity** — a 5-word passphrase is stronger than `P@ssw0rd`
- **Breach exposure** — a long password already in a leak is worthless
- **Usability** — policies users can follow produce stronger real-world security

## How the HIBP k-anonymity model works

The HaveIBeenPwned API uses a k-anonymity model so your password is never transmitted:

```
1. Hash the password:  SHA-1("password") → "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
2. Send only 5 chars:  GET /range/5BAA6
3. HIBP returns ~500 hash suffixes starting with "5BAA6"
4. Check locally:      is "1E4C9B93F3F0682250B6CF8331B7EE68FD8" in the list?
5. Result:             Yes — seen 9,659,365 times in breaches
```

The full hash never leaves your machine.

## References

- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [HaveIBeenPwned API](https://haveibeenpwned.com/API/v3#PwnedPasswords)
- [SecLists — Common Credentials](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Common-Credentials)
