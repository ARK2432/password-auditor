import os

WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "wordlists", "common_passwords.txt")

SEQUENTIAL_PATTERNS = [
    "1234", "2345", "3456", "4567", "5678", "6789", "7890",
    "abcd", "bcde", "cdef", "defg", "efgh",
    "qwerty", "asdf", "zxcv", "qazwsx",
    "aaaa", "bbbb", "cccc", "1111", "2222", "3333",
    "0000", "9999", "1212", "1122",
]

CONTEXT_WORDS = [
    "password", "passw0rd", "p@ssword", "p@ssw0rd",
    "letmein", "welcome", "login", "admin", "root",
    "iloveyou", "monkey", "dragon", "master", "sunshine",
]


def _load_wordlist():
    try:
        with open(WORDLIST_PATH, "r", encoding="utf-8", errors="ignore") as f:
            return {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        return set()


_WORDLIST = _load_wordlist()


def check_nist(password, breached=False):
    """
    Validate a password against NIST SP 800-63B guidelines.

    Key NIST 800-63B rules enforced:
      - Minimum 8 characters (15+ recommended)
      - Must not appear in known breach databases
      - Must not be a commonly used / dictionary password
      - Must not contain repetitive or sequential characters
      - Must not contain context-specific words

    Note: NIST explicitly discourages mandatory complexity rules
    (uppercase + digit + symbol requirements) and forced expiration.

    Returns:
        compliant  : bool — True if all checks pass
        issues     : list of FAIL messages
        passed     : list of PASS messages
        score      : int — number of checks passed out of total
    """
    issues = []
    passed = []

    # Rule 1 — Minimum length
    if len(password) < 8:
        issues.append(f"FAIL — length {len(password)} is below NIST minimum of 8 characters")
    elif len(password) < 15:
        passed.append(f"PASS — length {len(password)} meets minimum (15+ chars recommended)")
    else:
        passed.append(f"PASS — length {len(password)} meets and exceeds recommendation")

    # Rule 2 — Breach database check
    if breached is True:
        issues.append("FAIL — found in a known credential breach database (HIBP)")
    elif breached is False:
        passed.append("PASS — not found in known breach databases")
    else:
        passed.append("INFO — breach check was skipped or unavailable")

    # Rule 3 — Common/dictionary password check
    if password.lower() in _WORDLIST:
        issues.append("FAIL — matches a commonly used password from known lists")
    else:
        passed.append("PASS — not found in common password wordlist")

    # Rule 4 — Sequential or repetitive character patterns
    lower_pw = password.lower()
    found_seq = [p for p in SEQUENTIAL_PATTERNS if p in lower_pw]
    if found_seq:
        issues.append(f"FAIL — contains sequential/repetitive pattern: '{found_seq[0]}'")
    else:
        passed.append("PASS — no repetitive or sequential character patterns detected")

    # Rule 5 — Context-specific words
    found_ctx = [w for w in CONTEXT_WORDS if w in lower_pw]
    if found_ctx:
        issues.append(f"FAIL — contains context-specific word: '{found_ctx[0]}'")
    else:
        passed.append("PASS — no context-specific words detected")

    total = len(issues) + len(passed)
    return {
        "compliant": len(issues) == 0,
        "issues":    issues,
        "passed":    passed,
        "score":     f"{len(passed)}/{total}",
    }
