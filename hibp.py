import hashlib
import time
import requests


def check_hibp(password, retries=2):
    """
    Check a password against the HaveIBeenPwned Pwned Passwords API
    using k-anonymity — the full password is NEVER sent over the network.

    Flow:
        1. SHA-1 hash the password.
        2. Send only the first 5 hex characters (the prefix) to HIBP.
        3. HIBP returns ~500 hash suffixes that share that prefix.
        4. Check locally whether our full hash suffix appears in that list.

    Returns a dict:
        - breached  : True / False / None (None = API error)
        - count     : number of times seen in breaches (0 if not found)
        - error     : error message string or None
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {"Add-Padding": "true"}  # prevents traffic-size analysis

    for attempt in range(retries + 1):
        try:
            response = requests.get(url, headers=headers, timeout=6)
            response.raise_for_status()
            break
        except requests.exceptions.Timeout:
            if attempt < retries:
                time.sleep(2)
                continue
            return {"breached": None, "count": 0, "error": "Request timed out"}
        except requests.exceptions.RequestException as e:
            return {"breached": None, "count": 0, "error": str(e)}

    for line in response.text.splitlines():
        parts = line.split(":")
        if len(parts) == 2 and parts[0] == suffix:
            return {"breached": True, "count": int(parts[1]), "error": None}

    return {"breached": False, "count": 0, "error": None}
