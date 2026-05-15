import math
import zxcvbn as zx


def calc_entropy(password):
    """Calculate Shannon entropy based on character set size and length."""
    charset = 0
    if any(c.islower() for c in password):
        charset += 26
    if any(c.isupper() for c in password):
        charset += 26
    if any(c.isdigit() for c in password):
        charset += 10
    if any(c in "!@#$%^&*()-_=+[]{}|;:',.<>?/`~" for c in password):
        charset += 32
    if charset == 0:
        return 0.0
    return round(len(password) * math.log2(charset), 2)


def score_password(password):
    """
    Score a password using zxcvbn and entropy calculation.

    Returns a dict with:
        - password       : original password
        - length         : character count
        - entropy        : Shannon entropy in bits
        - zxcvbn_score   : 0 (weakest) to 4 (strongest)
        - strength_label : human-readable strength label
        - crack_time     : estimated offline crack time (slow hashing)
        - suggestions    : list of improvement suggestions from zxcvbn
        - warning        : single warning string from zxcvbn (may be empty)
    """
    result = zx.zxcvbn(password)
    entropy = calc_entropy(password)

    strength_labels = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]
    score = result["score"]

    return {
        "password":       password,
        "length":         len(password),
        "entropy":        entropy,
        "zxcvbn_score":   score,
        "strength_label": strength_labels[score],
        "crack_time":     result["crack_times_display"]["offline_slow_hashing_1e4_per_second"],
        "suggestions":    result["feedback"]["suggestions"],
        "warning":        result["feedback"]["warning"],
    }
