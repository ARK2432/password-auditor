#!/usr/bin/env python3
"""
Password Strength Auditor & NIST SP 800-63B Policy Enforcement Tool
--------------------------------------------------------------------
Usage:
    python auditor.py -p "MyPassword123"
    python auditor.py -f sample_passwords.txt
    python auditor.py -f sample_passwords.txt --no-hibp
    python auditor.py -f sample_passwords.txt --no-hibp --export
"""

import argparse
import time

from colorama import Fore, Style, init

from entropy import score_password
from hibp import check_hibp
from nist_policy import check_nist
from report import export_json, export_csv, print_summary

init(autoreset=True)

STRENGTH_COLORS = {
    0: Fore.RED,
    1: Fore.RED,
    2: Fore.YELLOW,
    3: Fore.GREEN,
    4: Fore.GREEN,
}

DIVIDER = "-" * 52


def _color_bool(value, true_is_good=True):
    if value is None:
        return f"{Fore.YELLOW}unavailable{Style.RESET_ALL}"
    if value:
        color = Fore.GREEN if true_is_good else Fore.RED
    else:
        color = Fore.RED if true_is_good else Fore.GREEN
    return f"{color}{value}{Style.RESET_ALL}"


def audit_one(password, skip_hibp=False):
    """
    Run a full audit on a single password.
    Returns the merged result dict used by the report module.
    """
    score  = score_password(password)
    hibp   = check_hibp(password) if not skip_hibp else {"breached": False, "count": 0, "error": None}
    nist   = check_nist(password, breached=hibp["breached"])

    # ── Display ──────────────────────────────────────────────────
    masked = password[:2] + "*" * max(0, len(password) - 2)
    s      = score["zxcvbn_score"]

    print(f"\n{Style.BRIGHT}Password : {masked}{Style.RESET_ALL}")
    print(DIVIDER)
    print(f"  Length      : {score['length']} characters")
    print(f"  Entropy     : {score['entropy']} bits")
    print(f"  Strength    : {STRENGTH_COLORS[s]}{score['strength_label']}{Style.RESET_ALL}  (zxcvbn score {s}/4)")
    print(f"  Crack time  : {score['crack_time']}  (offline slow hash)")

    if hibp["error"]:
        print(f"  HIBP check  : {Fore.YELLOW}error — {hibp['error']}{Style.RESET_ALL}")
    elif hibp["breached"]:
        print(f"  HIBP check  : {Fore.RED}BREACHED — seen {hibp['count']:,} times in leaks{Style.RESET_ALL}")
    elif skip_hibp:
        print(f"  HIBP check  : {Fore.YELLOW}skipped (--no-hibp){Style.RESET_ALL}")
    else:
        print(f"  HIBP check  : {Fore.GREEN}Not found in any known breach{Style.RESET_ALL}")

    # NIST section
    compliant_label = (
        f"{Fore.GREEN}COMPLIANT{Style.RESET_ALL}"
        if nist["compliant"]
        else f"{Fore.RED}NON-COMPLIANT{Style.RESET_ALL}"
    )
    print(f"\n  NIST 800-63B: {compliant_label}  ({nist['score']} checks passed)")

    for msg in nist["issues"]:
        print(f"    {Fore.RED}{msg}{Style.RESET_ALL}")
    for msg in nist["passed"]:
        print(f"    {Fore.GREEN}{msg}{Style.RESET_ALL}")

    # Suggestions
    if score["warning"]:
        print(f"\n  Warning     : {Fore.YELLOW}{score['warning']}{Style.RESET_ALL}")
    if score["suggestions"]:
        print(f"  Suggestions :")
        for suggestion in score["suggestions"]:
            print(f"    - {suggestion}")

    print(DIVIDER)

    return {**score, **hibp, "nist": nist}


def main():
    parser = argparse.ArgumentParser(
        description="Password Strength Auditor — NIST SP 800-63B compliance checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python auditor.py -p "Summer2024!"
  python auditor.py -f sample_passwords.txt
  python auditor.py -f sample_passwords.txt --no-hibp --export
        """,
    )
    parser.add_argument("-p", "--password", help="Single password to audit")
    parser.add_argument("-f", "--file",     help="Text file with one password per line")
    parser.add_argument(
        "--no-hibp",
        action="store_true",
        help="Skip the HaveIBeenPwned breach check (offline mode)",
    )
    parser.add_argument(
        "--export",
        action="store_true",
        help="Export results to sample_output/report.json and report.csv",
    )
    args = parser.parse_args()

    if not args.password and not args.file:
        parser.print_help()
        return

    print(f"\n{Style.BRIGHT}Password Strength Auditor  |  NIST SP 800-63B{Style.RESET_ALL}")
    if args.no_hibp:
        print(f"{Fore.YELLOW}  [offline mode — HIBP checks disabled]{Style.RESET_ALL}")

    results = []

    if args.password:
        result = audit_one(args.password, skip_hibp=args.no_hibp)
        results.append(result)

    elif args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                passwords = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Fore.RED}Error: file '{args.file}' not found.{Style.RESET_ALL}")
            return

        print(f"  Auditing {len(passwords)} password(s) from '{args.file}' …\n")

        for i, pw in enumerate(passwords):
            result = audit_one(pw, skip_hibp=args.no_hibp)
            results.append(result)
            if not args.no_hibp and i < len(passwords) - 1:
                time.sleep(1.6)   # respect HIBP rate limit

        print_summary(results)

    if args.export and results:
        print(f"\n{Style.BRIGHT}Exporting reports …{Style.RESET_ALL}")
        export_json(results)
        export_csv(results)


if __name__ == "__main__":
    main()
