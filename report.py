import json
import csv
import os
from datetime import datetime


def _mask(password):
    """Mask a password for safe storage — never log plaintext."""
    if len(password) <= 2:
        return "*" * len(password)
    return password[:2] + "*" * (len(password) - 2)


def _build_record(result):
    """Flatten a full audit result dict into a safe exportable record."""
    return {
        "masked_password":  _mask(result["password"]),
        "length":           result["length"],
        "entropy_bits":     result["entropy"],
        "strength":         result["strength_label"],
        "zxcvbn_score":     result["zxcvbn_score"],
        "crack_time":       result["crack_time"],
        "breached":         result["breached"],
        "breach_count":     result["count"],
        "nist_compliant":   result["nist"]["compliant"],
        "nist_score":       result["nist"]["score"],
        "nist_issues":      "; ".join(result["nist"]["issues"]) or "None",
        "suggestions":      "; ".join(result["suggestions"]) or "None",
    }


def export_json(results, output_dir="sample_output"):
    """Export all audit results to a formatted JSON file."""
    os.makedirs(output_dir, exist_ok=True)
    filename = os.path.join(output_dir, "report.json")
    payload = {
        "tool":      "Password Strength Auditor",
        "standard":  "NIST SP 800-63B",
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total":     len(results),
        "compliant": sum(1 for r in results if r["nist"]["compliant"]),
        "results":   [_build_record(r) for r in results],
    }
    with open(filename, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"  JSON report → {filename}")
    return filename


def export_csv(results, output_dir="sample_output"):
    """Export all audit results to a CSV file."""
    os.makedirs(output_dir, exist_ok=True)
    filename = os.path.join(output_dir, "report.csv")
    fields = [
        "masked_password", "length", "entropy_bits", "strength",
        "zxcvbn_score", "crack_time", "breached", "breach_count",
        "nist_compliant", "nist_score", "nist_issues", "suggestions",
    ]
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in results:
            writer.writerow(_build_record(r))
    print(f"  CSV report  → {filename}")
    return filename


def print_summary(results):
    """Print a brief compliance summary table to the terminal."""
    total     = len(results)
    compliant = sum(1 for r in results if r["nist"]["compliant"])
    breached  = sum(1 for r in results if r.get("breached") is True)
    strong    = sum(1 for r in results if r["zxcvbn_score"] >= 3)

    print("\n" + "=" * 50)
    print("  BATCH AUDIT SUMMARY")
    print("=" * 50)
    print(f"  Passwords audited   : {total}")
    print(f"  NIST compliant      : {compliant}/{total}")
    print(f"  Found in breaches   : {breached}/{total}")
    print(f"  Strong (score ≥ 3)  : {strong}/{total}")
    print("=" * 50)
