import json
import sys

def main(json_path, md_path):
    findings = []
    try:
        with open(json_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                findings.append(json.loads(line))
    except FileNotFoundError:
        with open(md_path, "w") as out:
            out.write("No trufflehog-report.json found.\n")
        return

    # Filter out capture-group artifacts (bare 0/1 values)
    real_findings = [f for f in findings if f.get("Raw") not in ("0", "1")]

    with open(md_path, "w") as out:
        out.write("## 🐷 TruffleHog Secret Scan Results\n\n")
        if not real_findings:
            out.write("✅ No hardcoded secrets detected.\n")
        else:
            out.write(f"⚠️ **{len(real_findings)} potential hardcoded secret(s) found**\n\n")
            out.write("| File | Line | Rule | Value | Verified |\n")
            out.write("|------|------|------|-------|----------|\n")
            for f in real_findings:
                file = f["SourceMetadata"]["Data"]["Filesystem"]["file"]
                line = f["SourceMetadata"]["Data"]["Filesystem"]["line"]
                rule = f.get("ExtraData", {}).get("name", f.get("DetectorName", ""))
                raw = f.get("Raw", "")
                verified = f.get("Verified", False)
                out.write(f"| `{file}` | {line} | {rule} | `{raw}` | {verified} |\n")

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
