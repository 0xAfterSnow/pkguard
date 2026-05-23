import requests
import difflib
import time
from datetime import datetime, timezone
from database import init_db, get_connection

OSV_API = "https://api.osv.dev/v1/query"
NPM_API  = "https://registry.npmjs.org"

class PackageScanner:
    def __init__(self):
        init_db()

    # ------------------------------------------------------------------ #
    #  Public entry point
    # ------------------------------------------------------------------ #
    def scan(self, pkg_json: dict) -> dict:
        direct   = self._extract_deps(pkg_json, direct=True)
        indirect = self._extract_deps(pkg_json, direct=False)

        direct_results   = [self._scan_package(name, ver, is_direct=True)  for name, ver in direct.items()]
        indirect_results = [self._scan_package(name, ver, is_direct=False) for name, ver in indirect.items()]

        all_results = direct_results + indirect_results
        summary = self._build_summary(all_results)
        return {
            "summary": summary,
            "direct":  direct_results,
            "indirect": indirect_results,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_stats(self) -> dict:
        conn = get_connection()
        total      = conn.execute("SELECT COUNT(*) FROM malicious_packages").fetchone()[0]
        critical   = conn.execute("SELECT COUNT(*) FROM malicious_packages WHERE severity='critical'").fetchone()[0]
        high       = conn.execute("SELECT COUNT(*) FROM malicious_packages WHERE severity='high'").fetchone()[0]
        targets    = conn.execute("SELECT COUNT(*) FROM typosquat_targets").fetchone()[0]
        conn.close()
        return {
            "total_known_malicious": total,
            "critical": critical,
            "high": high,
            "typosquat_targets": targets,
        }

    # ------------------------------------------------------------------ #
    #  Dependency extraction
    # ------------------------------------------------------------------ #
    def _extract_deps(self, pkg_json: dict, direct: bool) -> dict:
        if direct:
            deps = {}
            deps.update(pkg_json.get("dependencies", {}))
            deps.update(pkg_json.get("devDependencies", {}))
            return deps
        else:
            deps = {}
            deps.update(pkg_json.get("peerDependencies", {}))
            deps.update(pkg_json.get("optionalDependencies", {}))
            return deps

    # ------------------------------------------------------------------ #
    #  Per-package scan
    # ------------------------------------------------------------------ #
    def _scan_package(self, name: str, version_spec: str, is_direct: bool) -> dict:
        clean_ver = self._clean_version(version_spec)
        result = {
            "name":      name,
            "version":   version_spec,
            "is_direct": is_direct,
            "flags":     [],
            "safe":      True,
        }

        # 1. Local DB check
        db_flags = self._check_local_db(name, clean_ver)
        result["flags"].extend(db_flags)

        # 2. OSV advisory check
        osv_flags = self._check_osv(name, clean_ver)
        result["flags"].extend(osv_flags)

        # 3. Typosquat check
        typo_flags = self._check_typosquat(name)
        result["flags"].extend(typo_flags)

        # 4. npm metadata checks (age + velocity)
        meta_flags = self._check_npm_meta(name, clean_ver)
        result["flags"].extend(meta_flags)

        if result["flags"]:
            result["safe"] = False
            severities = [f.get("severity", "low") for f in result["flags"]]
            result["max_severity"] = self._max_severity(severities)
        else:
            result["max_severity"] = "safe"

        return result

    # ------------------------------------------------------------------ #
    #  Check 1: Local SQLite database
    # ------------------------------------------------------------------ #
    def _check_local_db(self, name: str, version: str) -> list:
        conn = get_connection()
        rows = conn.execute(
            "SELECT * FROM malicious_packages WHERE LOWER(name)=LOWER(?)",
            (name,)
        ).fetchall()
        conn.close()

        flags = []
        for row in rows:
            row = dict(row)
            # version=NULL means all versions; otherwise match exact
            if row["version"] is None or row["version"] == version:
                flags.append({
                    "source":      "PkgGuard DB",
                    "type":        row["reason"],
                    "severity":    row["severity"],
                    "title":       f"Known {row['reason'].title()} — {row['severity'].upper()}",
                    "description": row["description"],
                    "cve":         row.get("cve"),
                    "reference":   row.get("source"),
                })
        return flags

    # ------------------------------------------------------------------ #
    #  Check 2: OSV (Google Open Source Vulnerability DB)
    # ------------------------------------------------------------------ #
    def _check_osv(self, name: str, version: str) -> list:
        try:
            payload = {"package": {"name": name, "ecosystem": "npm"}}
            if version:
                payload["version"] = version
            resp = requests.post(OSV_API, json=payload, timeout=6)
            if resp.status_code != 200:
                return []
            data = resp.json()
            vulns = data.get("vulns", [])
            flags = []
            for v in vulns[:5]:  # cap at 5 per package
                aliases = v.get("aliases", [])
                cve = next((a for a in aliases if a.startswith("CVE-")), None)
                severity = self._osv_severity(v)
                flags.append({
                    "source":      "OSV / GitHub Advisory",
                    "type":        "vulnerability",
                    "severity":    severity,
                    "title":       v.get("id", "Advisory"),
                    "description": (v.get("summary") or v.get("details", ""))[:200],
                    "cve":         cve,
                    "reference":   f"https://osv.dev/vulnerability/{v.get('id','')}",
                })
            return flags
        except Exception:
            return []

    # ------------------------------------------------------------------ #
    #  Check 3: Typosquatting
    # ------------------------------------------------------------------ #
    def _check_typosquat(self, name: str) -> list:
        conn = get_connection()
        targets = [r[0] for r in conn.execute("SELECT legitimate_name FROM typosquat_targets").fetchall()]
        conn.close()

        for legit in targets:
            if name.lower() == legit.lower():
                continue  # it IS the legit one
            ratio = difflib.SequenceMatcher(None, name.lower(), legit.lower()).ratio()
            if ratio > 0.82 and name.lower() != legit.lower():
                return [{
                    "source":      "PkgGuard Typosquat Engine",
                    "type":        "typosquat",
                    "severity":    "high",
                    "title":       f"Possible Typosquat of '{legit}'",
                    "description": f"'{name}' is suspiciously similar to the popular package '{legit}' (similarity {ratio:.0%}). Verify you spelled it correctly.",
                    "cve":         None,
                    "reference":   f"https://www.npmjs.com/package/{legit}",
                }]
        return []

    # ------------------------------------------------------------------ #
    #  Check 4: npm metadata — age & download velocity
    # ------------------------------------------------------------------ #
    def _check_npm_meta(self, name: str, version: str) -> list:
        try:
            resp = requests.get(f"{NPM_API}/{name}", timeout=6)
            if resp.status_code == 404:
                return [{
                    "source":      "npm Registry",
                    "type":        "not_found",
                    "severity":    "medium",
                    "title":       "Package Not Found on npm",
                    "description": f"'{name}' does not exist on the npm registry. This may be a typo or a dependency confusion risk.",
                    "cve":         None,
                    "reference":   None,
                }]
            if resp.status_code != 200:
                return []

            meta  = resp.json()
            flags = []
            time_data = meta.get("time", {})

            # Age check
            created_str = time_data.get("created")
            if created_str:
                created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - created).days
                if age_days < 30:
                    flags.append({
                        "source":      "npm Registry",
                        "type":        "new_package",
                        "severity":    "medium",
                        "title":       f"Very New Package ({age_days} days old)",
                        "description": f"This package was published only {age_days} days ago. Newly published packages have less community scrutiny.",
                        "cve":         None,
                        "reference":   f"https://www.npmjs.com/package/{name}",
                    })

            # Maintainer count
            maintainers = meta.get("maintainers", [])
            if len(maintainers) == 1:
                flags.append({
                    "source":      "npm Registry",
                    "type":        "single_maintainer",
                    "severity":    "low",
                    "title":       "Single Maintainer",
                    "description": "This package has only one maintainer. A single account compromise could affect all users.",
                    "cve":         None,
                    "reference":   f"https://www.npmjs.com/package/{name}",
                })

            # Version-specific: check publish velocity (many versions in short time = suspicious)
            versions = list((meta.get("versions") or {}).keys())
            if len(versions) >= 3 and created_str:
                created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                age_days = max((datetime.now(timezone.utc) - created).days, 1)
                velocity = len(versions) / age_days
                if velocity > 1.0:
                    flags.append({
                        "source":      "npm Registry",
                        "type":        "high_velocity",
                        "severity":    "low",
                        "title":       f"Unusual Publish Velocity ({len(versions)} versions in {age_days} days)",
                        "description": "This package has been updated unusually frequently. While not always malicious, rapid version churn can be a signal of supply chain tampering.",
                        "cve":         None,
                        "reference":   f"https://www.npmjs.com/package/{name}",
                    })

            return flags
        except Exception:
            return []

    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #
    def _clean_version(self, version_spec: str) -> str:
        if not version_spec:
            return ""
        return version_spec.lstrip("^~>=<").split(" ")[0].strip()

    def _osv_severity(self, vuln: dict) -> str:
        for sev_entry in vuln.get("severity", []):
            score_str = sev_entry.get("score", "")
            try:
                score = float(score_str.split("/")[0]) if "/" in score_str else float(score_str)
                if score >= 9.0: return "critical"
                if score >= 7.0: return "high"
                if score >= 4.0: return "medium"
                return "low"
            except Exception:
                pass
        # fallback: look at CVSS in database_specific
        return "medium"

    def _max_severity(self, severities: list) -> str:
        order = ["critical", "high", "medium", "low"]
        for s in order:
            if s in severities:
                return s
        return "low"

    def _build_summary(self, all_results: list) -> dict:
        total    = len(all_results)
        flagged  = [r for r in all_results if not r["safe"]]
        safe     = total - len(flagged)
        by_sev   = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for r in flagged:
            sev = r.get("max_severity", "low")
            if sev in by_sev:
                by_sev[sev] += 1
        return {
            "total_packages": total,
            "safe":           safe,
            "flagged":        len(flagged),
            "by_severity":    by_sev,
            "risk_score":     self._risk_score(by_sev),
        }

    def _risk_score(self, by_sev: dict) -> int:
        return min(100, by_sev["critical"]*40 + by_sev["high"]*20 + by_sev["medium"]*8 + by_sev["low"]*2)
