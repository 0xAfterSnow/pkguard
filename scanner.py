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
        total    = conn.execute("SELECT COUNT(*) AS cnt FROM malicious_packages").fetchone()["cnt"]
        critical = conn.execute("SELECT COUNT(*) AS cnt FROM malicious_packages WHERE severity='critical'").fetchone()["cnt"]
        high     = conn.execute("SELECT COUNT(*) AS cnt FROM malicious_packages WHERE severity='high'").fetchone()["cnt"]
        targets  = conn.execute("SELECT COUNT(*) AS cnt FROM typosquat_targets").fetchone()["cnt"]
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
            result["suggestion"] = self._get_suggestion(name, version_spec, result["flags"])
        else:
            result["max_severity"] = "safe"
            result["suggestion"] = None

        return result

    # ------------------------------------------------------------------ #
    #  Check 1: Local SQLite database
    # ------------------------------------------------------------------ #
    def _check_local_db(self, name: str, version: str) -> list:
        conn = get_connection()
        rows = conn.execute(
            "SELECT * FROM malicious_packages WHERE LOWER(name)=LOWER(%s)",
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
                # Extract the minimum fixed version from SEMVER ranges
                fixed_version = None
                for affected in v.get("affected", []):
                    for rng in affected.get("ranges", []):
                        if rng.get("type") == "SEMVER":
                            for event in rng.get("events", []):
                                if "fixed" in event:
                                    fixed_version = event["fixed"]
                                    break
                        if fixed_version:
                            break
                    if fixed_version:
                        break
                flags.append({
                    "source":        "OSV / GitHub Advisory",
                    "type":          "vulnerability",
                    "severity":      severity,
                    "title":         v.get("id", "Advisory"),
                    "description":   (v.get("summary") or v.get("details", ""))[:200],
                    "cve":           cve,
                    "reference":     f"https://osv.dev/vulnerability/{v.get('id','')}",
                    "fixed_version": fixed_version,
                })
            return flags
        except Exception:
            return []

    # ------------------------------------------------------------------ #
    #  Check 3: Typosquatting
    # ------------------------------------------------------------------ #
    def _check_typosquat(self, name: str) -> list:
        conn = get_connection()
        targets = [r["legitimate_name"] for r in conn.execute("SELECT legitimate_name FROM typosquat_targets").fetchall()]
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
    #  Suggestion engine
    # ------------------------------------------------------------------ #
    def _get_npm_latest(self, name: str) -> str | None:
        """Fetch dist-tags.latest from the npm registry."""
        try:
            resp = requests.get(f"{NPM_API}/{name}/latest", timeout=6)
            if resp.status_code == 200:
                return resp.json().get("version")
        except Exception:
            pass
        return None

    def _get_suggestion(self, name: str, version_spec: str, flags: list) -> dict | None:
        """Return a suggestion dict for a flagged package, or None."""
        flag_types = {f["type"] for f in flags}

        # 1. Typosquat → find the legitimate package name
        if "typosquat" in flag_types:
            legit = None
            # Try: reference is an npm URL (set by the live typosquat engine)
            for f in flags:
                if f["type"] == "typosquat" and f.get("reference", "").startswith("https://www.npmjs.com/package/"):
                    candidate = f["reference"].rstrip("/").split("/")[-1]
                    if candidate.lower() != name.lower():
                        legit = candidate
                        break
            # Fallback: fuzzy-match against typosquat_targets table
            if not legit:
                conn = get_connection()
                tgts = [r["legitimate_name"] for r in conn.execute("SELECT legitimate_name FROM typosquat_targets").fetchall()]
                conn.close()
                best, best_ratio = None, 0.0
                for t in tgts:
                    ratio = difflib.SequenceMatcher(None, name.lower(), t.lower()).ratio()
                    if ratio > best_ratio:
                        best_ratio, best = ratio, t
                if best and best_ratio > 0.6 and best.lower() != name.lower():
                    legit = best
            if legit:
                return {
                    "name":    legit,
                    "version": "latest",
                    "reason":  f"'{name}' is a typosquat — install the real package",
                    "url":     f"https://www.npmjs.com/package/{legit}",
                    "install": f"npm install {legit}",
                    "warning": False,
                }

        # 2. Package not found → fuzzy-match against known legitimate names
        if "not_found" in flag_types:
            conn = get_connection()
            tgts = [r["legitimate_name"] for r in conn.execute("SELECT legitimate_name FROM typosquat_targets").fetchall()]
            conn.close()
            best, best_ratio = None, 0.0
            for t in targets:
                ratio = difflib.SequenceMatcher(None, name.lower(), t.lower()).ratio()
                if ratio > best_ratio:
                    best_ratio, best = ratio, t
            if best and best_ratio > 0.6:
                return {
                    "name":    best,
                    "version": "latest",
                    "reason":  f"Did you mean '{best}'? ({best_ratio:.0%} match)",
                    "url":     f"https://www.npmjs.com/package/{best}",
                    "install": f"npm install {best}",
                    "warning": False,
                }

        # 3. Vulnerability / malware / backdoor / sabotage → suggest a safe version
        actionable = {"vulnerability", "malware", "backdoor", "sabotage", "dependency confusion"}
        if flag_types & actionable:
            # Priority 1: minimum fixed version from OSV advisory
            fixed_version = next(
                (f["fixed_version"] for f in flags if f.get("fixed_version")),
                None
            )
            if fixed_version:
                return {
                    "name":    name,
                    "version": fixed_version,
                    "reason":  "Minimum patched version per OSV advisory",
                    "url":     f"https://www.npmjs.com/package/{name}",
                    "install": f"npm install {name}@{fixed_version}",
                    "warning": False,
                }

            # Priority 2: latest from npm
            latest = self._get_npm_latest(name)
            if latest is None:
                return {
                    "name":    None,
                    "version": None,
                    "reason":  "Package unreachable on npm — consider removing it",
                    "url":     None,
                    "install": None,
                    "warning": True,
                }

            # Check: is the latest version itself flagged in our DB?
            conn = get_connection()
            poisoned = conn.execute(
                "SELECT 1 FROM malicious_packages WHERE LOWER(name)=LOWER(%s) AND (version IS NULL OR version=%s)",
                (name, latest)
            ).fetchone()
            conn.close()

            if poisoned:
                return {
                    "name":    None,
                    "version": None,
                    "reason":  f"Latest ({latest}) is also compromised — remove this package",
                    "url":     f"https://www.npmjs.com/package/{name}",
                    "install": None,
                    "warning": True,
                }

            # Check: user is already on latest
            clean_cur = self._clean_version(version_spec)
            if clean_cur == latest:
                return {
                    "name":    None,
                    "version": None,
                    "reason":  f"Already on latest ({latest}) — await upstream patch or find an alternative",
                    "url":     f"https://www.npmjs.com/package/{name}",
                    "install": None,
                    "warning": True,
                }

            return {
                "name":    name,
                "version": latest,
                "reason":  "Upgrade to latest safe version",
                "url":     f"https://www.npmjs.com/package/{name}",
                "install": f"npm install {name}@latest",
                "warning": False,
            }

        return None

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
