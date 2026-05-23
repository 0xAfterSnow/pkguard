import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "pkguard.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS malicious_packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    version TEXT,          -- NULL means ALL versions
    severity TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low')),
    reason TEXT NOT NULL,
    description TEXT,
    cve TEXT,
    source TEXT,
    reported_at TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_pkg_name ON malicious_packages(name);

CREATE TABLE IF NOT EXISTS typosquat_targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    legitimate_name TEXT NOT NULL,
    category TEXT
);

CREATE INDEX IF NOT EXISTS idx_typo_name ON typosquat_targets(legitimate_name);

CREATE TABLE IF NOT EXISTS tools (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    cls TEXT NOT NULL,
    name TEXT NOT NULL,
    desc TEXT NOT NULL,
    url TEXT NOT NULL
);
"""

SEED_MALICIOUS = [
    # name, version, severity, reason, description, cve, source
    ("event-stream", "3.3.6", "critical", "backdoor", "Malicious code injected to steal cryptocurrency wallet credentials", "N/A", "npm incident 2018"),
    ("flatmap-stream", "0.1.1", "critical", "backdoor", "Dependency of compromised event-stream, contained obfuscated payload", "N/A", "npm incident 2018"),
    ("ua-parser-js", "0.7.29", "critical", "malware", "Hijacked package that installed cryptominers and password stealers", "CVE-2021-41265", "npm incident 2021"),
    ("ua-parser-js", "0.8.0", "critical", "malware", "Hijacked package that installed cryptominers and password stealers", "CVE-2021-41265", "npm incident 2021"),
    ("ua-parser-js", "1.0.0", "critical", "malware", "Hijacked package that installed cryptominers and password stealers", "CVE-2021-41265", "npm incident 2021"),
    ("coa", "2.0.3", "critical", "malware", "Hijacked package injecting malware via postinstall script", "CVE-2021-43469", "npm incident 2021"),
    ("coa", "2.0.4", "critical", "malware", "Hijacked package injecting malware via postinstall script", "CVE-2021-43469", "npm incident 2021"),
    ("rc", "1.2.9", "critical", "malware", "Hijacked package injecting malware via postinstall script", "CVE-2021-43492", "npm incident 2021"),
    ("colors", "1.4.44-liberty-2", "high", "sabotage", "Author intentionally introduced infinite loop breaking thousands of projects", "N/A", "npm incident 2022"),
    ("faker", "6.6.6", "high", "sabotage", "Author deleted package and pushed broken version intentionally", "N/A", "npm incident 2022"),
    ("node-ipc", "10.1.1", "critical", "malware", "Author added geopolitical malware wiping files on Russian/Belarusian IPs", "CVE-2022-23812", "npm incident 2022"),
    ("node-ipc", "10.1.2", "critical", "malware", "Author added geopolitical malware wiping files on Russian/Belarusian IPs", "CVE-2022-23812", "npm incident 2022"),
    ("lodash", "4.17.15", "medium", "vulnerability", "Prototype pollution vulnerability allowing object injection", "CVE-2020-8203", "GitHub Advisory"),
    ("lodash", "4.17.19", "low", "vulnerability", "ReDoS vulnerability in string methods", "CVE-2021-23337", "GitHub Advisory"),
    ("minimist", "1.2.5", "medium", "vulnerability", "Prototype pollution via constructor or __proto__ keys", "CVE-2021-44906", "GitHub Advisory"),
    ("ansi-html", None, "high", "vulnerability", "ReDoS vulnerability that can crash Node.js server", "CVE-2021-23424", "GitHub Advisory"),
    ("glob-parent", "5.1.1", "medium", "vulnerability", "ReDoS via crafted input string", "CVE-2020-28469", "GitHub Advisory"),
    ("axios", "0.21.0", "medium", "vulnerability", "SSRF vulnerability via redirects", "CVE-2020-28168", "GitHub Advisory"),
    ("axios", "0.21.1", "low", "vulnerability", "ReDoS in URL validation", "CVE-2021-3749", "GitHub Advisory"),
    ("netmask", "2.0.1", "high", "vulnerability", "Improper input validation allows IP spoofing attacks", "CVE-2021-28918", "GitHub Advisory"),
    ("netmask", "1.0.6", "high", "vulnerability", "Improper input validation allows IP spoofing attacks", "CVE-2021-28918", "GitHub Advisory"),
    ("browserslist", "4.16.4", "low", "vulnerability", "ReDoS vulnerability in version query parsing", "CVE-2021-23364", "GitHub Advisory"),
    ("xmlhttprequest-ssl", "1.6.1", "high", "vulnerability", "Improper certificate validation", "CVE-2021-31597", "GitHub Advisory"),
    ("path-parse", "1.0.6", "medium", "vulnerability", "ReDoS vulnerability", "CVE-2021-23343", "GitHub Advisory"),
    ("ws", "7.4.5", "high", "vulnerability", "ReDoS in headers validation", "CVE-2021-32640", "GitHub Advisory"),
    ("tar", "6.1.1", "high", "vulnerability", "Arbitrary file creation/overwrite via path traversal", "CVE-2021-37701", "GitHub Advisory"),
    ("tar", "4.4.14", "high", "vulnerability", "Path traversal via absolute paths in archives", "CVE-2021-37712", "GitHub Advisory"),
    ("npm", "7.0.0", "medium", "vulnerability", "Sensitive data exposure in error messages", "CVE-2021-39134", "GitHub Advisory"),
    ("y18n", "4.0.0", "high", "vulnerability", "Prototype pollution vulnerability", "CVE-2020-7774", "GitHub Advisory"),
    ("ini", "1.3.5", "medium", "vulnerability", "Prototype pollution via malicious config file", "CVE-2020-7788", "GitHub Advisory"),
    ("highlight.js", "9.18.4", "medium", "vulnerability", "ReDoS in language detection", "CVE-2021-23346", "GitHub Advisory"),
    ("jszip", "3.6.0", "high", "vulnerability", "Prototype pollution via zip file manipulation", "CVE-2022-48285", "GitHub Advisory"),
    ("parse-url", "6.0.0", "high", "vulnerability", "Authorization bypass via URL confusion", "CVE-2022-2216", "GitHub Advisory"),
    ("node-fetch", "2.6.0", "high", "vulnerability", "URL redirection to untrusted sites", "CVE-2022-0235", "GitHub Advisory"),
    ("got", "11.8.2", "medium", "vulnerability", "Open redirect vulnerability", "CVE-2022-33987", "GitHub Advisory"),
    ("crossenv", None, "critical", "typosquat", "Typosquat of cross-env, steals environment variables including secrets", "N/A", "npm incident 2017"),
    ("d3.js", None, "critical", "typosquat", "Typosquat of d3 package, contains credential harvester", "N/A", "npm security"),
    ("jquery.js", None, "high", "typosquat", "Typosquat of jquery, contains malicious postinstall script", "N/A", "npm security"),
    ("discordjs", None, "high", "typosquat", "Typosquat of discord.js, contains token logger", "N/A", "npm security"),
    ("momen", None, "medium", "typosquat", "Typosquat of moment, empty package used for dependency confusion", "N/A", "npm security"),
    ("babelcli", None, "high", "typosquat", "Typosquat of babel-cli, exfiltrates npm credentials", "N/A", "npm security"),
    ("electorn", None, "critical", "typosquat", "Typosquat of electron, installs remote access trojan", "N/A", "npm security"),
    ("mongose", None, "high", "typosquat", "Typosquat of mongoose, credential harvester", "N/A", "npm security"),
    ("expres", None, "medium", "typosquat", "Typosquat of express, empty malicious package", "N/A", "npm security"),
    ("jsonwebtoken", "8.5.1", "high", "vulnerability", "Improper validation of algorithm type allows authentication bypass", "CVE-2022-23529", "GitHub Advisory"),
    ("passport", "0.6.0", "medium", "vulnerability", "Session fixation vulnerability", "CVE-2022-25896", "GitHub Advisory"),
    ("passport-oauth2", "1.6.0", "medium", "vulnerability", "Insufficient PKCE protection", "CVE-2023-26047", "GitHub Advisory"),
]

SEED_TYPOSQUAT_TARGETS = [
    ("react", "frontend"), ("react-dom", "frontend"), ("vue", "frontend"),
    ("angular", "frontend"), ("svelte", "frontend"), ("next", "frontend"),
    ("nuxt", "frontend"), ("webpack", "build"), ("babel", "build"),
    ("eslint", "tooling"), ("prettier", "tooling"), ("typescript", "language"),
    ("express", "backend"), ("fastify", "backend"), ("koa", "backend"),
    ("mongoose", "database"), ("sequelize", "database"), ("knex", "database"),
    ("lodash", "utility"), ("moment", "utility"), ("axios", "http"),
    ("node-fetch", "http"), ("got", "http"), ("chalk", "cli"),
    ("commander", "cli"), ("inquirer", "cli"), ("jest", "testing"),
    ("mocha", "testing"), ("chai", "testing"), ("electron", "desktop"),
    ("socket.io", "realtime"), ("discord.js", "api"), ("stripe", "payments"),
    ("d3", "visualization"), ("three", "3d"), ("jquery", "dom"),
    ("cross-env", "build"), ("dotenv", "config"), ("cors", "middleware"),
    ("helmet", "security"), ("bcrypt", "security"), ("jsonwebtoken", "auth"),
    ("passport", "auth"), ("multer", "files"), ("sharp", "image"),
]

SEED_TOOLS = [
    ("VS Code", "tt-vscode", "Snyk Security", "Real-time vulnerability detection in your editor. Flags CVEs in package.json as you type.", "https://marketplace.visualstudio.com/items?itemName=snyk-security.snyk-vulnerability-scanner"),
    ("VS Code", "tt-vscode", "npm Audit", "Runs npm audit inline, surfacing vulnerability counts in the VS Code status bar automatically.", "https://marketplace.visualstudio.com/items?itemName=nicusorb.npm-audit"),
    ("VS Code", "tt-vscode", "OWASP Checker", "Integrates OWASP's dependency-check tool directly into the VS Code workflow.", "https://owasp.org/www-project-dependency-check/"),
    ("CLI Tool", "tt-cli", "npm audit", "Built into npm v6+. Run `npm audit` in any project for an instant vulnerability report.", "https://docs.npmjs.com/cli/v10/commands/npm-audit"),
    ("CLI Tool", "tt-cli", "Snyk CLI", "`snyk test` scans your project. `snyk monitor` tracks it over time for new advisories.", "https://docs.snyk.io/snyk-cli"),
    ("CLI Tool", "tt-cli", "Retire.js", "Detects JavaScript libraries with known vulnerabilities. Works as CLI, Grunt/Gulp plugin, or browser extension.", "https://retirejs.github.io/retire.js/"),
    ("CI / CD", "tt-ci", "Dependabot", "GitHub-native automated dependency updates and security alerts. Auto-creates PRs for vulnerable packages.", "https://docs.github.com/en/code-security/dependabot"),
    ("CI / CD", "tt-ci", "Socket Security", "GitHub app that blocks supply chain attacks by analyzing package behavior before merging a PR.", "https://socket.dev"),
    ("Service", "tt-service", "OSV Database", "Google's open vulnerability database aggregating advisories from GitHub, PyPI, npm and more.", "https://osv.dev"),
]


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    conn.commit()

    # Seed if empty
    count = conn.execute("SELECT COUNT(*) FROM malicious_packages").fetchone()[0]
    if count == 0:
        conn.executemany(
            "INSERT INTO malicious_packages (name, version, severity, reason, description, cve, source) VALUES (?,?,?,?,?,?,?)",
            SEED_MALICIOUS,
        )
        conn.executemany(
            "INSERT INTO typosquat_targets (legitimate_name, category) VALUES (?,?)",
            SEED_TYPOSQUAT_TARGETS,
        )
        conn.executemany(
            "INSERT INTO tools (type, cls, name, desc, url) VALUES (?,?,?,?,?)",
            SEED_TOOLS,
        )
        conn.commit()
        print(f"[DB] Seeded {len(SEED_MALICIOUS)} malicious packages, {len(SEED_TYPOSQUAT_TARGETS)} typosquat targets, and {len(SEED_TOOLS)} tools.")
    else:
        print(f"[DB] Database already has {count} records.")
    conn.close()
    return DB_PATH


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
