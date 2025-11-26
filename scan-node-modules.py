#!/usr/bin/env python3
"""
Shai-Hulud 2.0 Node Modules Scanner

Recursively scans directories for compromised packages and malicious indicators
from the Shai-Hulud 2.0 supply chain attack.

This is a standalone security scanner using ONLY Python standard library.
No external dependencies to minimize attack surface and maximize auditability.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any

# =============================================================================
# CONSTANTS AND PATTERNS
# =============================================================================

VERSION = "2.0.0"

# Color codes for terminal output
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    BOLD = '\033[1m'
    NC = '\033[0m'  # No Color

# Suspicious script patterns (from src/scanner.ts)
SUSPICIOUS_SCRIPT_PATTERNS = [
    (r'setup_bun\.js', 'Shai-Hulud malicious setup script'),
    (r'bun_environment\.js', 'Shai-Hulud environment script'),
    (r'\bcurl\s+[^|]*\|\s*(ba)?sh', 'Curl piped to shell execution'),
    (r'\bwget\s+[^|]*\|\s*(ba)?sh', 'Wget piped to shell execution'),
    (r'\beval\s*\(', 'Eval execution (potential code injection)'),
    (r'\beval\s+[\'"`\$]', 'Eval with dynamic content'),
    (r'base64\s+(--)?d(ecode)?', 'Base64 decode execution'),
    (r'\$\(curl', 'Command substitution with curl'),
    (r'\$\(wget', 'Command substitution with wget'),
    (r'node\s+-e\s+[\'"].*?(http|eval|Buffer\.from)', 'Inline Node.js code execution'),
    (r'npx\s+--yes\s+[^@\s]+@', 'NPX auto-install of versioned package'),
]

# TruffleHog and credential scanning patterns
TRUFFLEHOG_PATTERNS = [
    (r'trufflehog', 'TruffleHog reference detected'),
    (r'trufflesecurity', 'TruffleSecurity reference'),
    (r'credential[_-]?scan', 'Credential scanning pattern'),
    (r'secret[_-]?scan', 'Secret scanning pattern'),
    (r'--json\s+--no-update', 'TruffleHog CLI pattern'),
    (r'github\.com/trufflesecurity/trufflehog', 'TruffleHog GitHub download'),
    (r'releases/download.*trufflehog', 'TruffleHog binary download'),
]

# Shai-Hulud repository indicators
SHAI_HULUD_REPO_PATTERNS = [
    (r'shai[-_]?hulud', 'Shai-Hulud repository name'),
    (r'the\s+second\s+coming', 'Shai-Hulud campaign description'),
    (r'sha1hulud', 'SHA1HULUD variant'),
]

# Malicious runner patterns in GitHub Actions
MALICIOUS_RUNNER_PATTERNS = [
    (r'runs-on:\s*[\'"]?SHA1HULUD', 'SHA1HULUD malicious runner'),
    (r'runs-on:\s*[\'"]?self-hosted.*SHA1HULUD', 'Self-hosted SHA1HULUD runner'),
    (r'runner[_-]?name.*SHA1HULUD', 'SHA1HULUD runner reference'),
    (r'labels:.*SHA1HULUD', 'SHA1HULUD runner label'),
]

# Malicious workflow file patterns
MALICIOUS_WORKFLOW_PATTERNS = [
    (r'formatter_.*\.yml$', 'Shai-Hulud formatter workflow (formatter_*.yml)'),
    (r'discussion\.ya?ml$', 'Shai-Hulud discussion workflow'),
]

# Webhook exfiltration patterns
WEBHOOK_EXFIL_PATTERNS = [
    (r'webhook\.site', 'Webhook.site exfiltration endpoint'),
    (r'bb8ca5f6-4175-45d2-b042-fc9ebb8170b7', 'Known malicious webhook UUID'),
    (r'exfiltrat', 'Exfiltration reference'),
]

# Known affected namespaces
AFFECTED_NAMESPACES = [
    '@zapier', '@posthog', '@asyncapi', '@postman', '@ensdomains', '@ens',
    '@voiceflow', '@browserbase', '@ctrl', '@crowdstrike', '@art-ws',
    '@ngx', '@nativescript-community', '@oku-ui',
]

# Files/paths to exclude from scanning (detector's own files)
# These are relative patterns that match specific detector source files
EXCLUDED_PATTERNS = [
    '/src/scanner.ts',
    '/src/types.ts',
    '/src/index.ts',
    '/dist/',
    'scan-node-modules.py',
    'scan-node-modules.sh',
    'compromised-packages.json',
]

# =============================================================================
# DATA STRUCTURES
# =============================================================================

class Finding:
    """Represents a security finding"""
    def __init__(self, severity: str, finding_type: str, title: str,
                 description: str, location: str, evidence: str = ""):
        self.severity = severity  # critical, high, medium, low
        self.finding_type = finding_type
        self.title = title
        self.description = description
        self.location = location
        self.evidence = evidence

    def __repr__(self):
        return f"Finding({self.severity}, {self.finding_type}, {self.location})"

class ScanStats:
    """Track scan statistics"""
    def __init__(self):
        self.node_modules_scanned = 0
        self.compromised_packages = 0
        self.malicious_files = 0
        self.findings: List[Finding] = []

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def count_by_severity(self) -> Dict[str, int]:
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

# =============================================================================
# DATABASE LOADING
# =============================================================================

def load_database(db_path: Path) -> Dict[str, Any]:
    """Load compromised-packages.json with all indicators"""
    try:
        with open(db_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Extract package names and create lookup dict
        packages = {pkg['name']: pkg for pkg in data.get('packages', [])}

        # Extract indicators
        indicators = data.get('indicators', {})

        return {
            'packages': packages,
            'malicious_files': indicators.get('maliciousFiles', []),
            'malicious_workflows': indicators.get('maliciousWorkflows', []),
            'github_indicators': indicators.get('gitHubIndicators', {}),
            'file_hashes': indicators.get('fileHashes', {}),
        }
    except FileNotFoundError:
        print(f"{Colors.RED}ERROR: Database file not found: {db_path}{Colors.NC}")
        print("Please ensure compromised-packages.json is in the same directory as this script.")
        sys.exit(2)
    except json.JSONDecodeError as e:
        print(f"{Colors.RED}ERROR: Invalid JSON in database: {e}{Colors.NC}")
        sys.exit(2)

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def is_excluded_path(filepath: Path) -> bool:
    """Check if path should be excluded from scanning (detector's own source files only)"""
    filepath_str = str(filepath)
    filename = filepath.name
    
    # Check if it's one of the detector's specific files
    for pattern in EXCLUDED_PATTERNS:
        if pattern in ['scan-node-modules.py', 'scan-node-modules.sh', 'compromised-packages.json']:
            if filename == pattern:
                return True
        elif pattern in filepath_str:
            return True
    
    return False

def is_detector_source_code(content: str) -> bool:
    """Check if content is from the detector's own source code"""
    # Only check for very specific detector markers
    detector_markers = [
        'SUSPICIOUS_SCRIPT_PATTERNS',
        'TRUFFLEHOG_PATTERNS',
        'MALICIOUS_RUNNER_PATTERNS',
        'scan-node-modules',
    ]
    # Need multiple markers to be sure it's detector source
    marker_count = sum(1 for marker in detector_markers if marker in content)
    return marker_count >= 2

def find_files_recursive(directory: Path, pattern: str, max_depth: int = 5,
                        current_depth: int = 0) -> List[Path]:
    """Recursively find files matching pattern"""
    if current_depth > max_depth:
        return []

    results = []
    try:
        for entry in directory.iterdir():
            if entry.name.startswith('.') and entry.name not in ['.git', '.github']:
                continue

            if entry.is_file():
                if re.search(pattern, entry.name, re.IGNORECASE):
                    results.append(entry)
            elif entry.is_dir() and entry.name != 'node_modules':
                results.extend(find_files_recursive(
                    entry, pattern, max_depth, current_depth + 1))
    except PermissionError:
        pass  # Skip directories we can't read

    return results

def find_node_modules_dirs(directory: Path, max_depth: int = 15) -> List[Path]:
    """Find all node_modules directories"""
    results = []

    def search(path: Path, depth: int):
        if depth > max_depth:
            return

        try:
            for entry in path.iterdir():
                if entry.is_dir():
                    if entry.name == 'node_modules':
                        results.append(entry)
                        # Don't recurse into node_modules
                    elif not entry.name.startswith('.'):
                        search(entry, depth + 1)
        except PermissionError:
            pass

    search(directory, 0)
    return results

# =============================================================================
# DETECTION FUNCTIONS
# =============================================================================

def check_compromised_packages(node_modules_dir: Path, database: Dict[str, Any],
                               stats: ScanStats) -> List[Finding]:
    """Check for compromised packages in node_modules"""
    findings = []
    packages_dict = database['packages']

    try:
        for entry in node_modules_dir.iterdir():
            if not entry.is_dir():
                continue

            pkg_name = entry.name

            # Handle scoped packages (@scope/package)
            if pkg_name.startswith('@') and entry.is_dir():
                try:
                    for scoped_entry in entry.iterdir():
                        if scoped_entry.is_dir():
                            full_name = f"{pkg_name}/{scoped_entry.name}"
                            if full_name in packages_dict:
                                pkg_info = packages_dict[full_name]
                                severity = pkg_info.get('severity', 'critical')
                                findings.append(Finding(
                                    severity=severity,
                                    finding_type='compromised-package',
                                    title=f"Compromised package: {full_name}",
                                    description=f"This package is known to be compromised in the Shai-Hulud 2.0 attack.",
                                    location=str(scoped_entry)
                                ))
                                stats.compromised_packages += 1
                except PermissionError:
                    pass
            else:
                # Regular package
                if pkg_name in packages_dict:
                    pkg_info = packages_dict[pkg_name]
                    severity = pkg_info.get('severity', 'critical')
                    findings.append(Finding(
                        severity=severity,
                        finding_type='compromised-package',
                        title=f"Compromised package: {pkg_name}",
                        description=f"This package is known to be compromised in the Shai-Hulud 2.0 attack.",
                        location=str(entry)
                    ))
                    stats.compromised_packages += 1
    except PermissionError:
        pass

    return findings

def check_malicious_files(directory: Path, database: Dict[str, Any],
                         stats: ScanStats) -> List[Finding]:
    """Check for malicious indicator files"""
    findings = []
    malicious_files = database['malicious_files']

    for malicious_file in malicious_files:
        matches = list(directory.rglob(malicious_file))
        for match in matches:
            if is_excluded_path(match):
                continue

            findings.append(Finding(
                severity='critical',
                finding_type='malicious-file',
                title=f"Malicious indicator file: {malicious_file}",
                description=f"Found known malicious file used in Shai-Hulud attack.",
                location=str(match)
            ))
            stats.malicious_files += 1

    return findings

def check_malicious_scripts(directory: Path) -> List[Finding]:
    """Check package.json files for suspicious scripts"""
    findings = []

    package_json_files = find_files_recursive(directory, r'^package\.json$', max_depth=5)

    for pkg_file in package_json_files:
        if is_excluded_path(pkg_file):
            continue

        try:
            with open(pkg_file, 'r', encoding='utf-8') as f:
                content = f.read()
                if is_detector_source_code(content):
                    continue

                pkg_data = json.loads(content)
                scripts = pkg_data.get('scripts', {})

                for script_name, script_content in scripts.items():
                    if not script_content:
                        continue

                    # Check for critical Shai-Hulud specific patterns
                    if re.search(r'setup_bun\.js', script_content, re.IGNORECASE) or \
                       re.search(r'bun_environment\.js', script_content, re.IGNORECASE):
                        findings.append(Finding(
                            severity='critical',
                            finding_type='malicious-script',
                            title=f"Shai-Hulud malicious script in \"{script_name}\"",
                            description=f"The \"{script_name}\" script contains reference to known Shai-Hulud malicious files.",
                            location=str(pkg_file),
                            evidence=f'"{script_name}": "{script_content[:200]}"'
                        ))
                        continue

                    # Check other suspicious patterns
                    for pattern, description in SUSPICIOUS_SCRIPT_PATTERNS:
                        if re.search(pattern, script_content, re.IGNORECASE):
                            # Critical if in lifecycle hooks
                            is_critical = script_name in ['preinstall', 'postinstall', 'prepare', 'prepublish']
                            severity = 'critical' if is_critical else 'high'

                            findings.append(Finding(
                                severity=severity,
                                finding_type='suspicious-script',
                                title=f"Suspicious \"{script_name}\" script",
                                description=f"{description}. This pattern is commonly used in supply chain attacks.",
                                location=str(pkg_file),
                                evidence=f'"{script_name}": "{script_content[:200]}"'
                            ))
                            break  # Only report first match per script

        except (json.JSONDecodeError, PermissionError, UnicodeDecodeError):
            pass  # Skip files we can't read or parse

    return findings

def check_trufflehog_activity(directory: Path) -> List[Finding]:
    """Check for TruffleHog activity and credential scanning patterns"""
    findings = []

    # Files to scan for TruffleHog patterns
    script_extensions = ['.sh', '.js', '.ts', '.mjs', '.cjs']

    def search_dir(path: Path, depth: int = 0):
        if depth > 5:
            return

        try:
            for entry in path.iterdir():
                if entry.name.startswith('.') and entry.name not in ['.github']:
                    continue

                if entry.is_file():
                    # Check filename for TruffleHog binaries
                    if re.search(r'trufflehog', entry.name, re.IGNORECASE):
                        if not is_excluded_path(entry):
                            findings.append(Finding(
                                severity='critical',
                                finding_type='trufflehog-activity',
                                title='TruffleHog binary detected',
                                description='Found TruffleHog binary used for credential theft.',
                                location=str(entry)
                            ))

                    # Scan script file contents
                    if any(entry.suffix == ext for ext in script_extensions):
                        if is_excluded_path(entry):
                            continue

                        try:
                            with open(entry, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()

                                if is_detector_source_code(content):
                                    continue

                                for pattern, description in TRUFFLEHOG_PATTERNS:
                                    if re.search(pattern, content, re.IGNORECASE):
                                        findings.append(Finding(
                                            severity='critical',
                                            finding_type='trufflehog-activity',
                                            title='TruffleHog activity detected',
                                            description=f"{description}. This may indicate automated credential theft.",
                                            location=str(entry),
                                            evidence=pattern
                                        ))
                                        break

                                # Check for webhook exfiltration
                                for pattern, description in WEBHOOK_EXFIL_PATTERNS:
                                    if re.search(pattern, content, re.IGNORECASE):
                                        findings.append(Finding(
                                            severity='medium' if 'exfiltrat' in pattern else 'critical',
                                            finding_type='webhook-exfiltration',
                                            title='Data exfiltration endpoint detected',
                                            description=f"{description}. This endpoint may be used to exfiltrate stolen credentials.",
                                            location=str(entry),
                                            evidence=pattern
                                        ))
                                        break
                        except (PermissionError, UnicodeDecodeError):
                            pass

                elif entry.is_dir() and entry.name != 'node_modules':
                    search_dir(entry, depth + 1)
        except PermissionError:
            pass

    search_dir(directory)
    return findings

def check_malicious_runners(directory: Path, database: Dict[str, Any]) -> List[Finding]:
    """Check GitHub Actions workflows for malicious runners"""
    findings = []

    workflows_dir = directory / '.github' / 'workflows'
    if not workflows_dir.exists():
        return findings

    detector_pattern = re.compile(
        r'gensecaihq/Shai-Hulud-2\.0-Detector|shai-hulud.*detector|shai-hulud-check',
        re.IGNORECASE
    )

    try:
        for entry in workflows_dir.iterdir():
            if not entry.is_file() or not (entry.suffix == '.yml' or entry.suffix == '.yaml'):
                continue

            # Check for malicious workflow filename patterns
            for pattern, description in MALICIOUS_WORKFLOW_PATTERNS:
                if re.search(pattern, entry.name, re.IGNORECASE):
                    findings.append(Finding(
                        severity='critical',
                        finding_type='malicious-workflow',
                        title=f"Suspicious workflow file: {entry.name}",
                        description=f"{description}. This workflow filename matches patterns used by the Shai-Hulud attack.",
                        location=str(entry),
                        evidence=entry.name
                    ))

            # Check workflow content
            try:
                with open(entry, 'r', encoding='utf-8') as f:
                    content = f.read()

                    # Skip if this is a legitimate detector workflow
                    if detector_pattern.search(content):
                        continue

                    # Check for malicious runner patterns
                    for pattern, description in MALICIOUS_RUNNER_PATTERNS:
                        if re.search(pattern, content, re.IGNORECASE):
                            findings.append(Finding(
                                severity='critical',
                                finding_type='malicious-runner',
                                title='Malicious GitHub Actions runner detected',
                                description=f"{description}. The SHA1HULUD runner is used by the Shai-Hulud attack.",
                                location=str(entry),
                                evidence=pattern
                            ))

                    # Check for Shai-Hulud repo patterns
                    content_without_detector = detector_pattern.sub('', content)
                    for pattern, description in SHAI_HULUD_REPO_PATTERNS:
                        if re.search(pattern, content_without_detector, re.IGNORECASE):
                            findings.append(Finding(
                                severity='critical',
                                finding_type='shai-hulud-repo',
                                title='Shai-Hulud reference in workflow',
                                description=f"{description}. This workflow may be configured to exfiltrate data.",
                                location=str(entry),
                                evidence=pattern
                            ))
            except (PermissionError, UnicodeDecodeError):
                pass
    except PermissionError:
        pass

    return findings

def check_secrets_exfiltration(directory: Path) -> List[Finding]:
    """Check for secrets exfiltration files"""
    findings = []

    known_exfil_files = [
        'actionsSecrets.json',
        'cloud.json',
        'contents.json',
        'environment.json',
        'truffleSecrets.json',
        'trufflehog_output.json',
    ]

    def search_dir(path: Path, depth: int = 0):
        if depth > 5:
            return

        try:
            for entry in path.iterdir():
                if entry.name.startswith('.') and entry.name != '.github':
                    continue

                if entry.is_file():
                    # Check for known exfiltration files
                    if entry.name in known_exfil_files:
                        if not is_excluded_path(entry):
                            findings.append(Finding(
                                severity='critical',
                                finding_type='secrets-exfiltration',
                                title=f"Secrets exfiltration file: {entry.name}",
                                description=f"Found \"{entry.name}\" which is used by the Shai-Hulud attack to store stolen credentials.",
                                location=str(entry)
                            ))

                    # Check for suspicious JSON files with encoded data
                    if re.search(r'(secrets?|credentials?|exfil.*)\.json$', entry.name, re.IGNORECASE):
                        if is_excluded_path(entry):
                            continue

                        try:
                            with open(entry, 'r', encoding='utf-8') as f:
                                content = f.read()
                                # Check for base64 encoded data
                                if re.search(r'^[A-Za-z0-9+/=]{100,}$', content, re.MULTILINE):
                                    findings.append(Finding(
                                        severity='high',
                                        finding_type='secrets-exfiltration',
                                        title='Potential secrets file with encoded data',
                                        description=f"Found \"{entry.name}\" containing Base64 encoded data. May be exfiltrated credentials.",
                                        location=str(entry)
                                    ))
                        except (PermissionError, UnicodeDecodeError):
                            pass

                elif entry.is_dir() and entry.name != 'node_modules':
                    search_dir(entry, depth + 1)
        except PermissionError:
            pass

    search_dir(directory)
    return findings

def check_shai_hulud_repos(directory: Path) -> List[Finding]:
    """Check for Shai-Hulud git repository references"""
    findings = []

    # Check .git/config
    git_config = directory / '.git' / 'config'
    if git_config.exists():
        try:
            with open(git_config, 'r', encoding='utf-8') as f:
                content = f.read()

                # Skip if this is the detector's own repo
                if 'Shai-Hulud-2.0-Detector' in content or 'gensecaihq' in content:
                    pass
                else:
                    for pattern, description in SHAI_HULUD_REPO_PATTERNS:
                        if re.search(pattern, content, re.IGNORECASE):
                            findings.append(Finding(
                                severity='critical',
                                finding_type='shai-hulud-repo',
                                title='Shai-Hulud repository reference in git config',
                                description=f"{description}. Your repository may be configured to push to attacker-controlled remote.",
                                location=str(git_config)
                            ))
                            break
        except (PermissionError, UnicodeDecodeError):
            pass

    # Check package.json files for repository references
    package_files = find_files_recursive(directory, r'^package\.json$', max_depth=5)
    for pkg_file in package_files:
        if is_excluded_path(pkg_file):
            continue

        try:
            with open(pkg_file, 'r', encoding='utf-8') as f:
                content = f.read()

                if 'gensecaihq/Shai-Hulud-2.0-Detector' in content or 'shai-hulud-detector' in content:
                    continue

                for pattern, description in SHAI_HULUD_REPO_PATTERNS:
                    if re.search(pattern, content, re.IGNORECASE):
                        # Make sure it's not just referencing the detector
                        content_clean = re.sub(r'gensecaihq/Shai-Hulud-2\.0-Detector', '', content, flags=re.IGNORECASE)
                        content_clean = re.sub(r'shai-hulud-detector', '', content_clean, flags=re.IGNORECASE)

                        if re.search(pattern, content_clean, re.IGNORECASE):
                            findings.append(Finding(
                                severity='high',
                                finding_type='shai-hulud-repo',
                                title='Shai-Hulud reference in package.json',
                                description=f"{description}. Package may reference attacker infrastructure.",
                                location=str(pkg_file)
                            ))
                            break
        except (json.JSONDecodeError, PermissionError, UnicodeDecodeError):
            pass

    return findings

def check_git_branches(directory: Path) -> List[Finding]:
    """Check for suspicious git branch names"""
    findings = []

    git_dir = directory / '.git'
    if not git_dir.exists():
        return findings

    try:
        # Run git branch command
        result = subprocess.run(
            ['git', 'branch', '-a'],
            cwd=directory,
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            branches = result.stdout
            for pattern, description in SHAI_HULUD_REPO_PATTERNS:
                if re.search(pattern, branches, re.IGNORECASE):
                    findings.append(Finding(
                        severity='medium',
                        finding_type='suspicious-branch',
                        title='Suspicious git branch name',
                        description=f"{description}. Found git branch matching Shai-Hulud attack patterns.",
                        location=str(git_dir)
                    ))
                    break
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass  # Git not available or timeout

    return findings

def check_affected_namespaces(directory: Path, database: Dict[str, Any]) -> List[Finding]:
    """Check for packages from affected namespaces with semver ranges"""
    findings = []

    package_files = find_files_recursive(directory, r'^package\.json$', max_depth=5)

    for pkg_file in package_files:
        if is_excluded_path(pkg_file):
            continue

        try:
            with open(pkg_file, 'r', encoding='utf-8') as f:
                pkg_data = json.load(f)

                all_deps = {}
                all_deps.update(pkg_data.get('dependencies', {}))
                all_deps.update(pkg_data.get('devDependencies', {}))
                all_deps.update(pkg_data.get('peerDependencies', {}))
                all_deps.update(pkg_data.get('optionalDependencies', {}))

                for pkg_name, version in all_deps.items():
                    # Skip if already in compromised packages list
                    if pkg_name in database['packages']:
                        continue

                    # Check if from affected namespace
                    for namespace in AFFECTED_NAMESPACES:
                        if pkg_name.startswith(namespace + '/'):
                            # Check for semver range that could auto-update
                            if version and (version.startswith('^') or version.startswith('~')):
                                findings.append(Finding(
                                    severity='low',
                                    finding_type='namespace-warning',
                                    title='Package from affected namespace with semver range',
                                    description=f'"{pkg_name}" is from the {namespace} namespace which has known compromised packages. The version pattern "{version}" could auto-update to a compromised version.',
                                    location=str(pkg_file)
                                ))
                            break
        except (json.JSONDecodeError, PermissionError, UnicodeDecodeError):
            pass

    return findings

# =============================================================================
# SCANNING ORCHESTRATION
# =============================================================================

def scan_node_modules_dir(nm_dir: Path, database: Dict[str, Any],
                         stats: ScanStats) -> List[Finding]:
    """Scan a single node_modules directory"""
    findings = []

    # Check for compromised packages
    findings.extend(check_compromised_packages(nm_dir, database, stats))

    # Check for malicious indicator files
    findings.extend(check_malicious_files(nm_dir, database, stats))

    stats.node_modules_scanned += 1
    return findings

def run_full_scan(directory: Path, database: Dict[str, Any],
                 max_depth: int) -> Tuple[ScanStats, List[Finding]]:
    """Run comprehensive security scan"""
    stats = ScanStats()
    all_findings = []

    print(f"\n{Colors.BLUE}Starting scan from:{Colors.NC} {directory}")
    print(f"{Colors.BLUE}Maximum depth:{Colors.NC} {max_depth}\n")

    # Find all node_modules directories
    nm_dirs = find_node_modules_dirs(directory, max_depth)

    if nm_dirs:
        print(f"{Colors.BLUE}Found {len(nm_dirs)} node_modules director{'y' if len(nm_dirs) == 1 else 'ies'} to scan{Colors.NC}\n")

        for nm_dir in nm_dirs:
            findings = scan_node_modules_dir(nm_dir, database, stats)
            all_findings.extend(findings)
    else:
        print(f"{Colors.YELLOW}No node_modules directories found{Colors.NC}\n")

    # Run advanced security checks on the whole directory
    print(f"{Colors.BLUE}Running advanced security checks...{Colors.NC}\n")

    all_findings.extend(check_malicious_files(directory, database, stats))
    all_findings.extend(check_malicious_scripts(directory))
    all_findings.extend(check_trufflehog_activity(directory))
    all_findings.extend(check_malicious_runners(directory, database))
    all_findings.extend(check_secrets_exfiltration(directory))
    all_findings.extend(check_shai_hulud_repos(directory))
    all_findings.extend(check_git_branches(directory))
    all_findings.extend(check_affected_namespaces(directory, database))

    # Add all findings to stats
    for finding in all_findings:
        stats.add_finding(finding)

    return stats, all_findings

# =============================================================================
# OUTPUT FORMATTING
# =============================================================================

def print_header():
    """Print scan header"""
    print()
    print(f"{Colors.BOLD}====================================================================={Colors.NC}")
    print(f"{Colors.BOLD}  SHAI-HULUD 2.0 NODE_MODULES SCANNER (Python Edition){Colors.NC}")
    print(f"{Colors.BOLD}====================================================================={Colors.NC}")
    print()

def get_type_label(finding_type: str) -> str:
    """Get display label for finding type"""
    labels = {
        'compromised-package': 'COMPROMISED PKG',
        'malicious-file': 'MALICIOUS FILE',
        'malicious-script': 'MALICIOUS SCRIPT',
        'suspicious-script': 'SUSPICIOUS SCRIPT',
        'trufflehog-activity': 'TRUFFLEHOG',
        'malicious-runner': 'MALICIOUS RUNNER',
        'malicious-workflow': 'MALICIOUS WORKFLOW',
        'secrets-exfiltration': 'SECRETS EXFIL',
        'shai-hulud-repo': 'SHAI-HULUD REPO',
        'webhook-exfiltration': 'WEBHOOK EXFIL',
        'suspicious-branch': 'SUSPICIOUS BRANCH',
        'namespace-warning': 'NAMESPACE WARNING',
    }
    return labels.get(finding_type, finding_type.upper())

def print_findings(findings: List[Finding]):
    """Print findings grouped by severity"""
    # Group by severity
    by_severity = {
        'critical': [],
        'high': [],
        'medium': [],
        'low': []
    }

    for finding in findings:
        by_severity[finding.severity].append(finding)

    # Print critical findings
    if by_severity['critical']:
        print(f"{Colors.RED}{Colors.BOLD}CRITICAL FINDINGS:{Colors.NC}")
        for f in by_severity['critical']:
            print(f"  {Colors.RED}✗ [{get_type_label(f.finding_type)}]{Colors.NC} {f.title}")
            print(f"    Location: {f.location}")
            if f.evidence:
                print(f"    Evidence: {f.evidence[:100]}")
        print()

    # Print high findings
    if by_severity['high']:
        print(f"{Colors.YELLOW}{Colors.BOLD}HIGH RISK FINDINGS:{Colors.NC}")
        for f in by_severity['high']:
            print(f"  {Colors.YELLOW}⚠ [{get_type_label(f.finding_type)}]{Colors.NC} {f.title}")
            print(f"    Location: {f.location}")
        print()

    # Print medium findings
    if by_severity['medium']:
        print(f"{Colors.YELLOW}MEDIUM RISK FINDINGS:{Colors.NC}")
        for f in by_severity['medium']:
            print(f"  {Colors.YELLOW}⚠ [{get_type_label(f.finding_type)}]{Colors.NC} {f.title}")
            print(f"    Location: {f.location}")
        print()

    # Print low findings
    if by_severity['low']:
        print(f"{Colors.BLUE}LOW RISK FINDINGS:{Colors.NC}")
        for f in by_severity['low']:
            print(f"  {Colors.BLUE}ℹ [{get_type_label(f.finding_type)}]{Colors.NC} {f.title}")
            print(f"    Location: {f.location}")
        print()

def print_summary(stats: ScanStats):
    """Print scan summary"""
    print(f"{Colors.BOLD}====================================================================={Colors.NC}")
    print(f"{Colors.BOLD}  SCAN SUMMARY{Colors.NC}")
    print(f"{Colors.BOLD}====================================================================={Colors.NC}")
    print()
    print(f"  node_modules directories scanned: {stats.node_modules_scanned}")
    print(f"  Compromised packages found:       {stats.compromised_packages}")
    print(f"  Malicious indicator files found:  {stats.malicious_files}")
    print()

    counts = stats.count_by_severity()
    total = sum(counts.values())

    if total == 0:
        print(f"{Colors.GREEN}{Colors.BOLD}  ✓ STATUS: CLEAN{Colors.NC}")
        print(f"{Colors.GREEN}  No Shai-Hulud 2.0 threats detected{Colors.NC}")
    else:
        print(f"{Colors.RED}{Colors.BOLD}  ✗ STATUS: THREATS DETECTED{Colors.NC}")
        print()
        print(f"  Total findings: {total}")
        if counts['critical'] > 0:
            print(f"    {Colors.RED}Critical: {counts['critical']}{Colors.NC}")
        if counts['high'] > 0:
            print(f"    {Colors.YELLOW}High: {counts['high']}{Colors.NC}")
        if counts['medium'] > 0:
            print(f"    {Colors.YELLOW}Medium: {counts['medium']}{Colors.NC}")
        if counts['low'] > 0:
            print(f"    {Colors.BLUE}Low: {counts['low']}{Colors.NC}")
        print()
        print(f"{Colors.YELLOW}  IMMEDIATE ACTIONS REQUIRED:{Colors.NC}")
        print("  1. Do NOT run npm install until packages are updated")
        print("  2. Rotate all credentials (npm, GitHub, AWS, etc.)")
        print("  3. Check for unauthorized GitHub self-hosted runners named 'SHA1HULUD'")
        print("  4. Audit GitHub repos for 'Shai-Hulud: The Second Coming' description")
        print("  5. Check for actionsSecrets.json files containing stolen credentials")
        print("  6. Review package.json scripts for suspicious preinstall/postinstall hooks")
        print()
        print("  For more information:")
        print("  https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains")

    print()
    print(f"{Colors.BOLD}====================================================================={Colors.NC}")
    print()

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Shai-Hulud 2.0 Node Modules Scanner - Detect compromised packages and malicious indicators',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                        Scan current directory
  %(prog)s ~/projects             Scan specific directory
  %(prog)s --depth 10 .           Limit scan depth to 10

This scanner uses only Python standard library for maximum security and auditability.
No external dependencies. No npm/pip packages required.
        """
    )

    parser.add_argument(
        'directory',
        nargs='?',
        default='.',
        help='Directory to scan (default: current directory)'
    )

    parser.add_argument(
        '--depth',
        type=int,
        default=15,
        metavar='N',
        help='Maximum directory depth to scan (default: 15)'
    )

    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {VERSION}'
    )

    args = parser.parse_args()

    # Resolve and validate directory
    scan_dir = Path(args.directory).resolve()
    if not scan_dir.exists():
        print(f"{Colors.RED}ERROR: Directory not found: {scan_dir}{Colors.NC}")
        sys.exit(2)

    if not scan_dir.is_dir():
        print(f"{Colors.RED}ERROR: Not a directory: {scan_dir}{Colors.NC}")
        sys.exit(2)

    # Find database file
    script_dir = Path(__file__).parent
    db_path = script_dir / 'compromised-packages.json'

    # Load database
    print_header()
    print("Loading package database...", end=' ', flush=True)
    database = load_database(db_path)
    pkg_count = len(database['packages'])
    file_count = len(database['malicious_files'])
    print(f"Done! ({pkg_count} packages, {file_count} indicators)")

    # Run scan
    stats, findings = run_full_scan(scan_dir, database, args.depth)

    # Print results
    if findings:
        print_findings(findings)

    print_summary(stats)

    # Exit with appropriate code
    counts = stats.count_by_severity()
    if counts['critical'] > 0 or counts['high'] > 0:
        sys.exit(1)  # Threats found
    else:
        sys.exit(0)  # Clean

if __name__ == '__main__':
    main()

