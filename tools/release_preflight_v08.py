"""KARIO v0.8 local-only public-release preflight (report, NEVER publish).

This is a conservative source-tree inventory and secret-pattern check, not
legal clearance, a complete malware scan, or a substitute for human review.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
from typing import Any

SCHEMA = "KARIO_RELEASE_PREFLIGHT_V0_8"
MAX_SOURCE_BYTES = 1024 * 1024
IGNORE_DIRS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
PRIVATE_ROOT_DIRS = {"data", "private", "outputs", "local_data", "secrets", "research_r1", "research", "datasets", "credentials", "customer_data"}
MANDATORY_FILES = ("README.md", "DATA_RIGHTS.md", ".gitignore", "LICENSE", "pyproject.toml")
MANDATORY_GITIGNORE = (
    ".venv/", "__pycache__/", ".env", "*.pem", "*.key", "*.jsonl", "*.log", "*.csv", "*.sqlite", "*.db", "data/", "private/", "outputs/"
)

SECRET_PATTERNS = (
    ("PEM_PRIVATE_KEY", re.compile(r"-----BEGIN\s+(?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED)\s+)?PRIVATE\s+KEY-----[ \t]*\r?\n(?:[A-Za-z0-9+/=]{16,}[ \t]*\r?\n)+-----END\s+(?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED)\s+)?PRIVATE\s+KEY-----")),
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GITHUB_TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("OPENAI_STYLE_TOKEN", re.compile(r"\bsk-[A-Za-z0-9_-]{24,}\b")),
    ("ASSIGNED_SECRET", re.compile(
        r"\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|password)\s*[:=]\s*['\"][^'\"\s]{20,}['\"]", re.I
    )),
)
PEM_HEADER_MARKER = re.compile(r"-----BEGIN\s+(?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED)\s+)?PRIVATE\s+KEY-----")
VENDOR_IMPORT = re.compile(
    r"^\s*(?:from\s+(?:lseg|refinitiv|eikon|factset|ravenpack)(?:\b|\.)|"
    r"import\s+(?:lseg|refinitiv|eikon|factset|ravenpack)(?:\b|\.))",
    re.M | re.I,
)


def _allowed_file(name: str) -> bool:
    p = PurePosixPath(name)
    if len(p.parts) == 1:
        return name in MANDATORY_FILES or bool(re.fullmatch(r"requirements-[A-Za-z0-9_.-]+\.txt", name))
    if name.startswith("src/kario_pit/") and name.endswith(".py"):
        return len(p.parts) >= 3
    if name.startswith("tools/") and len(p.parts) == 2 and name.endswith(".py"):
        return True
    if name.startswith("tests/") and len(p.parts) == 2 and re.fullmatch(r"test_[A-Za-z0-9_]+\.py", p.name):
        return True
    if name.startswith("examples/synthetic/") and len(p.parts) == 3 and name.endswith(".py"):
        return True
    if name.startswith("docs/") and len(p.parts) == 2 and name.endswith(".md"):
        return True
    return False


def _safe_relative(root: Path, file: Path) -> str:
    return file.relative_to(root).as_posix()


def _finding(code: str, path: str = "", line: int | None = None, severity: str = "BLOCKER") -> dict[str, Any]:
    # Do not include excerpted source text, keys, private identifiers or absolute paths.
    out: dict[str, Any] = {"code": code, "severity": severity}
    if path:
        out["relative_path"] = path
    if line is not None:
        out["line"] = line
    return out


def _iter_repo_files(root: Path) -> tuple[list[Path], list[dict[str, Any]], bool]:
    files: list[Path] = []
    findings: list[dict[str, Any]] = []
    ignored_env = False
    for directory, dirs, names in os.walk(root, topdown=True, followlinks=False):
        current = Path(directory)
        safe_dirs = []
        for d in sorted(dirs):
            sub = current / d
            rel = _safe_relative(root, sub)
            if sub.is_symlink():
                findings.append(_finding("SYMLINK_DIRECTORY_REFUSED", rel))
            elif d in IGNORE_DIRS:
                if d in {".venv", "venv"}:
                    ignored_env = True
                continue
            elif current == root and d.lower() in PRIVATE_ROOT_DIRS:
                # Regardless of .gitignore: do not silently permit customer/private material
                findings.append(_finding("PRIVATE_DIRECTORY_PRESENT", rel))
            else:
                safe_dirs.append(d)
        dirs[:] = safe_dirs
        for name in sorted(names):
            candidate = current / name
            rel = _safe_relative(root, candidate)
            if candidate.is_symlink():
                findings.append(_finding("SYMLINK_FILE_REFUSED", rel))
            elif not candidate.is_file():
                findings.append(_finding("NONREGULAR_FILE_REFUSED", rel))
            else:
                files.append(candidate)
    return sorted(files), findings, ignored_env


def _git_review(root: Path) -> tuple[list[dict[str, Any]], int | None]:
    git_dir = root / ".git"
    if not git_dir.exists():
        return [_finding("GIT_INDEX_NOT_AVAILABLE", severity="MANUAL")], None
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"], capture_output=True,
            timeout=8, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return [_finding("GIT_INDEX_INSPECTION_FAILED")], None
    if proc.returncode != 0:
        return [_finding("GIT_INDEX_INSPECTION_FAILED")], None
    findings = []
    tracked = []
    for raw in proc.stdout.split(b"\x00"):
        if not raw:
            continue
        rel = os.fsdecode(raw).replace("\\", "/")
        tracked.append(rel)
        if not _allowed_file(rel):
            findings.append(_finding("UNAPPROVED_GIT_TRACKED_FILE", rel))
    findings.append(_finding("GIT_HISTORY_REVIEW_NOT_PERFORMED", severity="MANUAL"))
    return findings, len(tracked)


def review_tree(root: Path) -> dict[str, Any]:
    root = Path(root).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Root must be a directory")
    files, findings, ignored_env = _iter_repo_files(root)
    candidates: list[dict[str, Any]] = []
    dependencies: list[dict[str, str]] = []
    for name in MANDATORY_FILES:
        if not (root / name).is_file():
            findings.append(_finding("MISSING_REQUIRED_FILE", name))
    for file in files:
        rel = _safe_relative(root, file)
        if not _allowed_file(rel):
            if rel.startswith("PATCH_NOTES_V0_") and rel.endswith(".md"):
                findings.append(_finding("PATCH_NOTES_EXCLUDED", rel, severity="MANUAL"))
            else:
                findings.append(_finding("UNAPPROVED_FILE", rel))
            continue
        size = file.stat().st_size
        if size > MAX_SOURCE_BYTES:
            findings.append(_finding("OVERSIZE_SOURCE", rel))
            continue
        raw = file.read_bytes()
        try:
            decoded = raw.decode("utf-8-sig")
        except UnicodeError:
            findings.append(_finding("INVALID_UTF8_SOURCE", rel))
            continue
        for label, pattern in SECRET_PATTERNS:
            hit = pattern.search(decoded)
            if hit:
                findings.append(_finding(label, rel, decoded.count("\n", 0, hit.start()) + 1))
        if PEM_HEADER_MARKER.search(decoded) and not SECRET_PATTERNS[0][1].search(decoded):
            findings.append(_finding("PEM_HEADER_LITERAL_MANUAL_REVIEW", rel, severity="MANUAL"))
        if rel.endswith(".py") and VENDOR_IMPORT.search(decoded):
            findings.append(_finding("VENDOR_SDK_IMPORT", rel))
        if rel == "LICENSE" and not decoded.strip():
            findings.append(_finding("EMPTY_LICENSE", rel))
        if rel == "DATA_RIGHTS.md" and not decoded.strip():
            findings.append(_finding("EMPTY_DATA_RIGHTS_POLICY", rel))
        if rel.startswith("requirements-") and rel.endswith(".txt"):
            for s in decoded.splitlines():
                s = s.strip()
                if not s or s.startswith("#"):
                    continue
                if re.fullmatch(r"[a-zA-Z0-9_.-]+==[a-zA-Z0-9_.+!~-]+", s):
                    pkg, version = s.split("==", 1)
                    dependencies.append({"package": pkg, "version": version, "license_review": "PENDING_MANUAL"})
                else:
                    findings.append(_finding("UNREVIEWED_DEPENDENCY_SPEC", rel))
        candidates.append({"path": rel, "size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})

    ignored_status = []
    if (root / ".gitignore").is_file():
        try:
            ignore_text = (root / ".gitignore").read_text(encoding="utf-8-sig")
            entries = {ln.strip() for ln in ignore_text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")}
            ignored_status = [pattern for pattern in MANDATORY_GITIGNORE if pattern not in entries]
            for gap in ignored_status:
                findings.append(_finding("GITIGNORE_RULE_MISSING", gap))
        except UnicodeError:
            findings.append(_finding("INVALID_GITIGNORE"))

    git_findings, tracked_count = _git_review(root)
    findings.extend(git_findings)
    # This is a proposal manifest. No package, external data or source bytes are copied.
    blockers = sum(f["severity"] == "BLOCKER" for f in findings)
    return {
        "schema_version": SCHEMA,
        "status": "BLOCKED" if blockers else "MANUAL_REVIEW_ONLY",
        "blocking_findings": blockers,
        "candidate_count": len(candidates),
        "candidate_manifest": sorted(candidates, key=lambda row: row["path"]),
        "findings": sorted(findings, key=lambda f: (f["severity"], f["code"], f.get("relative_path", ""))),
        "dependency_inventory": sorted(dependencies, key=lambda d: d["package"].lower()),
        "git_tracked_count": tracked_count,
        "ignored_local_environment_present": ignored_env,
        "data_license_independently_verified": False,
        "dependencies_license_cleared": False,
        "security_audit_completed": False,
        "git_history_review_completed": False,
        "public_release_authorized": False,
        "repository_published": False,
        "pit_certified": False,
        "trusted_time_verified": False,
        "lseg_connector_included": False,
        "release_note": "Offline candidate list only; manual security, code ownership, dependency and data-rights reviews mandatory."
    }


def write_report(report: dict[str, Any], report_path: Path, source_root: Path) -> None:
    root = Path(source_root).expanduser().resolve(strict=True)
    output = Path(report_path).expanduser().resolve(strict=False)
    if output == root or root in output.parents:
        raise ValueError("Never write release reports inside the source tree")
    if output.is_symlink():
        raise ValueError("Report destination may not be a symlink")
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".kario_v08_", suffix=".json.tmp", dir=output.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, output)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="KARIO v0.8 offline release preflight (NO PUBLISH)")
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--require-clean", action="store_true", help="Return nonzero if any blocker is reported")
    args = parser.parse_args(argv)
    try:
        report = review_tree(args.root)
        write_report(report, args.report, args.root)
    except (OSError, ValueError) as e:
        print(f"KARIO preflight could not complete: {type(e).__name__}", file=sys.stderr)
        return 2
    print(json.dumps({
        "schema_version": report["schema_version"], "status": report["status"],
        "candidate_count": report["candidate_count"], "blocking_findings": report["blocking_findings"],
        "public_release_authorized": False, "report_written": True,
    }, sort_keys=True))
    return 1 if args.require_clean and report["blocking_findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
