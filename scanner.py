#!/usr/bin/env python3
"""
GitLab Ansible Role Scanner

Scans all GitLab repositories and detects Ansible roles by structural indicators.
Outputs a self-contained HTML report.

Token permissions
─────────────────
  read_api   — sufficient if you only need repos accessible to the token owner
               (personal repos + groups where the user is a member).
  api        — required if you want to enumerate ALL repos on the instance
               (admin-level listing).
  sudo       — optional scope that lets the token impersonate other users;
               combined with `api` it gives full visibility. Enable with
               --sudo flag or GITLAB_SUDO=1 env var. Requires admin account.

Environment variables:
    GITLAB_URL             — GitLab instance URL (required)
    GITLAB_TOKEN           — Personal access token (required)
    GITLAB_GROUP           — Limit scan to this group path (optional)
    GITLAB_EXCLUDE_GROUPS  — Comma-separated group paths to skip (optional)
    GITLAB_SUDO            — Set to 1 to enable sudo mode (optional)
    GITLAB_SSL_VERIFY      — Set to 0 to disable SSL verification (optional, default: 1)

Usage:
    python scanner.py [--group GROUP] [--exclude-group GROUP] [--output FILE]
                      [--min-confidence LEVEL] [--sudo] [--no-ssl-verify]
"""

import argparse
import base64
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import gitlab
import urllib3
from jinja2 import Environment, FileSystemLoader

# ANSI colours — disabled automatically when stdout is not a TTY
_IS_TTY = sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _IS_TTY else text

def _green(t):  return _c("32",   t)
def _yellow(t): return _c("33",   t)
def _red(t):    return _c("31",   t)
def _bold(t):   return _c("1",    t)
def _dim(t):    return _c("2",    t)
def _cyan(t):   return _c("36",   t)

SCANNER_VERSION = "1.1.0"

# Primary indicators — strong evidence the directory IS an Ansible role.
PRIMARY_INDICATORS = [
    "tasks/main.yml",
    "defaults/main.yml",
    "handlers/main.yml",
    "meta/main.yml",
    "vars/main.yml",
]

# Container directories that hold role subdirectories.
ROLE_CONTAINER_NAMES = {"roles", "role", "playbooks", "plays", "playbook", "ansible"}
VENDOR_LIKE_NAMES    = {"vendor", "external", "third_party", "third-party"}

NAME_PATTERNS = [
    re.compile(r"^ansible-role-", re.IGNORECASE),
    re.compile(r"^role-",         re.IGNORECASE),
]

README_PATTERN = re.compile(r"ansible[_\s-]role", re.IGNORECASE)

NESTED_BUDGET     = 25   # max API calls per repo for the nested-roles BFS
NESTED_MAX_DEPTH  = 5    # max directory depth to explore
SAVE_INTERVAL     = 100  # render the HTML report every N scanned projects


@dataclass
class CommitInfo:
    message: str
    author_name: str
    author_email: str
    committed_date: str


@dataclass
class Indicator:
    label: str
    css_class: str


@dataclass
class RepoResult:
    name: str
    namespace: str
    web_url: str
    description: str
    confidence: str
    indicators: list[Indicator]
    nested_role_paths: list[str]
    has_molecule: bool
    last_commit: CommitInfo | None
    prev_commit: CommitInfo | None
    days_since_commit: int
    activity_class: str


def file_exists(project, path: str) -> bool:
    """Check if a file path exists in the default branch."""
    try:
        project.files.get(file_path=path, ref=project.default_branch or "HEAD")
        return True
    except Exception:
        return False


def dir_exists(project, path: str) -> bool:
    """Check if a directory exists by listing its tree path."""
    try:
        items = project.repository_tree(
            path=path.rstrip("/"),
            ref=project.default_branch or "HEAD",
            per_page=1,
            get_all=False,
        )
        return len(items) > 0
    except Exception:
        return False


def has_molecule(project) -> bool:
    """Return True if the repo contains a molecule/ directory."""
    return dir_exists(project, "molecule")


def find_nested_roles(project, budget: int = NESTED_BUDGET, max_depth: int = NESTED_MAX_DEPTH) -> list[str]:
    """BFS for role-like directories nested inside container folders.

    Recurses into well-known role containers (roles/, playbooks/, ansible/, plays/),
    their subdirectories, and vendor-like names. A directory is reported as a role
    if it contains a `tasks/` subdirectory.

    Stops when the API-call budget is exhausted or queue is empty.
    """
    branch = project.default_branch or "HEAD"
    found: list[str] = []
    used  = [0]

    def list_dir(path: str):
        if used[0] >= budget:
            return None
        used[0] += 1
        try:
            return project.repository_tree(
                path=path, ref=branch, per_page=100, get_all=False
            )
        except Exception:
            return None

    queue: list[tuple[str, int]] = [("", 0)]
    while queue and used[0] < budget:
        path, depth = queue.pop(0)
        if depth >= max_depth:
            continue

        entries = list_dir(path)
        if not entries:
            continue

        # If this non-root directory has tasks/ → it's a role
        if path:
            has_tasks = any(
                e.get("type") == "tree" and e.get("name") == "tasks"
                for e in entries
            )
            if has_tasks:
                found.append(path)
                continue  # don't recurse into a found role

        # Decide which subdirectories to enqueue
        path_parts    = path.split("/") if path else []
        last_segment  = path_parts[-1] if path_parts else ""
        in_container  = last_segment in ROLE_CONTAINER_NAMES
        in_vendor     = any(p in VENDOR_LIKE_NAMES for p in path_parts)

        for e in entries:
            if e.get("type") != "tree":
                continue
            name = e.get("name", "")
            sub  = f"{path}/{name}" if path else name

            if name in ROLE_CONTAINER_NAMES:
                queue.append((sub, depth + 1))
            elif in_container or in_vendor:
                queue.append((sub, depth + 1))
            elif name in VENDOR_LIKE_NAMES:
                queue.append((sub, depth + 1))

    return found


def readme_mentions_ansible(project) -> bool:
    """Return True if any README file mentions 'ansible role'."""
    for readme_name in ("README.md", "README.rst", "README.txt", "README"):
        try:
            f = project.files.get(file_path=readme_name, ref=project.default_branch or "HEAD")
            content = base64.b64decode(f.content).decode("utf-8", errors="replace")
            if README_PATTERN.search(content):
                return True
        except Exception:
            continue
    return False


def collect_indicators(project) -> list[Indicator]:
    """Return all matched indicators for a project (root level only)."""
    indicators: list[Indicator] = []

    # Name-based check (cheap — no API call)
    for pat in NAME_PATTERNS:
        if pat.match(project.name):
            indicators.append(Indicator(
                label=pat.pattern.strip("^").rstrip("-").rstrip("*") + "*",
                css_class="name-match",
            ))
            break

    # Primary structural indicators
    for path in PRIMARY_INDICATORS:
        if file_exists(project, path):
            indicators.append(Indicator(label=path, css_class="primary"))

    # README text check
    if readme_mentions_ansible(project):
        indicators.append(Indicator(label="README mentions", css_class="readme"))

    return indicators


def compute_confidence(indicators: list[Indicator], nested: list[str]) -> str:
    """Determine confidence level from indicators and nested role paths."""
    # Nested roles found = strong signal regardless of root indicators
    if nested:
        return "High"

    primary_labels = set(PRIMARY_INDICATORS)
    primary  = sum(1 for i in indicators if i.label in primary_labels)
    has_name = any(i.css_class == "name-match" for i in indicators)

    if primary >= 3 or (has_name and primary >= 2):
        return "High"
    if primary >= 2 or (has_name and primary >= 1):
        return "Medium"
    return "Low"


def activity_class(days: int) -> str:
    if days < 90:
        return "fresh"
    if days < 365:
        return "aging"
    return "stale"


def get_commits(project) -> tuple[CommitInfo | None, CommitInfo | None]:
    """Fetch the two most recent commits."""
    try:
        commits = project.commits.list(per_page=2, get_all=False)
    except Exception:
        return None, None

    def to_info(c) -> CommitInfo:
        return CommitInfo(
            message=c.message.strip(),
            author_name=c.author_name,
            author_email=c.author_email,
            committed_date=c.committed_date,
        )

    last = to_info(commits[0]) if len(commits) > 0 else None
    prev = to_info(commits[1]) if len(commits) > 1 else None
    return last, prev


def days_ago(iso_date: str) -> int:
    """Return integer days between iso_date and now (UTC)."""
    try:
        dt = datetime.fromisoformat(iso_date.replace("Z", "+00:00"))
        return (datetime.now(tz=timezone.utc) - dt).days
    except Exception:
        return 0


CONFIDENCE_RANK = {"High": 3, "Medium": 2, "Low": 1}
MIN_CONFIDENCE_MAP = {"high": 3, "medium": 2, "low": 1}


def scan_project(project) -> RepoResult | None:
    """Analyse a single project and return a result, or None if not a role at all."""
    try:
        indicators = collect_indicators(project)

        # Skip nested search if the repo IS a role at root (saves API budget)
        is_root_role = any(i.label == "tasks/main.yml" for i in indicators)
        nested       = [] if is_root_role else find_nested_roles(project)

        if not indicators and not nested:
            return None

        confidence = compute_confidence(indicators, nested)

        # Nested role paths become visible indicators so the column is never blank
        for path in nested:
            indicators.append(Indicator(label=path, css_class="nested"))

        molecule   = has_molecule(project)
        if molecule:
            indicators.append(Indicator(label="molecule", css_class="molecule"))
        last, prev = get_commits(project)

        days = days_ago(last.committed_date) if last else 9999
        act  = activity_class(days)

        return RepoResult(
            name=project.name,
            namespace=project.namespace["full_path"],
            web_url=project.web_url,
            description=project.description or "",
            confidence=confidence,
            indicators=indicators,
            nested_role_paths=nested,
            has_molecule=molecule,
            last_commit=last,
            prev_commit=prev,
            days_since_commit=days,
            activity_class=act,
        )
    except Exception as exc:
        print(f"  [WARN] {project.path_with_namespace}: {exc}", file=sys.stderr)
        return None


def is_excluded(namespace: str, exclude_groups: list[str]) -> bool:
    """Return True if the project namespace falls under any excluded group."""
    for excl in exclude_groups:
        if namespace == excl or namespace.startswith(excl + "/"):
            return True
    return False


def iter_projects(gl: gitlab.Gitlab, group_path: str | None) -> list:
    """Return all accessible projects with live pagination progress.

    Paginates manually (100 per page) so we can print a running count while
    enumerating — useful when the instance has thousands of repositories and
    the discovery phase would otherwise appear frozen.
    """
    if group_path:
        group  = gl.groups.get(group_path)
        manager = group.projects
        kwargs  = {"include_subgroups": True}
    else:
        manager = gl.projects
        kwargs  = {}

    collected: list = []
    page = 1
    while True:
        batch = manager.list(page=page, per_page=100, **kwargs)
        if not batch:
            break
        collected.extend(batch)
        # Print running count on a single overwriting line
        print(
            f"\r  {_dim('Enumerating…')} {_bold(str(len(collected)))} projects found",
            end="", flush=True,
        )
        if len(batch) < 100:
            break
        page += 1

    return collected


def group_results(results: list[RepoResult]) -> list[dict]:
    """Group results by their top-level GitLab namespace."""
    buckets: dict[str, list[RepoResult]] = {}
    for r in results:
        top = r.namespace.split("/")[0] if r.namespace else "(no group)"
        buckets.setdefault(top, []).append(r)

    groups = []
    for top in sorted(buckets.keys()):
        repos = buckets[top]
        groups.append({
            "name":   top,
            "repos":  repos,
            "high":   sum(1 for r in repos if r.confidence == "High"),
            "medium": sum(1 for r in repos if r.confidence == "Medium"),
            "low":    sum(1 for r in repos if r.confidence == "Low"),
            "total":  len(repos),
        })
    return groups


def render_report(
    repos: list[RepoResult],
    total_scanned: int,
    output_path: Path,
    comments: dict[str, str] | None = None,
) -> None:
    template_dir = Path(__file__).parent
    env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=True)
    template = env.get_template("report_template.html")

    stats = {
        "total_scanned": total_scanned,
        "total_found":   len(repos),
        "high":   sum(1 for r in repos if r.confidence == "High"),
        "medium": sum(1 for r in repos if r.confidence == "Medium"),
        "low":    sum(1 for r in repos if r.confidence == "Low"),
    }

    html = template.render(
        groups=group_results(repos),
        stats=stats,
        generated_at=datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        scanner_version=SCANNER_VERSION,
        comments=comments or {},
    )
    output_path.write_text(html, encoding="utf-8")
    print(f"Report written to: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan GitLab for Ansible role repositories")
    parser.add_argument("--group",          metavar="GROUP_PATH", help="Limit scan to this GitLab group path")
    parser.add_argument("--exclude-group",  metavar="GROUP_PATH", action="append", dest="exclude_groups", default=[],
                        help="Skip this group and all its subgroups (repeatable)")
    parser.add_argument("--output",         metavar="FILE",       default=None, help="Output HTML file (default: report_TIMESTAMP.html)")
    parser.add_argument("--min-confidence", metavar="LEVEL",      choices=["low", "medium", "high"], default="low",
                        help="Minimum confidence level to include in report (default: low)")
    parser.add_argument("--sudo",           action="store_true",  default=False,
                        help="Enable GitLab sudo mode (requires admin token with sudo scope). "
                             "Allows scanning ALL repos regardless of membership. "
                             "Also enabled via GITLAB_SUDO=1 env var.")
    parser.add_argument("--no-ssl-verify",  action="store_true",  default=False,
                        help="Disable SSL certificate verification (useful for self-signed certs). "
                             "Also enabled via GITLAB_SSL_VERIFY=0 env var.")
    parser.add_argument("--comments",       metavar="FILE",       default=None,
                        help="JSON file with saved comments to embed into the report "
                             "(key: repo web_url, value: comment text). "
                             "If omitted, auto-detected as comments.json next to the output file.")
    args = parser.parse_args()

    gitlab_url   = os.environ.get("GITLAB_URL")
    gitlab_token = os.environ.get("GITLAB_TOKEN")
    group_path   = args.group or os.environ.get("GITLAB_GROUP") or None

    # Merge --exclude-group args with GITLAB_EXCLUDE_GROUPS env var
    env_excludes    = [g.strip() for g in os.environ.get("GITLAB_EXCLUDE_GROUPS", "").split(",") if g.strip()]
    exclude_groups  = list(dict.fromkeys(args.exclude_groups + env_excludes))  # deduplicate, preserve order

    # sudo: --sudo flag OR GITLAB_SUDO=1
    use_sudo    = args.sudo or os.environ.get("GITLAB_SUDO", "").strip() == "1"
    # ssl_verify: disabled by --no-ssl-verify OR GITLAB_SSL_VERIFY=0
    ssl_verify  = not args.no_ssl_verify and os.environ.get("GITLAB_SSL_VERIFY", "1").strip() != "0"

    if not ssl_verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if not gitlab_url or not gitlab_token:
        print("Error: GITLAB_URL and GITLAB_TOKEN environment variables are required.", file=sys.stderr)
        sys.exit(1)

    output_path = Path(args.output) if args.output else Path(f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
    min_rank    = MIN_CONFIDENCE_MAP[args.min_confidence]

    # Load comments: explicit file > auto-detect comments.json next to output
    comments: dict[str, str] = {}
    comments_path = Path(args.comments) if args.comments else output_path.parent / "comments.json"
    if comments_path.exists():
        try:
            comments = json.loads(comments_path.read_text(encoding="utf-8"))
            print(f"  {_dim('Comments loaded from')} {comments_path}  ({len(comments)} entries)")
        except Exception as exc:
            print(f"[WARN] Could not read comments file {comments_path}: {exc}", file=sys.stderr)

    gl = gitlab.Gitlab(gitlab_url, private_token=gitlab_token, ssl_verify=ssl_verify)
    try:
        gl.auth()
        if use_sudo:
            gl.sudo = 1
    except Exception as exc:
        print(f"Error: GitLab authentication failed: {exc}", file=sys.stderr)
        sys.exit(1)

    print(_bold(f"Connected to {gitlab_url}"))
    if group_path:
        print(f"Scope   : {_cyan(group_path)}")
    else:
        print("Scope   : all accessible projects")
    if use_sudo:
        print(f"Mode    : {_yellow('sudo')} (all repos, requires admin token)")
    if not ssl_verify:
        print(f"SSL     : {_yellow('verification disabled')}")
    if exclude_groups:
        print(f"Exclude : {_yellow(', '.join(exclude_groups))}")

    # ── Step 1: enumerate all projects up front so we know the total ──
    print(_dim("\nEnumerating projects…"))
    all_projects = iter_projects(gl, group_path)
    total = len(all_projects)
    # Clear the progress line, print final count
    print(f"\r  {_dim('Enumerating…')} {_bold(str(total))} projects found. \n")

    results:  list[RepoResult] = []
    skipped   = 0
    width     = len(str(total))

    def save_partial(label: str = "partial") -> None:
        """Render the current results to the output file."""
        sorted_results = sorted(results, key=lambda r: (-CONFIDENCE_RANK[r.confidence], r.days_since_commit))
        render_report(sorted_results, total, output_path, comments)

    # ── Step 2: scan each project ──────────────────────────────────────
    for idx, project in enumerate(all_projects, 1):
        namespace = getattr(project, "path_with_namespace", "")
        name      = namespace or str(project.id)
        counter   = f"[{idx:{width}d}/{total}]"

        if is_excluded(project.namespace.get("full_path", ""), exclude_groups):
            skipped += 1
            continue

        # Overwrite the current line with the "scanning…" status
        print(f"  {_dim(counter)} {name:<72}", end="\r", flush=True)

        result = scan_project(project)

        if result and CONFIDENCE_RANK[result.confidence] >= min_rank:
            results.append(result)

            conf_label = {
                "High":   _green(_bold("HIGH  ")),
                "Medium": _yellow(_bold("MED   ")),
                "Low":    _red(_bold("LOW   ")),
            }[result.confidence]
            mol_tag        = f" {_cyan('[molecule]')}" if result.has_molecule else ""
            nested_tag     = f" {_cyan(f'[nested:{len(result.nested_role_paths)}]')}" if result.nested_role_paths else ""
            indicators_str = " ".join(f"[{i.label}]" for i in result.indicators)
            print(f"  {_dim(counter)} {_bold(name):<55} {conf_label}{_dim(indicators_str)}{mol_tag}{nested_tag}")

        # Periodic save — every SAVE_INTERVAL projects, write the report so far.
        # If the script crashes, the latest partial state is on disk.
        if idx % SAVE_INTERVAL == 0:
            save_partial()
            print(f"  {_dim(f'… partial report saved ({len(results)} roles so far → {output_path})')}")

    # Clear the last status line
    print(" " * 82, end="\r")

    # ── Summary ────────────────────────────────────────────────────────
    n_high   = sum(1 for r in results if r.confidence == "High")
    n_medium = sum(1 for r in results if r.confidence == "Medium")
    n_low    = sum(1 for r in results if r.confidence == "Low")

    n_molecule = sum(1 for r in results if r.has_molecule)
    n_nested   = sum(1 for r in results if r.nested_role_paths)
    nested_total = sum(len(r.nested_role_paths) for r in results)

    sep = "─" * 56
    print(sep)
    print(f"  Scanned : {_bold(str(total))} repos"
          + (f"  ({_yellow(str(skipped))} excluded)" if skipped else ""))
    print(f"  Found   : {_bold(str(len(results)))} role-bearing repos  "
          f"({_green(f'High: {n_high}')}  "
          f"{_yellow(f'Medium: {n_medium}')}  "
          f"{_red(f'Low: {n_low}')})")
    if n_nested:
        print(f"  Nested  : {_cyan(str(n_nested))} repos contain {_cyan(str(nested_total))} nested roles")
    if n_molecule:
        print(f"  Molecule: {_cyan(str(n_molecule))} roles have molecule/ tests")
    print(f"  Output  : {output_path}")
    print(sep + "\n")

    # Sort: High first, then by days_since_commit ascending
    results.sort(key=lambda r: (-CONFIDENCE_RANK[r.confidence], r.days_since_commit))

    render_report(results, total, output_path, comments)


if __name__ == "__main__":
    main()
