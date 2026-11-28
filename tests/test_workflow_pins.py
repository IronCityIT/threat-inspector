"""Every external action in .github/workflows must be SHA-pinned to a Node 24 release.

A floating tag such as ``@v4`` can be moved by whoever controls the action's
repository; a 40-character commit SHA cannot. The trailing ``# vX.Y.Z`` comment
records which release that SHA is, so a reviewer (or Dependabot) can tell what
it is and what to upgrade from.

GitHub's Node 20 runtime is end-of-life: runners force Node 20 actions onto Node 24
and warn on every run. ``NODE24_SINCE_MAJOR`` records, per action, the first major
release whose ``action.yml`` declares ``runs.using: node24``. Each entry was
verified by reading ``action.yml`` at the floating major tags (2026-11-28). An
action not in the table fails the test until someone verifies its runtime and adds
it. That way a new dependency cannot slip in on Node 20 unnoticed.

Exempt: local refs (``./...``) and the org's own reusable workflows
(``IronCityIT/<repo>/.github/workflows/...``), which are reviewed in this org and
deliberately tracked on their default branch.
"""

from __future__ import annotations

import pathlib
import re
from typing import Any

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW_DIR = ROOT / ".github" / "workflows"
WORKFLOWS = sorted([*WORKFLOW_DIR.glob("*.yml"), *WORKFLOW_DIR.glob("*.yaml")])

FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
VERSION_COMMENT = re.compile(r"^#\s*v(?P<major>\d+)\.\d+\.\d+\s*$")
# A `uses:` line in raw text, e.g. `      - uses: owner/repo@<sha> # v1.2.3`.
USES_LINE = re.compile(
    r"""^\s*(?:-\s+)?uses:\s*["']?(?P<ref>[^\s"'#]+)["']?\s*(?P<comment>#.*)?$"""
)
FIRST_PARTY_WORKFLOW = re.compile(r"^IronCityIT/[^/]+/\.github/workflows/")

# First major whose action.yml declares `runs.using: node24` (earlier majors: node20).
NODE24_SINCE_MAJOR = {
    "actions/checkout": 5,
    "actions/setup-python": 6,
    "actions/setup-node": 5,
    "actions/setup-java": 5,
    "actions/upload-artifact": 6,  # v5 is still node20
    "actions/download-artifact": 7,  # v5 and v6 are still node20
    "google-github-actions/auth": 3,
}


def is_exempt(ref: str) -> bool:
    return ref.startswith("./") or FIRST_PARTY_WORKFLOW.match(ref) is not None


def iter_uses(workflow: Any) -> list[str]:
    """Every ``uses:`` value in a parsed workflow, job-level and step-level."""
    refs: list[str] = []
    jobs = workflow.get("jobs") if isinstance(workflow, dict) else None
    for job in (jobs or {}).values():
        if not isinstance(job, dict):
            continue
        if isinstance(job.get("uses"), str):
            refs.append(job["uses"])
        for step in job.get("steps") or []:
            if isinstance(step, dict) and isinstance(step.get("uses"), str):
                refs.append(step["uses"])
    return refs


def raw_comments(raw_text: str) -> dict[str, list[str]]:
    """Map each ``uses:`` ref in the raw source to the trailing comment(s) on its line(s).

    PyYAML drops comments, so the ``# vX.Y.Z`` check has to read the raw text.
    """
    found: dict[str, list[str]] = {}
    for line in raw_text.splitlines():
        match = USES_LINE.match(line)
        if match:
            found.setdefault(match["ref"], []).append((match["comment"] or "").strip())
    return found


def pin_problems(ref: str, comments: list[str]) -> list[str]:
    """Why external action ``ref`` is not an acceptable pin; empty when it is.

    ``comments`` are the trailing comments on every raw line that uses ``ref``.
    """
    action, sep, version = ref.rpartition("@")
    if not sep:
        return [f"{ref}: no @ref at all"]
    problems = []
    if not FULL_SHA.match(version):
        problems.append(f"{ref}: ref is not a 40-character commit SHA")
    if not comments:
        problems.append(f"{ref}: could not find its `uses:` line to read the version comment")
    majors = []
    for comment in comments:
        match = VERSION_COMMENT.match(comment)
        if match:
            majors.append(int(match["major"]))
        else:
            problems.append(f"{ref}: missing trailing '# vX.Y.Z' version comment (got {comment!r})")
    repo = "/".join(action.split("/")[:2])
    since = NODE24_SINCE_MAJOR.get(repo)
    if since is None:
        problems.append(
            f"{ref}: {repo} has no verified Node 24 release in NODE24_SINCE_MAJOR; check "
            "`runs.using` in its action.yml and add it"
        )
    else:
        problems.extend(
            f"{ref}: v{major} of {repo} runs on Node 20; Node 24 starts at v{since}"
            for major in majors
            if major < since
        )
    return problems


def workflow_problems(raw_text: str) -> list[str]:
    comments = raw_comments(raw_text)
    refs = dict.fromkeys(iter_uses(yaml.safe_load(raw_text)))  # unique, in order
    return [
        problem
        for ref in refs
        if not is_exempt(ref)
        for problem in pin_problems(ref, comments.get(ref, []))
    ]


# --- the repository's workflows ---------------------------------------------


def test_walker_finds_external_actions() -> None:
    """Guard: if parsing or the walk breaks, the pin test would pass by finding nothing."""
    assert WORKFLOWS, f"no workflow files found in {WORKFLOW_DIR}"
    external = [
        ref
        for path in WORKFLOWS
        for ref in iter_uses(yaml.safe_load(path.read_text()))
        if not is_exempt(ref)
    ]
    assert external, "walker found no external `uses:` refs"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_external_actions_are_sha_pinned_node24_releases(path: pathlib.Path) -> None:
    problems = workflow_problems(path.read_text())
    assert not problems, f"{path.name}:\n  " + "\n  ".join(problems)


# --- the checker itself must reject what it is meant to reject ---------------

SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"


def _steps_workflow(*lines: str) -> str:
    body = "".join(f"      - {line}\n" for line in lines)
    return f"on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n{body}"


def test_sha_pinned_node24_release_passes() -> None:
    assert workflow_problems(_steps_workflow(f"uses: actions/checkout@{SHA} # v7.0.1")) == []


@pytest.mark.parametrize(
    "line",
    [
        "uses: actions/checkout@v4",
        "uses: actions/checkout@v7 # v7.0.1",
        f"uses: actions/checkout@{SHA[:7]} # v7.0.1",
        f"uses: actions/checkout@{SHA.upper()} # v7.0.1",
        f"uses: actions/checkout@{SHA}",
        f"uses: actions/checkout@{SHA} # v7",
        "uses: actions/checkout",
        "uses: docker://alpine:3",
    ],
    ids=[
        "tag",
        "major-tag-with-comment",
        "short-sha",
        "uppercase-sha",
        "no-comment",
        "major-only-comment",
        "no-ref",
        "docker",
    ],
)
def test_unpinned_or_uncommented_refs_fail(line: str) -> None:
    assert workflow_problems(_steps_workflow(line))


@pytest.mark.parametrize(
    "line",
    [
        f"uses: actions/checkout@{SHA} # v4.2.2",
        f"uses: actions/setup-python@{SHA} # v5.6.0",
        f"uses: actions/upload-artifact@{SHA} # v5.0.0",
        f"uses: actions/download-artifact@{SHA} # v6.0.0",
        f"uses: google-github-actions/auth@{SHA} # v2.1.13",
    ],
    ids=["checkout-v4", "setup-python-v5", "upload-artifact-v5", "download-artifact-v6", "auth-v2"],
)
def test_node20_releases_fail(line: str) -> None:
    problems = workflow_problems(_steps_workflow(line))
    assert any("runs on Node 20" in p for p in problems), problems


def test_action_without_verified_runtime_fails() -> None:
    problems = workflow_problems(_steps_workflow(f"uses: some-org/some-action@{SHA} # v9.9.9"))
    assert any("no verified Node 24 release" in p for p in problems), problems


def test_job_level_uses_is_walked() -> None:
    raw = "on: push\njobs:\n  a:\n    uses: other-org/repo/.github/workflows/w.yml@main\n"
    assert workflow_problems(raw)


def test_exemptions_are_local_and_ironcityit_reusable_workflows_only() -> None:
    assert is_exempt("./.github/workflows/_consensus-store.yml")
    assert is_exempt("IronCityIT/consensus-engine/.github/workflows/analyze.yml@main")
    assert not is_exempt("IronCityIT/some-action@v1")  # an org *action* still gets pinned
    assert not is_exempt("ironcityit-fork/repo/.github/workflows/w.yml@main")
    assert not is_exempt("actions/checkout@v4")
    raw = (
        "on: push\njobs:\n"
        "  a:\n    uses: IronCityIT/consensus-engine/.github/workflows/analyze.yml@main\n"
        "  b:\n    uses: ./.github/workflows/_consensus-store.yml\n"
    )
    assert workflow_problems(raw) == []


def test_every_occurrence_of_a_ref_needs_the_comment() -> None:
    raw = _steps_workflow(f"uses: actions/checkout@{SHA} # v7.0.1", f"uses: actions/checkout@{SHA}")
    assert workflow_problems(raw)
