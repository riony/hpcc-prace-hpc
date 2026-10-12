"""Functional check runners: post-patch regressions each scenario must keep passing."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Callable, Protocol


@dataclass(frozen=True)
class CheckResult:
    check_id: str
    passed: bool
    detail: str
    status: str = ""        # pass | fail | error; derived from passed when empty
    code: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.status:
            object.__setattr__(self, "status", "pass" if self.passed else "fail")
        if not self.code:
            object.__setattr__(self, "code", f"{self.check_id or 'check'}-{self.status}")


class CheckRunner(Protocol):
    def run(self) -> list[CheckResult]:
        """Execute declared functional checks and return ordered results."""


# Legitimate work each security scenario's patch must leave working. Component 4
# owns these checks; a scenario cannot run while one lacks an observer.
# - unauthorized-data-write: authorized alpha/beta writes + normal Slurm job
# - unauthorized-compute (authorization): legitimate partition job still runs
# - admin-credential-exposure: normal home access + valid-project job
REGRESSION_MATRIX = {
    "permission-read-ctf": ["alpha-authorized-write", "beta-authorized-write", "normal-project-job"],
    "unauthorized-data-write": [
        "alpha-authorized-write",
        "beta-authorized-write",
        "normal-project-job",
    ],
    "unauthorized-compute": [
        "normal-cpu-job",
        "worker-remains-healthy",
    ],
    "admin-credential-exposure": [
        "normal-home-access",
        "normal-project-job",
    ],
}


def run_callable_checks(checks: list[tuple[str, Callable[[], Any]]]) -> list[CheckResult]:
    """Run each check in order. A check returns (passed, detail) or a CheckResult;
    one that raises is an error, never a pass or a functional regression."""
    results: list[CheckResult] = []
    for check_id, fn in checks:
        try:
            value = fn()
        except Exception as exc:  # noqa: BLE001 - recorded as an observer error
            results.append(CheckResult(check_id, False, f"observer error: {type(exc).__name__}", "error"))
            continue
        if isinstance(value, CheckResult):
            results.append(replace(value, check_id=check_id))
        else:
            passed, detail = value
            results.append(CheckResult(check_id, bool(passed), detail))
    return results


class RegressionCheckRunner:
    """The scenario's REGRESSION_MATRIX checks, in order. A missing observer refuses."""

    def __init__(self, scenario_id: str, checks: dict[str, Callable[[], Any]]):
        if scenario_id not in REGRESSION_MATRIX:
            raise ValueError(f"no regression matrix for {scenario_id}")
        missing = sorted(set(REGRESSION_MATRIX[scenario_id]) - set(checks))
        if missing:
            raise ValueError(f"missing regression observers: {missing}")
        self.order = REGRESSION_MATRIX[scenario_id]
        self.checks = checks

    def run(self) -> list[CheckResult]:
        return run_callable_checks([(check_id, self.checks[check_id]) for check_id in self.order])
