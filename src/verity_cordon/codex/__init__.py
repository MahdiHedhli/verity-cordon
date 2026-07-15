"""Supported Codex hook and installation boundary for Verity Cordon."""

from verity_cordon.codex.demo_installer import (
    DesktopDemoError,
    DesktopDemoResult,
    DesktopDemoStatus,
    DesktopFixtureProbe,
    DesktopSystemReadiness,
    probe_desktop_fixture,
    probe_desktop_system,
    setup_desktop_demo,
    status_desktop_demo,
    teardown_desktop_demo,
)
from verity_cordon.codex.hooks import HookAdapter
from verity_cordon.codex.installer import (
    CodexDoctorReport,
    IntegrationResult,
    doctor_codex,
    install_codex,
    uninstall_codex,
)

__all__ = [
    "CodexDoctorReport",
    "DesktopDemoError",
    "DesktopDemoResult",
    "DesktopDemoStatus",
    "DesktopFixtureProbe",
    "DesktopSystemReadiness",
    "HookAdapter",
    "IntegrationResult",
    "doctor_codex",
    "install_codex",
    "probe_desktop_fixture",
    "probe_desktop_system",
    "setup_desktop_demo",
    "status_desktop_demo",
    "teardown_desktop_demo",
    "uninstall_codex",
]
