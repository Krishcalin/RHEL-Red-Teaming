"""T1069 — Permission Groups Discovery.

Checks accessibility of local and domain group enumeration.
Sub-techniques: T1069.001 (Local Groups), T1069.002 (Domain Groups).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule

PRIVILEGED_GROUPS = {"wheel", "sudo", "root", "adm", "shadow", "disk", "docker", "lxd", "libvirt"}


class PermissionGroupsCheck(BaseModule):
    TECHNIQUE_ID = "T1069"
    TECHNIQUE_NAME = "Permission Groups Discovery"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.LOW
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # T1069.001 — Local Groups
        groups = session.execute("cat /etc/group")
        if groups.success:
            all_groups = []
            priv_groups_found = []
            for line in groups.output.splitlines():
                if line and not line.startswith("#"):
                    parts = line.split(":")
                    gname = parts[0]
                    members = parts[3] if len(parts) > 3 else ""
                    all_groups.append(gname)
                    if gname in PRIVILEGED_GROUPS and members:
                        priv_groups_found.append(f"{gname}: {members}")

            self.add_finding(
                title="Local groups enumerable via /etc/group",
                description=f"{len(all_groups)} groups discoverable",
                severity=Severity.INFO,
                evidence=f"Total groups: {len(all_groups)}",
            )

            if priv_groups_found:
                self.add_finding(
                    title="Privileged group memberships exposed",
                    description="Users in privileged groups are visible to all users",
                    severity=Severity.LOW,
                    evidence="\n".join(priv_groups_found),
                    remediation="Review privileged group membership regularly",
                )

        # Check current user's groups
        id_result = session.execute("id")
        if id_result.success:
            output = id_result.output
            for pg in PRIVILEGED_GROUPS:
                if f"({pg})" in output:
                    self.add_finding(
                        title=f"Current user is in privileged group: {pg}",
                        description=f"The scanning user belongs to the '{pg}' group",
                        severity=Severity.MEDIUM,
                        evidence=output,
                        remediation=f"Verify that membership in '{pg}' is intended and documented",
                    )

        # T1069.002 — Domain Groups
        getent_group = session.execute("getent group 2>/dev/null | wc -l")
        local_count = len(groups.output.splitlines()) if groups.success else 0
        if getent_group.success and getent_group.output.strip().isdigit():
            total = int(getent_group.output.strip())
            if total > local_count:
                self.add_finding(
                    title="Domain groups enumerable",
                    description=f"getent returns {total} groups vs {local_count} local — directory groups exposed",
                    severity=Severity.LOW,
                    evidence=f"Additional directory groups: {total - local_count}",
                    remediation="Restrict SSSD/LDAP group enumeration",
                )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Review and minimize privileged group memberships",
            "Set enumerate = false in SSSD for domain groups",
            "Remove users from wheel/sudo unless required",
            "Audit docker/lxd/libvirt group membership (container escape risk)",
        ]
