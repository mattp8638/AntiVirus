"""ISMS roles and permissions (ported from the standalone app's tests)."""

import pytest

from fenrir_cloud.isms.access import (
    PERMISSIONS, ROLE_PERMISSIONS, TENANT_ROLES, IsmsForbidden, assert_can, can, can_on_record,
)


def test_tenant_admins_get_every_permission():
    assert all(can("tenant_admin", p) for p in PERMISSIONS)


def test_isms_managers_do_not_get_tenant_security_settings():
    assert can("isms_manager", "programme.manage")
    assert not can("isms_manager", "tenant.security.manage")


def test_auditors_and_executives_are_read_only():
    for role in ("auditor", "executive_viewer"):
        assert not any(p.endswith((".edit", ".manage")) for p in ROLE_PERMISSIONS[role])


def test_unknown_or_missing_roles_are_denied():
    assert not can(None, "documents.view")
    assert not can("", "documents.view")
    assert not can("platform_admin", "documents.view")  # Fenrir roles are not ISMS roles


def test_every_role_is_covered():
    # Every grantable role has permissions; the one extra is the API credential's read-only role, never granted.
    assert sorted(ROLE_PERMISSIONS) == sorted((*TENANT_ROLES, "api_reader"))
    assert ROLE_PERMISSIONS["api_reader"] == {"controls.view", "risks.view", "documents.view", "evidence.view"}
    assert all(p in PERMISSIONS for perms in ROLE_PERMISSIONS.values() for p in perms)


def test_owners_edit_their_own_records_only():
    assert can_on_record("control_owner", "u1", "controls.edit", "u1")
    assert not can_on_record("control_owner", "u1", "controls.edit", "u2")
    assert not can_on_record("control_owner", "u1", "controls.edit", None)
    assert not can_on_record("staff", "u1", "controls.edit", "u1")  # cannot even view controls
    assert not can_on_record("control_owner", "u1", "risks.accept", "u1")  # no override for acceptance
    assert can_on_record("isms_manager", "u1", "controls.edit", "u2")


def test_assert_can_raises():
    with pytest.raises(IsmsForbidden):
        assert_can("staff", "programme.manage")
    assert_can("isms_manager", "programme.manage")
