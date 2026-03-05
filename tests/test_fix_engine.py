"""Tests for Fix Engine."""

from src.fix_engine import FixAction, FixEngine


class TestFixEngine:
    """Fix engine test cases."""

    def test_preview_returns_command(self) -> None:
        engine = FixEngine()
        action = FixAction(
            action_id="test_action",
            title="Test Fix",
            command="echo test",
        )
        assert engine.preview(action) == "echo test"

    def test_fix_action_fields(self) -> None:
        action = FixAction(
            action_id="ssh_root_login",
            title="Disable root login",
            command="sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config",
            requires_root=True,
            auto_apply_safe=True,
        )
        assert action.requires_root is True
        assert action.auto_apply_safe is True
