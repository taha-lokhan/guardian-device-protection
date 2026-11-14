"""Cross-platform command ACK contract checks for Guardian agents."""

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_python_agents_are_syntactically_valid():
    ast.parse(source("windows-agent/guardian_windows_agent.py"))
    ast.parse(source("mac-agent/guardian_mac_agent.py"))


def test_windows_and_macos_acknowledge_abort_commands_with_correlation_ids():
    windows = source("windows-agent/guardian_windows_agent.py")
    macos = source("mac-agent/guardian_mac_agent.py")

    assert 'send_ack("abort_wipe", "flag_set", command_id)' in windows
    assert 'send_ack("abort_wipe", "flag_set", command_id)' in macos


def test_all_agents_use_original_wipe_command_for_initiation_and_abort():
    windows = source("windows-agent/guardian_windows_agent.py")
    macos = source("mac-agent/guardian_mac_agent.py")
    android = source(
        "android-app/app/src/main/java/com/guardian/agent/GuardianService.kt"
    )

    assert '"command": "wipe"' in windows
    assert '"id": command_id' in windows
    assert 'send_ack("wipe", "initiating", command_id)' in macos
    assert 'send_ack("wipe", "aborted_locally", command_id)' in macos
    assert 'sendAck("wipe", "initiating", commandId)' in android
    assert 'sendAck("wipe", "aborted_locally", commandId)' in android


def test_agents_do_not_emit_unmatched_wipe_complete_ack_names():
    for path in (
        "windows-agent/guardian_windows_agent.py",
        "mac-agent/guardian_mac_agent.py",
        "android-app/app/src/main/java/com/guardian/agent/GuardianService.kt",
    ):
        assert "wipe_complete" not in source(path), path


def test_android_abort_command_acknowledges_its_own_id():
    android = source(
        "android-app/app/src/main/java/com/guardian/agent/GuardianService.kt"
    )
    assert 'sendAck("abort_wipe", "flag_set", commandId)' in android


def test_abort_flags_are_initialized_before_wipe_workers_start():
    windows = source("windows-agent/guardian_windows_agent.py")
    macos = source("mac-agent/guardian_mac_agent.py")
    android = source(
        "android-app/app/src/main/java/com/guardian/agent/GuardianService.kt"
    )

    assert 'elif command == "wipe":\n        _wipe_abort_flag.clear()\n        def do_wipe():' in windows
    assert 'elif command == "wipe":\n        _wipe_abort_flag.clear()' in macos
    assert 'wipeAbortRequested = false\n                Thread { doWipeWithAbort(commandId) }.start()' in android
