"""Shared deterministic, non-production configuration for isolated tests."""
import os

# Relay imports in tests require a valid protocol key. This fixed synthetic key
# is test-only and must never be used by a deployed relay or device.
os.environ["COMMAND_SIGNING_KEY"] = "0123456789abcdef" * 4
