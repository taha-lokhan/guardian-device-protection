# Run in an elevated PowerShell session after provisioning this device on the relay.
$ErrorActionPreference = "Stop"
$DeviceId = Read-Host "Device ID (must match the relay key directory)"
$KeyId = Read-Host "Device command key ID"
$PublicKey = Read-Host "Device Ed25519 public key (base64)"

if ($DeviceId -notmatch '^[A-Za-z0-9_-]{1,64}$') { throw "Invalid device ID." }
if ($KeyId -notmatch '^[A-Za-z0-9_-]{1,64}$') { throw "Invalid key ID." }
if ($PublicKey -notmatch '^[A-Za-z0-9+/]{43}=$') { throw "Public key must be a base64-encoded 32-byte Ed25519 key." }

[Environment]::SetEnvironmentVariable("GUARDIAN_DEVICE_ID", $DeviceId, "Machine")
[Environment]::SetEnvironmentVariable("GUARDIAN_COMMAND_KEY_ID", $KeyId, "Machine")
[Environment]::SetEnvironmentVariable("GUARDIAN_COMMAND_PUBLIC_KEY", $PublicKey, "Machine")

Write-Host "Device-specific verification public key configured."
Write-Host "The public key is not secret; never copy the relay private key to this endpoint."
Write-Host "Restart the Guardian agent/service to load the new environment."
