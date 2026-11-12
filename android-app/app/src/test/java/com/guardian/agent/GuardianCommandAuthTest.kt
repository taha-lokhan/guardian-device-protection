package com.guardian.agent

import org.json.JSONObject
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class GuardianCommandAuthTest {
    private val publicKey = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w="
    private val target = "synthetic-device-01"
    private val keyId = "test-key-01"

    private fun knownVector(): JSONObject = JSONObject(
        """
        {
          "version": 2,
          "key_id": "test-key-01",
          "id": "11111111-1111-4111-8111-111111111111",
          "device_id": "synthetic-device-01",
          "command": "ping",
          "params": {
            "nested": {"count": 2, "label": "synthetic"},
            "enabled": true
          },
          "issued_at": 1800000000,
          "ttl": 300,
          "nonce": "22222222-2222-4222-8222-222222222222",
          "sig": "IvMM8qubRvw+TT9dsph3V6iTcH+b/IGWmxY5ADojhzSWMOkZDhzpJHoYryRZceQnshtmgaZpEOl8EsQIBOPaBQ=="
        }
        """.trimIndent()
    )

    @Test
    fun acceptsPythonEd25519ProtocolV2KnownVector() {
        assertTrue(GuardianCommandAuth.verifySignature(
            knownVector(), target, publicKey, keyId, 1800000001L
        ))
    }

    @Test
    fun rejectsModifiedNestedParamsAndUnknownKeyId() {
        val changed = knownVector()
        changed.getJSONObject("params").getJSONObject("nested").put("count", 3)
        assertFalse(GuardianCommandAuth.verifySignature(
            changed, target, publicKey, keyId, 1800000001L
        ))
        assertFalse(GuardianCommandAuth.verifySignature(
            knownVector(), target, publicKey, "revoked-key", 1800000001L
        ))
    }

    @Test
    fun rejectsWrongTargetAndAlteredNonce() {
        assertFalse(GuardianCommandAuth.verifySignature(
            knownVector(), "synthetic-device-02", publicKey, keyId, 1800000001L
        ))
        val altered = knownVector().put("nonce", "33333333-3333-4333-8333-333333333333")
        assertFalse(GuardianCommandAuth.verifySignature(
            altered, target, publicKey, keyId, 1800000001L
        ))
    }

    @Test
    fun rejectsExpiredAndFutureCommands() {
        assertFalse(GuardianCommandAuth.verifySignature(
            knownVector(), target, publicKey, keyId, 1800000400L
        ))
        val future = knownVector().put("issued_at", 1800000061L)
        assertFalse(GuardianCommandAuth.verifySignature(
            future, target, publicKey, keyId, 1800000000L
        ))
    }

    @Test
    fun rejectsSignatureAndEnvelopeShapeTampering() {
        val badSignature = knownVector().put("sig", "A".repeat(88))
        assertFalse(GuardianCommandAuth.verifySignature(
            badSignature, target, publicKey, keyId, 1800000001L
        ))
        val extraField = knownVector().put("unexpected", true)
        assertFalse(GuardianCommandAuth.verifySignature(
            extraField, target, publicKey, keyId, 1800000001L
        ))
    }
}
