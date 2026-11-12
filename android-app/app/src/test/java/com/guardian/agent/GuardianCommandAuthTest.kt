package com.guardian.agent

import android.util.Base64
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import org.junit.Assert.assertEquals
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
    fun kotlinCanonicalizationMatchesPythonEd25519Vector() {
        val unsigned = JSONObject().apply {
            put("version", 2)
            put("key_id", keyId)
            put("id", "11111111-1111-4111-8111-111111111111")
            put("device_id", target)
            put("command", "ping")
            put("params", JSONObject().put(
                "nested", JSONObject().put("count", 2).put("label", "synthetic")
            ).put("enabled", true))
            put("issued_at", 1800000000)
            put("ttl", 300)
            put("nonce", "22222222-2222-4222-8222-222222222222")
        }
        val canonical = GuardianCommandAuth.canonicalJson(unsigned)
        assertEquals(
            "{\"command\":\"ping\",\"device_id\":\"synthetic-device-01\",\"id\":\"11111111-1111-4111-8111-111111111111\",\"issued_at\":1800000000,\"key_id\":\"test-key-01\",\"nonce\":\"22222222-2222-4222-8222-222222222222\",\"params\":{\"enabled\":true,\"nested\":{\"count\":2,\"label\":\"synthetic\"}},\"ttl\":300,\"version\":2}",
            canonical
        )
        val message = ("guardian-command-envelope-v2\\u0000" + canonical)
            .toByteArray(StandardCharsets.UTF_8)
        val verifier = Ed25519Signer()
        verifier.init(false, Ed25519PublicKeyParameters(Base64.decode(publicKey, Base64.DEFAULT), 0))
        verifier.update(message, 0, message.size)
        assertTrue(verifier.verifySignature(Base64.decode(
            "IvMM8qubRvw+TT9dsph3V6iTcH+b/IGWmxY5ADojhzSWMOkZDhzpJHoYryRZceQnshtmgaZpEOl8EsQIBOPaBQ==",
            Base64.DEFAULT
        )))
    }

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
