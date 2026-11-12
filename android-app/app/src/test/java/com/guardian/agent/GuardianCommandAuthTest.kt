package com.guardian.agent

import org.json.JSONObject
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class GuardianCommandAuthTest {
    private val key = "0123456789abcdef".repeat(4)
    private val target = "synthetic-device-01"

    private fun knownVector(): JSONObject = JSONObject(
        """
        {
          "version": 1,
          "id": "11111111-1111-4111-8111-111111111111",
          "device_id": "synthetic-device-01",
          "command": "ping",
          "params": {
            "nested": {"count": 2, "label": "synthetic"},
            "enabled": true
          },
          "issued_at": 1800000000,
          "ttl": 300,
          "sig": "dbdf8209050af0b8bf753f038bc035d44a2873ca8760eadaddd34c8a9b54194e"
        }
        """.trimIndent()
    )

    @Test
    fun acceptsPythonProtocolV1KnownVector() {
        assertTrue(
            GuardianCommandAuth.verifySignature(
                knownVector(), target, key, 1800000001L
            )
        )
    }

    @Test
    fun rejectsModifiedNestedParams() {
        val payload = knownVector()
        payload.getJSONObject("params")
            .getJSONObject("nested")
            .put("count", 3)

        assertFalse(
            GuardianCommandAuth.verifySignature(
                payload, target, key, 1800000001L
            )
        )
    }

    @Test
    fun rejectsWrongTargetDevice() {
        assertFalse(
            GuardianCommandAuth.verifySignature(
                knownVector(), "synthetic-device-02", key, 1800000001L
            )
        )
    }

    @Test
    fun rejectsExpiredAndFutureCommands() {
        assertFalse(
            GuardianCommandAuth.verifySignature(
                knownVector(), target, key, 1800000400L
            )
        )

        val future = knownVector().put("issued_at", 1800000061L)
        assertFalse(
            GuardianCommandAuth.verifySignature(
                future, target, key, 1800000000L
            )
        )
    }

    @Test
    fun rejectsSignatureAndEnvelopeShapeTampering() {
        val badSignature = knownVector().put("sig", "0".repeat(64))
        assertFalse(
            GuardianCommandAuth.verifySignature(
                badSignature, target, key, 1800000001L
            )
        )

        val extraField = knownVector().put("unexpected", true)
        assertFalse(
            GuardianCommandAuth.verifySignature(
                extraField, target, key, 1800000001L
            )
        )
    }
}
