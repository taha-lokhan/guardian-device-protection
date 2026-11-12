package com.guardian.agent

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteConstraintException
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import org.json.JSONArray
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import org.bouncycastle.util.encoders.Base64
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

/**
 * Verifies Guardian protocol-v2 Ed25519 command envelopes before any command handler runs.
 *
 * Canonical JSON is intentionally restricted to strings, booleans, null, safe
 * integers, arrays and objects with short ASCII keys. This keeps the Python and
 * Android implementations byte-for-byte interoperable.
 */
internal object GuardianCommandAuth {
    private const val PROTOCOL_VERSION = 2L
    private const val MAX_TTL_SECONDS = 3600L
    private const val MAX_CLOCK_SKEW_SECONDS = 60L
    private const val REPLAY_RETENTION_SECONDS = 7L * 24L * 60L * 60L
    private const val MAX_SAFE_INTEGER = 9007199254740991L
    private const val MAX_CANONICAL_BYTES = 64 * 1024
    internal const val REPLAY_TABLE = "processed_commands_v2"

    private val signedFields = listOf(
        "version", "key_id", "id", "device_id", "command", "params", "issued_at", "ttl", "nonce"
    )
    private val envelopeFields = (signedFields + "sig").toSet()
    private val allowedCommands = setOf(
        "ping", "status", "location", "location_burst",
        "lock", "backup", "abort_wipe", "wipe"
    )
    private val commandIdPattern =
        Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    private val base64KeyPattern = Regex("^[A-Za-z0-9+/]{43}=$")
    private val base64SignaturePattern = Regex("^[A-Za-z0-9+/]{86}==$")
    private val deviceIdPattern = Regex("^[A-Za-z0-9_-]{1,64}$")
    private val integerPattern = Regex("^-?(0|[1-9][0-9]*)$")
    private val objectKeyPattern = Regex("^[A-Za-z0-9_.-]{1,128}$")

    @Synchronized
    fun verifyAndClaim(
        payload: JSONObject,
        expectedDeviceId: String,
        publicKey: String,
        expectedKeyId: String,
        context: Context,
        nowSeconds: Long = System.currentTimeMillis() / 1000L
    ): Boolean {
        if (!verifySignature(payload, expectedDeviceId, publicKey, expectedKeyId, nowSeconds)) {
            return false
        }
        val commandId = payload.optString("id", "")
        return claimCommandId(commandId, payload.optString("nonce", ""), expectedDeviceId, context, nowSeconds)
    }

    internal fun verifySignature(
        payload: JSONObject,
        expectedDeviceId: String,
        publicKey: String,
        expectedKeyId: String,
        nowSeconds: Long
    ): Boolean {
        return try {
            val actualFields = payload.keys().asSequence().toSet()
            if (actualFields != envelopeFields) return false
            if (!base64KeyPattern.matches(publicKey)) return false
            if (!Regex("^[A-Za-z0-9_-]{1,64}$").matches(expectedKeyId)) return false
            val version = strictInteger(payload.opt("version")) ?: return false
            if (version != PROTOCOL_VERSION) return false
            if ((payload.opt("key_id") as? String) != expectedKeyId) return false

            val commandId = payload.opt("id") as? String ?: return false
            if (!commandIdPattern.matches(commandId)) return false
            val nonce = payload.opt("nonce") as? String ?: return false
            if (!commandIdPattern.matches(nonce)) return false
            val target = payload.opt("device_id") as? String ?: return false
            if (!deviceIdPattern.matches(target) || target != expectedDeviceId) return false
            val command = payload.opt("command") as? String ?: return false
            if (command !in allowedCommands || payload.opt("params") !is JSONObject) return false

            val issuedAt = strictInteger(payload.opt("issued_at")) ?: return false
            val ttl = strictInteger(payload.opt("ttl")) ?: return false
            if (ttl !in 1L..MAX_TTL_SECONDS) return false
            val age = nowSeconds - issuedAt
            if (issuedAt > nowSeconds + MAX_CLOCK_SKEW_SECONDS) return false
            if (age > ttl || age < -MAX_CLOCK_SKEW_SECONDS) return false

            val signatureText = payload.opt("sig") as? String ?: return false
            if (!base64SignaturePattern.matches(signatureText)) return false
            val signatureBytes = Base64.decode(signatureText)
            if (signatureBytes.size != 64) return false
            val unsigned = JSONObject()
            for (field in signedFields) unsigned.put(field, payload.get(field))
            val message = ("guardian-command-envelope-v2\u0000" + canonicalJson(unsigned))
                .toByteArray(StandardCharsets.UTF_8)
            if (message.size > MAX_CANONICAL_BYTES) return false
            val publicBytes = Base64.decode(publicKey)
            if (publicBytes.size != 32) return false
            val verifier = Ed25519Signer()
            verifier.init(false, Ed25519PublicKeyParameters(publicBytes, 0))
            verifier.update(message, 0, message.size)
            verifier.verifySignature(signatureBytes)
        } catch (_: Exception) {
            false
        }
    }

    private fun claimCommandId(
        commandId: String, nonce: String, deviceId: String,
        context: Context, nowSeconds: Long
    ): Boolean {
        if (!commandIdPattern.matches(commandId) || !commandIdPattern.matches(nonce)) return false
        val helper = GuardianReplayDatabase(context.applicationContext)
        var db: SQLiteDatabase? = null
        return try {
            db = helper.writableDatabase
            db.beginTransaction()
            db.delete(REPLAY_TABLE, "received_at < ?", arrayOf((nowSeconds - REPLAY_RETENTION_SECONDS).toString()))
            val values = ContentValues().apply {
                put("device_id", deviceId)
                put("command_id", commandId)
                put("nonce", nonce)
                put("received_at", nowSeconds)
            }
            db.insertOrThrow(REPLAY_TABLE, null, values)
            db.setTransactionSuccessful()
            true
        } catch (_: SQLiteConstraintException) {
            false
        } catch (_: Exception) {
            false
        } finally {
            if (db != null && db.inTransaction()) db.endTransaction()
            helper.close()
        }
    }

    private fun strictInteger(value: Any?): Long? {
        if (value !is Number) return null
        val text = value.toString()
        if (!integerPattern.matches(text)) return null
        val parsed = text.toLongOrNull() ?: return null
        if (parsed > MAX_SAFE_INTEGER || parsed < -MAX_SAFE_INTEGER) return null
        return parsed
    }

    internal fun canonicalJson(value: Any?, depth: Int = 0): String {
        if (depth > 16) throw IllegalArgumentException("JSON nesting exceeds protocol limit")
        return when {
            value == null || value === JSONObject.NULL -> "null"
            value is String -> quoteJson(value)
            value is Boolean -> value.toString()
            value is Number -> {
                val integer = strictInteger(value)
                    ?: throw IllegalArgumentException("Only safe integers are supported")
                integer.toString()
            }
            value is JSONObject -> {
                val keys = value.keys().asSequence().toList().sorted()
                for (key in keys) {
                    if (!objectKeyPattern.matches(key)) {
                        throw IllegalArgumentException("Invalid JSON object key")
                    }
                }
                keys.joinToString(prefix = "{", postfix = "}", separator = ",") { key ->
                    quoteJson(key) + ":" + canonicalJson(value.get(key), depth + 1)
                }
            }
            value is JSONArray -> {
                (0 until value.length()).joinToString(prefix = "[", postfix = "]", separator = ",") {
                    canonicalJson(value.get(it), depth + 1)
                }
            }
            else -> throw IllegalArgumentException("Unsupported JSON type")
        }
    }

    private fun quoteJson(value: String): String {
        val out = StringBuilder("\"")
        var index = 0
        while (index < value.length) {
            val ch = value[index]
            when (ch) {
                '"' -> out.append("\\\"")
                '\\' -> out.append("\\\\")
                '\b' -> out.append("\\b")
                '\u000C' -> out.append("\\f")
                '\n' -> out.append("\\n")
                '\r' -> out.append("\\r")
                '\t' -> out.append("\\t")
                else -> {
                    val code = ch.toInt()
                    if (code < 0x20) {
                        out.append(String.format(java.util.Locale.ROOT, "\\u%04x", code))
                    } else if (Character.isHighSurrogate(ch)) {
                        if (index + 1 >= value.length || !Character.isLowSurrogate(value[index + 1])) {
                            throw IllegalArgumentException("Unpaired high surrogate")
                        }
                        out.append(ch).append(value[index + 1])
                        index++
                    } else if (Character.isLowSurrogate(ch)) {
                        throw IllegalArgumentException("Unpaired low surrogate")
                    } else {
                        out.append(ch)
                    }
                }
            }
            index++
        }
        return out.append('"').toString()
    }

}


/** App-private persistent replay store with atomic command-ID uniqueness. */
private class GuardianReplayDatabase(context: Context) :
    SQLiteOpenHelper(context, "guardian-command-replay.db", null, 2) {

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            "CREATE TABLE IF NOT EXISTS processed_commands_v2 (" +
                "device_id TEXT NOT NULL, command_id TEXT NOT NULL, nonce TEXT NOT NULL, " +
                "received_at INTEGER NOT NULL, PRIMARY KEY(device_id, command_id), " +
                "UNIQUE(device_id, nonce))"
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS idx_processed_commands_v2_received_at " +
                "ON processed_commands_v2(received_at)"
        )
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        if (oldVersion < 2) {
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS processed_commands_v2 (" +
                    "device_id TEXT NOT NULL, command_id TEXT NOT NULL, nonce TEXT NOT NULL, " +
                    "received_at INTEGER NOT NULL, PRIMARY KEY(device_id, command_id), " +
                    "UNIQUE(device_id, nonce))"
            )
            db.execSQL(
                "CREATE INDEX IF NOT EXISTS idx_processed_commands_v2_received_at " +
                    "ON processed_commands_v2(received_at)"
            )
        }
    }
}
