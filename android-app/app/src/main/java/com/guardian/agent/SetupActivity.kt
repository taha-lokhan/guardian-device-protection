package com.guardian.agent

import android.app.admin.DevicePolicyManager
import android.content.*
import android.os.Bundle
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat

class SetupActivity : AppCompatActivity() {
    private val REQUEST_ENABLE_ADMIN = 1001
    private var reconfigureExisting = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val prefs = getSharedPreferences("guardian", Context.MODE_PRIVATE)
        val alreadyConfigured = prefs.getBoolean("configured", false)
        reconfigureExisting = alreadyConfigured
        setContentView(R.layout.activity_setup)

        // Keep setup available after activation so an administrator can rotate
        // MQTT and command-authentication credentials without clearing app data.
        if (alreadyConfigured) {
            findViewById<EditText>(R.id.et_device_name).setText(prefs.getString("device_name", ""))
            findViewById<EditText>(R.id.et_device_id).setText(prefs.getString("device_id", ""))
            findViewById<EditText>(R.id.et_relay_ip).setText(prefs.getString("relay_ip", ""))
            findViewById<EditText>(R.id.et_wg_ip).setText(prefs.getString("wg_ip", ""))
            findViewById<EditText>(R.id.et_mqtt_pass).setText(prefs.getString("mqtt_pass", ""))
            findViewById<EditText>(R.id.et_command_key_id).setText(
                prefs.getString("command_key_id", "")
            )
            findViewById<EditText>(R.id.et_command_public_key).setText(
                prefs.getString("command_public_key", "")
            )
            findViewById<Button>(R.id.btn_save).text = "UPDATE GUARDIAN CONFIG"
        }

        findViewById<Button>(R.id.btn_save).setOnClickListener {
            val relayIp    = findViewById<EditText>(R.id.et_relay_ip).text.toString().trim()
            val mqttPass   = findViewById<EditText>(R.id.et_mqtt_pass).text.toString().trim()
            val deviceId   = findViewById<EditText>(R.id.et_device_id).text.toString().trim()
            val deviceName = findViewById<EditText>(R.id.et_device_name).text.toString().trim()
            val wgIp       = findViewById<EditText>(R.id.et_wg_ip).text.toString().trim()
            val commandKeyId = findViewById<EditText>(R.id.et_command_key_id).text.toString().trim()
            val commandPublicKey = findViewById<EditText>(R.id.et_command_public_key).text.toString().trim()

            if (relayIp.isEmpty() || mqttPass.isEmpty() || deviceId.isEmpty() ||
                !commandKeyId.matches(Regex("^[A-Za-z0-9_-]{1,64}$")) ||
                !GuardianCommandAuth.isValidPublicKey(commandPublicKey)) {
                Toast.makeText(
                    this,
                    "Relay, MQTT, device ID and the device-specific Ed25519 key ID/public key are required.",
                    Toast.LENGTH_LONG
                ).show()
                return@setOnClickListener
            }

            prefs.edit()
                .putString("relay_ip",   relayIp)
                .putString("mqtt_pass",  mqttPass)
                .putString("device_id",  deviceId)
                .putString("device_name", deviceName)
                .putString("wg_ip",      wgIp)
                .putString("command_key_id", commandKeyId)
                .putString("command_public_key", commandPublicKey)
                .putBoolean("configured", true)
                .apply()

            requestDeviceAdmin()
        }
    }

    private fun requestDeviceAdmin() {
        val admin = ComponentName(this, GuardianAdminReceiver::class.java)
        val dpm   = getSystemService(DEVICE_POLICY_SERVICE) as DevicePolicyManager
        if (!dpm.isAdminActive(admin)) {
            startActivityForResult(Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN).apply {
                putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, admin)
                putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION,
                    "Guardian needs Device Admin to lock and wipe this device if stolen.")
            }, REQUEST_ENABLE_ADMIN)
        } else startGuardianService()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_ENABLE_ADMIN) startGuardianService()
    }

    private fun startGuardianService() {
        val serviceIntent = Intent(this, GuardianService::class.java)
        if (reconfigureExisting) {
            serviceIntent.action = GuardianService.ACTION_RECONFIGURE
        }
        ContextCompat.startForegroundService(this, serviceIntent)
        Toast.makeText(this, "Guardian configuration saved", Toast.LENGTH_LONG).show()
        finish()
    }
}
