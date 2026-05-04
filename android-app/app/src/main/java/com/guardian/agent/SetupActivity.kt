package com.guardian.agent

import android.app.admin.DevicePolicyManager
import android.content.*
import android.os.Bundle
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat

class SetupActivity : AppCompatActivity() {
    private val REQUEST_ENABLE_ADMIN = 1001

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val prefs = getSharedPreferences("guardian", Context.MODE_PRIVATE)
        if (prefs.getBoolean("configured", false)) { startGuardianService(); return }
        setContentView(R.layout.activity_setup)

        findViewById<Button>(R.id.btn_save).setOnClickListener {
            val relayIp    = findViewById<EditText>(R.id.et_relay_ip).text.toString().trim()
            val mqttPass   = findViewById<EditText>(R.id.et_mqtt_pass).text.toString().trim()
            val deviceId   = findViewById<EditText>(R.id.et_device_id).text.toString().trim()
            val deviceName = findViewById<EditText>(R.id.et_device_name).text.toString().trim()
            val wgIp       = findViewById<EditText>(R.id.et_wg_ip).text.toString().trim()

            if (relayIp.isEmpty() || mqttPass.isEmpty() || deviceId.isEmpty()) {
                Toast.makeText(this, "All fields required", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            prefs.edit()
                .putString("relay_ip",   relayIp)
                .putString("mqtt_pass",  mqttPass)
                .putString("device_id",  deviceId)
                .putString("device_name", deviceName)
                .putString("wg_ip",      wgIp)
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
        ContextCompat.startForegroundService(this, Intent(this, GuardianService::class.java))
        Toast.makeText(this, "Guardian is active", Toast.LENGTH_LONG).show()
        finish()
    }
}
