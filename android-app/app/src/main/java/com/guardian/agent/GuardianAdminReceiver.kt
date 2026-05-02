package com.guardian.agent

import android.app.admin.DeviceAdminReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

class GuardianAdminReceiver : DeviceAdminReceiver() {
    override fun onEnabled(context: Context, intent: Intent) {
        Log.d("Guardian", "Device Admin enabled")
    }
    override fun onDisabled(context: Context, intent: Intent) {
        Log.d("Guardian", "Device Admin disabled — remote wipe LOST")
    }
}