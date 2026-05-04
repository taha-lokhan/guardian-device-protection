package com.guardian.agent

import android.app.*
import android.app.admin.DevicePolicyManager
import android.content.*
import android.location.Location
import android.os.*
import android.util.Log
import androidx.core.app.NotificationCompat
import com.google.android.gms.location.*
import org.eclipse.paho.client.mqttv3.*
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence
import org.json.JSONObject
import java.util.Timer
import java.util.TimerTask

class GuardianService : Service() {

    private lateinit var prefs: SharedPreferences
    private val RELAY_IP   get() = prefs.getString("relay_ip", "")!!
    private val MQTT_PORT  get() = prefs.getInt("mqtt_port", 1883)
    private val MQTT_USER  get() = prefs.getString("mqtt_user", "guardian")!!
    private val MQTT_PASS  get() = prefs.getString("mqtt_pass", "")!!
    private val DEVICE_ID  get() = prefs.getString("device_id", "phone-01")!!
    private val DEVICE_NAME get() = prefs.getString("device_name", "My Phone")!!
    private val WG_IP      get() = prefs.getString("wg_ip", "")!!

    private var mqttClient: MqttAsyncClient? = null
    private lateinit var fusedLocationClient: FusedLocationProviderClient
    private lateinit var locationCallback: LocationCallback
    private var lastLocation: Location? = null
    private var heartbeatTimer: Timer? = null

    // Abort state for wipe
    @Volatile private var wipeAbortRequested = false
    private var wipeCancelIntent: PendingIntent? = null

    companion object {
        const val CHANNEL_ID        = "guardian_service"
        const val NOTIF_ID          = 1001
        const val NOTIF_WIPE_ID     = 1002
        const val ACTION_ABORT_WIPE = "com.guardian.agent.ABORT_WIPE"
    }

    override fun onCreate() {
        super.onCreate()
        prefs = getSharedPreferences("guardian", Context.MODE_PRIVATE)
        createNotificationChannel()
        startForeground(NOTIF_ID, buildNotification("Guardian active"))
        setupLocation()
        connectMqtt()
        startHeartbeat()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_ABORT_WIPE) {
            wipeAbortRequested = true
            Log.i("Guardian", "Wipe abort requested via notification")
            getSystemService(NotificationManager::class.java).cancel(NOTIF_WIPE_ID)
            updateNotification("Wipe aborted")
            mqttPublish("guardian/status", JSONObject().apply {
                put("device_id", DEVICE_ID)
                put("event", "wipe_aborted")
            }.toString())
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        super.onDestroy()
        heartbeatTimer?.cancel()
        fusedLocationClient.removeLocationUpdates(locationCallback)
        mqttClient?.disconnect()
        scheduleRestart()
    }

    private fun setupLocation() {
        fusedLocationClient = LocationServices.getFusedLocationProviderClient(this)
        val req = LocationRequest.Builder(Priority.PRIORITY_HIGH_ACCURACY, 30_000L)
            .setMinUpdateIntervalMillis(15_000L).build()
        locationCallback = object : LocationCallback() {
            override fun onLocationResult(result: LocationResult) {
                lastLocation = result.lastLocation
                publishLocation(result.lastLocation!!)
            }
        }
        try {
            fusedLocationClient.requestLocationUpdates(req, locationCallback, mainLooper)
        } catch (e: SecurityException) {
            Log.e("Guardian", "Location permission missing")
        }
    }

    private fun publishLocation(loc: Location) {
        mqttPublish("guardian/location", JSONObject().apply {
            put("device_id", DEVICE_ID); put("lat", loc.latitude); put("lon", loc.longitude)
            put("accuracy", loc.accuracy); put("timestamp", System.currentTimeMillis())
        }.toString())
    }

    private fun connectMqtt() {
        if (RELAY_IP.isEmpty()) {
            Log.w("Guardian", "RELAY_IP not configured -- skipping MQTT connect until setup is complete")
            return
        }
        try {
            mqttClient = MqttAsyncClient("tcp://$RELAY_IP:$MQTT_PORT", DEVICE_ID, MemoryPersistence())
            val opts = MqttConnectOptions().apply {
                userName = MQTT_USER
                password = MQTT_PASS.toCharArray()
                isCleanSession = false
                keepAliveInterval = 60
                isAutomaticReconnect = true
            }
            mqttClient!!.setCallback(object : MqttCallback {
                override fun connectionLost(cause: Throwable?) {
                    Log.w("Guardian", "MQTT connection lost: ${cause?.message}")
                }
                override fun messageArrived(topic: String, message: MqttMessage) {
                    handleCommand(JSONObject(String(message.payload)))
                }
                override fun deliveryComplete(token: IMqttDeliveryToken?) {}
            })
            mqttClient!!.connect(opts, null, object : IMqttActionListener {
                override fun onSuccess(token: IMqttToken?) {
                    mqttClient!!.subscribe("guardian/cmd/$DEVICE_ID", 1)
                    sendHeartbeat()
                }
                override fun onFailure(token: IMqttToken?, e: Throwable?) {
                    Log.e("Guardian", "MQTT connect failed: ${e?.message}")
                }
            })
        } catch (e: Exception) {
            Log.e("Guardian", "MQTT error: $e")
        }
    }

    private fun mqttPublish(topic: String, payload: String) {
        try {
            if (mqttClient?.isConnected == true)
                mqttClient!!.publish(topic, MqttMessage(payload.toByteArray()).apply { qos = 1 })
        } catch (e: Exception) {
            Log.e("Guardian", "Publish error: $e")
        }
    }

    private fun startHeartbeat() {
        heartbeatTimer = Timer()
        heartbeatTimer!!.scheduleAtFixedRate(object : TimerTask() {
            override fun run() { sendHeartbeat() }
        }, 0L, 30_000L)
    }

    private fun sendHeartbeat() {
        val bm = getSystemService(BATTERY_SERVICE) as BatteryManager
        mqttPublish("guardian/heartbeat", JSONObject().apply {
            put("device_id", DEVICE_ID); put("name", DEVICE_NAME); put("type", "android")
            put("wg_ip", WG_IP)
            put("battery", bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY))
            put("timestamp", System.currentTimeMillis())
        }.toString())
    }

    private fun handleCommand(cmd: JSONObject) {
        when (cmd.optString("action")) {
            "locate"     -> lastLocation?.let { publishLocation(it) }
            "lock"       -> lockDevice()
            "backup"     -> doBackup()
            "abort_wipe" -> {
                wipeAbortRequested = true
                getSystemService(NotificationManager::class.java).cancel(NOTIF_WIPE_ID)
                updateNotification("Wipe aborted remotely")
                mqttPublish("guardian/status", JSONObject().apply {
                    put("device_id", DEVICE_ID); put("event", "wipe_aborted")
                }.toString())
            }
            "wipe" -> Thread { doWipeWithAbort() }.start()
        }
    }

    private fun doWipeWithAbort() {
        wipeAbortRequested = false
        val abortIntent = Intent(this, GuardianService::class.java).apply { action = ACTION_ABORT_WIPE }
        wipeCancelIntent = PendingIntent.getService(
            this, 99, abortIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val wipeNotif = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("REMOTE WIPE IN 30s")
            .setContentText("Tap ABORT to cancel. All data will be deleted.")
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .addAction(android.R.drawable.ic_delete, "ABORT WIPE", wipeCancelIntent)
            .setOngoing(true)
            .build()
        getSystemService(NotificationManager::class.java).notify(NOTIF_WIPE_ID, wipeNotif)
        for (i in 6 downTo 1) {
            if (wipeAbortRequested) {
                Log.i("Guardian", "Wipe aborted at ${i * 5}s remaining")
                getSystemService(NotificationManager::class.java).cancel(NOTIF_WIPE_ID)
                updateNotification("Wipe aborted")
                return
            }
            Thread.sleep(5_000L)
        }
        if (wipeAbortRequested) {
            getSystemService(NotificationManager::class.java).cancel(NOTIF_WIPE_ID)
            updateNotification("Wipe aborted")
            return
        }
        Log.i("Guardian", "Wipe countdown complete -- executing")
        getSystemService(NotificationManager::class.java).cancel(NOTIF_WIPE_ID)
        doWipe()
    }

    private fun lockDevice() {
        val dpm = getSystemService(DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val admin = ComponentName(this, GuardianAdminReceiver::class.java)
        if (dpm.isAdminActive(admin)) dpm.lockNow()
    }

    private fun doBackup() {
        mqttPublish("guardian/backup_complete", JSONObject().apply {
            put("device_id", DEVICE_ID)
            put("backup_id", "backup_${System.currentTimeMillis()}")
        }.toString())
    }

    private fun doWipe() {
        val dpm = getSystemService(DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val admin = ComponentName(this, GuardianAdminReceiver::class.java)
        if (dpm.isAdminActive(admin))
            dpm.wipeData(DevicePolicyManager.WIPE_EXTERNAL_STORAGE)
        else
            Log.e("Guardian", "Cannot wipe -- Device Admin not active")
    }

    private fun scheduleRestart() {
        val pi = PendingIntent.getService(
            this, 1, Intent(this, GuardianService::class.java),
            PendingIntent.FLAG_ONE_SHOT or PendingIntent.FLAG_IMMUTABLE
        )
        (getSystemService(ALARM_SERVICE) as AlarmManager)
            .set(AlarmManager.ELAPSED_REALTIME, SystemClock.elapsedRealtime() + 5000, pi)
    }

    private fun createNotificationChannel() {
        val ch = NotificationChannel(CHANNEL_ID, "Guardian", NotificationManager.IMPORTANCE_HIGH)
        getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
    }

    private fun buildNotification(text: String) =
        NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Guardian").setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setPriority(NotificationCompat.PRIORITY_LOW).build()

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java).notify(NOTIF_ID, buildNotification(text))
    }
}
