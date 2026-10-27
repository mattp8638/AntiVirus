package uk.co.fenrirsecurity.agent

import android.app.AlarmManager
import android.app.Application
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.os.SystemClock
import android.util.Log
import org.json.JSONObject
import uk.co.fenrirsecurity.agent.core.ApiException
import uk.co.fenrirsecurity.agent.core.Command
import uk.co.fenrirsecurity.agent.core.ControlPlane
import uk.co.fenrirsecurity.agent.core.LostMode
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class FenrirApp : Application() {
    override fun onCreate() {
        super.onCreate()
        Notifications.createChannels(this)
        if (Store(this).enrolled) AgentService.start(this)
    }
}

/** Starts the agent after a reboot or an app update. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (!Store(context).enrolled) return
        AgentService.start(context, if (intent.action == Intent.ACTION_BOOT_COMPLETED) "boot" else "periodic")
    }
}

/** Android suspends timers while the phone sleeps; this alarm wakes the agent every ~10 minutes even in Doze. */
class WakeReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        AgentService.scheduleWake(context)
        AgentService.checkNow(context)
    }
}

/**
 * The agent: a foreground service (Android's requirement for running continuously) that checks in every minute,
 * runs the console's actions, reports location every 15 minutes (every 5 in lost mode) and the app list every 6 hours.
 */
class AgentService : Service() {
    companion object {
        const val ACTION_CHECK_NOW = "uk.co.fenrirsecurity.agent.CHECK_NOW"
        const val ACTION_STOP_ALARM = "uk.co.fenrirsecurity.agent.STOP_ALARM"
        private const val EXTRA_REASON = "reason"
        private const val TAG = "FenrirAgent"

        /** True while the service runs; an already-running foreground service is woken with a plain startService. */
        @Volatile var running = false

        fun start(context: Context, reason: String = "periodic") {
            val intent = Intent(context, AgentService::class.java).setAction(ACTION_CHECK_NOW).putExtra(EXTRA_REASON, reason)
            try {
                if (running) context.startService(intent) else context.startForegroundService(intent)
            } catch (error: Exception) {
                // Android 12+ refuses to start foreground services from the background in some cases; the wake alarm retries.
                Log.w(TAG, "could not start the agent now: ${error.message}")
            }
            scheduleWake(context)
        }

        fun checkNow(context: Context) = start(context)

        fun scheduleWake(context: Context) {
            val alarms = context.service<AlarmManager>()
            val wake = PendingIntent.getBroadcast(context, 0, Intent(context, WakeReceiver::class.java),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            alarms.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, SystemClock.elapsedRealtime() + 10 * 60_000L, wake)
        }
    }

    private lateinit var store: Store
    private val worker = Executors.newSingleThreadScheduledExecutor()
    private lateinit var alarm: AlarmPlayer
    private var bootReason: String? = null
    private val screenOn = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            // A lost phone shows its lost-mode screen every time someone wakes it.
            val lost = store.lostMode
            if (lost.enabled) Notifications.lost(this@AgentService, lost.message)
        }
    }

    override fun onCreate() {
        super.onCreate()
        store = Store(this)
        alarm = AlarmPlayer(this)
        goForeground()
        running = true
        registerReceiver(screenOn, IntentFilter(Intent.ACTION_SCREEN_ON))
        worker.scheduleWithFixedDelay({ cycle(force = false) }, 3, 30, TimeUnit.SECONDS)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        goForeground()  // every startForegroundService must be answered with startForeground
        when (intent?.action) {
            ACTION_STOP_ALARM -> alarm.stop()
            ACTION_CHECK_NOW -> {
                if (intent.getStringExtra(EXTRA_REASON) == "boot") bootReason = "boot"
                worker.execute { cycle(force = true) }
            }
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        running = false
        runCatching { unregisterReceiver(screenOn) }
        alarm.stop()
        worker.shutdownNow()
        super.onDestroy()
    }

    private fun goForeground() {
        val notification = Notifications.status(this, statusText())
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            // Location type only when Android will allow it (background location granted), else it refuses to start.
            val withLocation = Locator.hasPermission(this) && Locator.hasBackgroundPermission(this)
            val type = ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE or (if (withLocation) ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION else 0)
            try {
                startForeground(Notifications.ID_STATUS, notification, type)
            } catch (_: SecurityException) {
                startForeground(Notifications.ID_STATUS, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            }
        } else {
            startForeground(Notifications.ID_STATUS, notification)
        }
    }

    private fun statusText(): String = when {
        store.lostMode.enabled -> "Lost mode is on: reporting location every 5 minutes"
        !Device.adminActive(this) -> "Open Fenrir to finish setup (device admin is off)"
        !Locator.hasPermission(this) -> "Open Fenrir to allow location"
        else -> "Connected to your IT team"
    }

    private fun api() = ControlPlane(store.server, store.deviceId, store.apiKey)

    @Synchronized
    private fun cycle(force: Boolean) {
        if (!store.enrolled) { stopSelf(); return }
        val wake = service<PowerManager>().newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "fenrir:cycle")
        wake.acquire(2 * 60_000L)
        try {
            val now = System.currentTimeMillis()
            val lost = store.lostMode.enabled
            if (force || now - store.lastHeartbeat >= (if (lost) 30_000L else 60_000L)) heartbeat()
            val reason = bootReason ?: if (store.lostMode.enabled) "lostmode" else "periodic"
            if (bootReason != null || now - store.lastLocation >= (if (store.lostMode.enabled) 5 else 15) * 60_000L) {
                locate(reason)
                bootReason = null
            }
            if (now - store.lastInventory >= 6 * 3600_000L) sendInventory()
            flush()
            store.lastError = ""
        } catch (error: ApiException) {
            if (error.status == 401) {
                // The device was decommissioned in the console, or its key was revoked.
                store.removed = true
                Notifications.updateStatus(this, "Removed from management by your IT team")
                stopSelf()
            } else store.lastError = error.message ?: "HTTP ${error.status}"
        } catch (error: Exception) {
            store.lastError = error.message ?: error.javaClass.simpleName
        } finally {
            if (wake.isHeld) wake.release()
        }
    }

    private fun heartbeat() {
        val reply = api().heartbeat(BuildConfig.VERSION_NAME, Device.metrics(this))
        store.lastHeartbeat = System.currentTimeMillis()
        store.lastContact = store.lastHeartbeat
        reply.lostMode?.let { if (it != store.lostMode) applyLostMode(it) }
        Notifications.updateStatus(this, statusText())
        if (reply.commandsPending > 0) runCommands()
    }

    private fun runCommands() {
        val api = api()
        for (command in api.pendingCommands()) {
            val outcome = try { execute(command) } catch (error: Exception) { Outcome(false, JSONObject().put("error", error.message ?: "failed")) }
            api.complete(command.id, outcome.ok, outcome.result)
            outcome.after?.invoke()
        }
    }

    private class Outcome(val ok: Boolean, val result: JSONObject, val after: (() -> Unit)? = null)

    private fun fail(why: String) = Outcome(false, JSONObject().put("error", why))

    private fun execute(command: Command): Outcome = when (command.type) {
        "device.locate" -> {
            val fix = Locator.current(this, "locate")
            if (fix == null) fail(if (!Locator.hasPermission(this)) "Location permission is not granted" else "No location fix (location may be off)")
            else { store.queueFix(fix); store.lastLocation = System.currentTimeMillis(); flush()
                Outcome(true, JSONObject().put("lat", fix.lat).put("lon", fix.lon).put("accuracy", fix.accuracy?.toDouble())) }
        }
        "device.lock" -> if (Device.lock(this)) Outcome(true, JSONObject().put("locked", true)) else fail("Fenrir is not a device administrator on this phone")
        "device.alarm" -> {
            val seconds = command.int("seconds", 60, 5, 300)
            alarm.play(seconds)
            Outcome(true, JSONObject().put("seconds", seconds))
        }
        "device.message" -> {
            val text = command.text("message").ifBlank { command.targetPath }
            if (text.isBlank()) fail("No message text") else { Notifications.message(this, command.text("title", 80), text); Outcome(true, JSONObject()) }
        }
        "device.lostmode" -> {
            applyLostMode(LostMode(command.payload.optBoolean("enabled", false), command.text("message", 300), command.text("phone", 40)))
            Outcome(true, JSONObject().put("enabled", store.lostMode.enabled))
        }
        "device.wipe" -> if (!Device.adminActive(this)) fail("Fenrir is not a device administrator on this phone")
        else Outcome(true, JSONObject().put("erasing", true)) {
            // Reported first: once the reset starts the phone never reports again.
            Device.wipe(this)?.let { why ->
                store.queueEvent(Device.event("agent.wipe.failed", "The phone refused to erase", JSONObject().put("reason", why)))
                flush()
            }
        }
        "inventory.refresh" -> { sendInventory(); Outcome(true, JSONObject()) }
        "policy.refresh" -> Outcome(true, JSONObject())
        else -> fail("${command.type} is not supported on Android")
    }

    private fun applyLostMode(lost: LostMode) {
        val was = store.lostMode
        store.lostMode = lost
        if (lost.enabled) {
            Device.lock(this)
            Device.setLockScreenMessage(this, listOf(lost.message, lost.phone).filter { it.isNotBlank() }.joinToString("\n"))
            Notifications.lost(this, lost.message)
            if (!was.enabled) worker.execute { runCatching { locate("lostmode"); flush() } }
        } else if (was.enabled) {
            Device.setLockScreenMessage(this, null)
            Notifications.cancel(this, Notifications.ID_LOST)
            sendBroadcast(Intent(LostModeActivity.ACTION_CLOSE).setPackage(packageName))
        }
        Notifications.updateStatus(this, statusText())
    }

    private fun locate(reason: String) {
        store.lastLocation = System.currentTimeMillis()
        Locator.current(this, reason)?.let(store::queueFix)
    }

    private fun sendInventory() {
        store.queueEvent(Device.inventory(this))
        store.lastInventory = System.currentTimeMillis()
    }

    /** Sends queued fixes and events; anything that fails waits for the next cycle. */
    private fun flush() {
        val api = api()
        val fixes = store.pendingFixes()
        if (fixes.isNotEmpty()) {
            val points = org.json.JSONArray()
            fixes.forEach { points.put(it) }
            api.request("POST", "/api/v1/devices/${store.deviceId}/location", JSONObject().put("points", points))
            store.clearFixes(fixes.size)
        }
        val events = store.pendingEvents()
        if (events.isNotEmpty()) {
            api.telemetry(events)
            store.clearEvents(events.size)
        }
    }
}
