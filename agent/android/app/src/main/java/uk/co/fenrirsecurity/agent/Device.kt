package uk.co.fenrirsecurity.agent

import android.Manifest
import android.annotation.SuppressLint
import android.app.ActivityManager
import android.app.KeyguardManager
import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.media.AudioAttributes
import android.media.AudioManager
import android.media.MediaPlayer
import android.media.RingtoneManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.BatteryManager
import android.os.Build
import android.os.CancellationSignal
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.os.StatFs
import android.os.SystemClock
import android.provider.Settings
import android.telephony.TelephonyManager
import org.json.JSONArray
import org.json.JSONObject
import uk.co.fenrirsecurity.agent.core.Fix
import uk.co.fenrirsecurity.agent.core.Inventory
import uk.co.fenrirsecurity.agent.core.Iso
import java.io.File
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Device administrator rights: lock and erase. */
class FenrirAdminReceiver : DeviceAdminReceiver() {
    override fun onDisableRequested(context: Context, intent: Intent): CharSequence =
        "If you turn this off, your IT team can no longer lock or erase this phone if it is lost or stolen. They will be told."

    override fun onDisabled(context: Context, intent: Intent) {
        // Tamper signal: the console shows it on the device's timeline and in Needs attention.
        Store(context).queueEvent(Device.event("agent.admin.removed", "Fenrir's device administrator rights were turned off on the phone"))
        AgentService.checkNow(context)
    }

    override fun onEnabled(context: Context, intent: Intent) = AgentService.checkNow(context)
}

object Device {
    private fun component(context: Context) = ComponentName(context, FenrirAdminReceiver::class.java)
    private fun policy(context: Context) = context.service<DevicePolicyManager>()

    fun adminActive(context: Context) = policy(context).isAdminActive(component(context))
    fun isDeviceOwner(context: Context) = policy(context).isDeviceOwnerApp(context.packageName)

    fun adminRequest(context: Context): Intent = Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN)
        .putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, component(context))
        .putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION, context.getString(R.string.admin_description))

    fun lock(context: Context): Boolean {
        if (!adminActive(context)) return false
        policy(context).lockNow()
        return true
    }

    /** The lost message on the lock screen itself; Android only allows this for a device-owner (managed) phone. */
    fun setLockScreenMessage(context: Context, text: String?) {
        if (isDeviceOwner(context)) runCatching { policy(context).setDeviceOwnerLockScreenInfo(component(context), text) }
    }

    /** Returns null when the factory reset was started, or why it could not be. */
    fun wipe(context: Context): String? {
        if (!adminActive(context)) return "Fenrir is not a device administrator on this phone"
        return try {
            policy(context).wipeData(0)
            null
        } catch (error: SecurityException) {
            "Android refused the erase (${error.message}). Android 14+ only lets a managed (device-owner) Fenrir erase a phone."
        }
    }

    fun hostname(context: Context): String =
        Settings.Global.getString(context.contentResolver, Settings.Global.DEVICE_NAME)?.takeIf { it.isNotBlank() }
            ?: "${Build.MANUFACTURER} ${Build.MODEL}".replaceFirstChar { it.uppercase() }

    fun osVersion(): String = "Android ${Build.VERSION.RELEASE} (${Build.MANUFACTURER} ${Build.MODEL})"

    @SuppressLint("HardwareIds")
    fun serial(context: Context): String = Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID) ?: ""

    fun battery(context: Context): Int? =
        context.service<BatteryManager>().getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY).takeIf { it in 0..100 }

    fun event(type: String, summary: String, payload: JSONObject = JSONObject()): JSONObject =
        JSONObject().put("eventId", UUID.randomUUID().toString()).put("eventType", type).put("source", "android")
            .put("summary", summary).put("occurredAt", Iso.format(System.currentTimeMillis())).put("payloadJson", payload.toString())

    /** Heartbeat metrics: what the console's stats strip, Needs attention and At a glance show for a phone. */
    @SuppressLint("MissingPermission")
    fun metrics(context: Context): JSONObject {
        val m = JSONObject()
        val batteryManager = context.service<BatteryManager>()
        battery(context)?.let { m.put("batteryPercent", it) }
        m.put("charging", batteryManager.isCharging)

        val memory = ActivityManager.MemoryInfo().also { context.service<ActivityManager>().getMemoryInfo(it) }
        if (memory.totalMem > 0) {
            m.put("memoryTotalGb", memory.totalMem / 1e9)
            m.put("memoryPercent", 100.0 * (memory.totalMem - memory.availMem) / memory.totalMem)
        }
        val stat = StatFs(Environment.getDataDirectory().path)
        if (stat.totalBytes > 0) {
            m.put("disks", JSONArray().put(JSONObject().put("mount", "Internal").put("totalGb", stat.totalBytes / 1e9)
                .put("freeGb", stat.availableBytes / 1e9).put("freePercent", 100.0 * stat.availableBytes / stat.totalBytes)))
        }
        val up = SystemClock.elapsedRealtime()
        m.put("uptimeSeconds", up / 1000)
        m.put("lastBootAt", Iso.format(System.currentTimeMillis() - up))

        val connectivity = context.service<ConnectivityManager>()
        val caps = connectivity.getNetworkCapabilities(connectivity.activeNetwork)
        val network = when {
            caps == null -> "Offline"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Mobile data"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
            else -> "Other"
        }
        m.put("network", network)
        if (network == "Wi-Fi") {
            @Suppress("DEPRECATION")
            val ssid = context.applicationContext.service<WifiManager>().connectionInfo?.ssid?.trim('"')
            if (!ssid.isNullOrBlank() && ssid != "<unknown ssid>") m.put("wifiSsid", ssid)
        }
        context.getSystemService(TelephonyManager::class.java)?.networkOperatorName?.takeIf { it.isNotBlank() }?.let { m.put("carrier", it) }

        m.put("screenLockSecure", context.service<KeyguardManager>().isDeviceSecure)
        val encryption = policy(context).storageEncryptionStatus
        m.put("encrypted", encryption == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE ||
            encryption == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER ||
            encryption == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY)
        m.put("deviceAdmin", adminActive(context))
        m.put("developerMode", Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1)
        m.put("rooted", listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/system/app/Superuser.apk").any { File(it).exists() })
        m.put("locationEnabled", Locator.enabled(context.service<LocationManager>()))
        Build.VERSION.SECURITY_PATCH?.takeIf { it.isNotBlank() }?.let { m.put("securityPatch", it) }
        m.put("manufacturer", Build.MANUFACTURER.replaceFirstChar { it.uppercase() })
        m.put("model", Build.MODEL)
        return m
    }

    /** Installed apps (user-installed and updated system apps), for the console's Apps tab. */
    fun inventory(context: Context): JSONObject {
        val pm = context.packageManager
        @Suppress("DEPRECATION")
        val packages = pm.getInstalledPackages(0)
        val apps = packages.mapNotNull { info ->
            val app = info.applicationInfo ?: return@mapNotNull null
            val system = app.flags and ApplicationInfo.FLAG_SYSTEM != 0
            val updated = app.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
            if (system && !updated) return@mapNotNull null
            Inventory.App(pm.getApplicationLabel(app).toString(), info.versionName ?: "", info.packageName)
        }
        return Inventory.event(UUID.randomUUID().toString(), apps, "Android", Build.VERSION.RELEASE,
            Build.MANUFACTURER.replaceFirstChar { it.uppercase() }, Build.MODEL, System.currentTimeMillis())
    }
}

/** One-shot location fixes from every enabled provider; the most accurate within the time limit wins. */
object Locator {
    fun hasPermission(context: Context) =
        context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED ||
            context.checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED

    fun hasBackgroundPermission(context: Context) =
        context.checkSelfPermission(Manifest.permission.ACCESS_BACKGROUND_LOCATION) == PackageManager.PERMISSION_GRANTED

    fun enabled(manager: LocationManager): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) manager.isLocationEnabled
        else manager.isProviderEnabled(LocationManager.GPS_PROVIDER) || manager.isProviderEnabled(LocationManager.NETWORK_PROVIDER)

    /** Blocking: call from a background thread. */
    @SuppressLint("MissingPermission")
    fun current(context: Context, reason: String, timeoutMs: Long = 30_000): Fix? {
        if (!hasPermission(context)) return null
        val manager = context.service<LocationManager>()
        if (!enabled(manager)) return null
        val providers = buildList {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && manager.hasProvider(LocationManager.FUSED_PROVIDER)) add(LocationManager.FUSED_PROVIDER)
            if (manager.isProviderEnabled(LocationManager.GPS_PROVIDER)) add(LocationManager.GPS_PROVIDER)
            if (manager.isProviderEnabled(LocationManager.NETWORK_PROVIDER)) add(LocationManager.NETWORK_PROVIDER)
        }
        val results = java.util.Collections.synchronizedList(mutableListOf<Location>())
        val done = CountDownLatch(providers.size)
        val cancel = CancellationSignal()
        val executor = Executors.newSingleThreadExecutor()
        val listeners = mutableListOf<LocationListener>()
        val main = Handler(Looper.getMainLooper())
        for (provider in providers) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                manager.getCurrentLocation(provider, cancel, executor) { location -> location?.let(results::add); done.countDown() }
            } else {
                val listener = object : LocationListener {
                    override fun onLocationChanged(location: Location) { results.add(location); done.countDown() }
                    @Deprecated("Deprecated in Java") override fun onStatusChanged(provider: String?, status: Int, extras: android.os.Bundle?) {}
                    override fun onProviderEnabled(provider: String) {}
                    override fun onProviderDisabled(provider: String) { done.countDown() }
                }
                listeners += listener
                @Suppress("DEPRECATION")
                main.post { runCatching { manager.requestSingleUpdate(provider, listener, Looper.getMainLooper()) }.onFailure { done.countDown() } }
            }
        }
        done.await(timeoutMs, TimeUnit.MILLISECONDS)
        cancel.cancel()
        listeners.forEach { listener -> main.post { manager.removeUpdates(listener) } }
        executor.shutdown()
        var best = results.filter { it.hasAccuracy() }.minByOrNull { it.accuracy } ?: results.firstOrNull()
        if (best == null) {
            // Nothing fresh: the newest last-known fix from the last 10 minutes is better than nothing.
            best = providers.mapNotNull { runCatching { manager.getLastKnownLocation(it) }.getOrNull() }
                .filter { System.currentTimeMillis() - it.time < 10 * 60_000 }.maxByOrNull { it.time }
        }
        return best?.let { toFix(it, reason, Device.battery(context)) }
    }

    private fun toFix(location: Location, reason: String, battery: Int?) = Fix(
        lat = location.latitude, lon = location.longitude,
        accuracy = if (location.hasAccuracy()) location.accuracy else null,
        altitude = if (location.hasAltitude()) location.altitude else null,
        speed = if (location.hasSpeed()) location.speed else null,
        source = when (location.provider) { LocationManager.GPS_PROVIDER -> "gps"; LocationManager.NETWORK_PROVIDER -> "network"; "fused" -> "fused"; else -> "passive" },
        reason = reason, battery = battery, atMillis = location.time.takeIf { it > 0 } ?: System.currentTimeMillis(),
    )
}

/** The find-my-phone alarm: the alarm tone at full alarm volume (which plays in silent mode), then volume restored. */
class AlarmPlayer(private val context: Context) {
    private val main = Handler(Looper.getMainLooper())
    private var player: MediaPlayer? = null
    private var savedVolume = -1
    private val stopper = Runnable { stopNow() }

    fun play(seconds: Int) = main.post {
        stopNow()
        val audio = context.service<AudioManager>()
        runCatching {
            savedVolume = audio.getStreamVolume(AudioManager.STREAM_ALARM)
            audio.setStreamVolume(AudioManager.STREAM_ALARM, audio.getStreamMaxVolume(AudioManager.STREAM_ALARM), 0)
        }
        val tone = RingtoneManager.getActualDefaultRingtoneUri(context, RingtoneManager.TYPE_ALARM)
            ?: RingtoneManager.getDefaultUri(RingtoneManager.TYPE_RINGTONE)
        player = runCatching {
            MediaPlayer().apply {
                setAudioAttributes(AudioAttributes.Builder().setUsage(AudioAttributes.USAGE_ALARM).setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION).build())
                setDataSource(context, tone)
                isLooping = true
                prepare()
                start()
            }
        }.getOrNull()
        Notifications.alarm(context)
        main.postDelayed(stopper, seconds * 1000L)
    }

    fun stop() = main.post { stopNow() }

    private fun stopNow() {
        main.removeCallbacks(stopper)
        player?.let { runCatching { it.stop() }; it.release() }
        player = null
        if (savedVolume >= 0) {
            runCatching { context.service<AudioManager>().setStreamVolume(AudioManager.STREAM_ALARM, savedVolume, 0) }
            savedVolume = -1
        }
        Notifications.cancel(context, Notifications.ID_ALARM)
    }
}
