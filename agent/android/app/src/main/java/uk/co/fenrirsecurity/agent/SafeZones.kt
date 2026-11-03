package uk.co.fenrirsecurity.agent

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.location.LocationManager
import android.util.Log

/**
 * Safe zones (geofences) set in the console. Android's own proximity alerts (no Google Play services needed) wake the
 * agent when the phone crosses a zone's edge; the agent then takes a fix and reports it with reason "geofence", and
 * the server decides whether that is a crossing worth an alert. The 5-minute location reports while a phone has zones
 * are the fallback when Android delays or skips a proximity alert.
 */
object SafeZones {
    private const val TAG = "FenrirZones"
    private const val EXTRA_ZONE = "zone"
    private const val EXTRA_NAME = "name"
    private const val EXTRA_NOTIFY = "notify"

    private fun code(id: String) = 7000 + (id.hashCode() and 0x3ffff)

    private fun intent(context: Context, id: String, name: String = "", notify: Boolean = false, create: Boolean = true): PendingIntent? {
        val intent = Intent(context, SafeZoneReceiver::class.java).putExtra(EXTRA_ZONE, id).putExtra(EXTRA_NAME, name).putExtra(EXTRA_NOTIFY, notify)
        // Mutable: Android adds KEY_PROXIMITY_ENTERING to the intent when it fires.
        val flags = PendingIntent.FLAG_MUTABLE or (if (create) PendingIntent.FLAG_UPDATE_CURRENT else PendingIntent.FLAG_NO_CREATE)
        return PendingIntent.getBroadcast(context, code(id), intent, flags)
    }

    /** Replace the registered proximity alerts with the stored zones. */
    @SuppressLint("MissingPermission")
    fun register(context: Context, store: Store) {
        val manager = context.service<LocationManager>()
        for (old in store.zoneCodes) {
            intent(context, old, create = false)?.let { runCatching { manager.removeProximityAlert(it) }; it.cancel() }
        }
        val zones = store.zones
        val registered = mutableSetOf<String>()
        if (Locator.hasPermission(context)) {
            for (zone in zones) {
                val pending = intent(context, zone.id, zone.name, zone.notifyPhone) ?: continue
                try {
                    manager.addProximityAlert(zone.lat, zone.lon, zone.radius, -1, pending)
                    registered += zone.id
                } catch (error: Exception) {  // SecurityException without precise location, or no provider
                    Log.w(TAG, "could not watch ${zone.name}: ${error.message}")
                }
            }
        }
        store.zoneCodes = registered
    }

    internal fun crossed(context: Context, intent: Intent) {
        val entering = intent.getBooleanExtra(LocationManager.KEY_PROXIMITY_ENTERING, false)
        val name = intent.getStringExtra(EXTRA_NAME).orEmpty().ifBlank { "a safe zone" }
        if (intent.getBooleanExtra(EXTRA_NOTIFY, false)) {
            // Told openly on the phone too, when the console asks for it (people should know they are being looked after).
            Notifications.message(context, if (entering) "Arrived at $name" else "Left $name",
                "Your organisation has been told, so someone who looks after you knows where you are.")
        }
        AgentService.start(context, "geofence")
    }
}

class SafeZoneReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) = SafeZones.crossed(context, intent)
}
