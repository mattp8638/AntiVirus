package uk.co.fenrirsecurity.agent

import android.annotation.SuppressLint
import android.content.Context
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.os.Build
import android.os.Looper
import uk.co.fenrirsecurity.agent.core.Fix
import uk.co.fenrirsecurity.agent.core.Pace
import uk.co.fenrirsecurity.agent.core.Tracking

/**
 * Continuous location for the "close" care level and during an SOS: Android delivers a fix about every minute while
 * the phone is moving, near a safe-zone edge or in an SOS, and every 5 minutes once it has been still for 10 minutes.
 * The agent's foreground service (type location) keeps this running while the screen is off.
 */
class Tracker(private val context: Context, private val store: Store, private val onFix: (Fix) -> Unit) {
    private val manager = context.service<LocationManager>()
    private var current: Tracking? = null
    private var minTime = 0L
    private var last: Location? = null
    private var lastMovedAt = 0L

    private val listener = object : LocationListener {
        override fun onLocationChanged(location: Location) = received(location)
        @Deprecated("Deprecated in Java") override fun onStatusChanged(provider: String?, status: Int, extras: android.os.Bundle?) {}
        override fun onProviderEnabled(provider: String) {}
        override fun onProviderDisabled(provider: String) {}
    }

    @Synchronized
    fun apply(tracking: Tracking) {
        current = tracking
        if (!tracking.continuous) { stop(); return }
        listen(Pace.minTimeMs(tracking, moving(), nearEdge()))
    }

    @Synchronized
    fun stop() {
        if (minTime != 0L) runCatching { manager.removeUpdates(listener) }
        minTime = 0L
    }

    private fun moving() = System.currentTimeMillis() - lastMovedAt < Pace.STILL_AFTER_MS
    private fun nearEdge() = last?.let { Pace.nearEdge(it.latitude, it.longitude, store.zones) } ?: false

    @SuppressLint("MissingPermission")
    private fun listen(wanted: Long) {
        if (wanted == minTime || !Locator.hasPermission(context)) return
        stop()
        val providers = buildList {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && manager.hasProvider(LocationManager.FUSED_PROVIDER)) add(LocationManager.FUSED_PROVIDER)
            else {
                if (manager.isProviderEnabled(LocationManager.GPS_PROVIDER)) add(LocationManager.GPS_PROVIDER)
                if (manager.isProviderEnabled(LocationManager.NETWORK_PROVIDER)) add(LocationManager.NETWORK_PROVIDER)
            }
        }
        for (provider in providers) {
            runCatching { manager.requestLocationUpdates(provider, wanted, 0f, listener, Looper.getMainLooper()) }
        }
        minTime = if (providers.isEmpty()) 0L else wanted
    }

    @Synchronized
    private fun received(location: Location) {
        val previous = last
        if (previous != null && previous.time >= location.time) return
        val moved = previous == null || location.distanceTo(previous) >= Pace.MOVED_METRES || (location.hasSpeed() && location.speed >= 1f)
        if (moved) lastMovedAt = System.currentTimeMillis()
        // With two providers (older phones) keep at most one fix a minute, the more accurate one winning ties.
        if (previous != null && location.time - previous.time < 50_000 && (!location.hasAccuracy() || location.accuracy >= previous.accuracy)) return
        last = location
        onFix(Locator.toFix(location, if (current?.sos == true) "sos" else "tracking", Device.battery(context)))
        current?.let { listen(Pace.minTimeMs(it, moving(), nearEdge())) }  // speed up or slow down as needed
    }
}
