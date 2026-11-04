package uk.co.fenrirsecurity.agent.core

import org.json.JSONObject
import kotlin.math.asin
import kotlin.math.cos
import kotlin.math.sin
import kotlin.math.sqrt

/**
 * How often the phone reports where it is, from the heartbeat reply's "tracking":
 * close (every minute while moving, near a safe-zone edge or during an SOS, every 5 minutes when still),
 * standard (5 minutes) or saver (15 minutes).
 */
data class Tracking(val mode: String, val intervalSeconds: Int, val adaptive: Boolean, val sos: Boolean) {
    val continuous get() = mode == "close" || sos

    fun toJson(): JSONObject = JSONObject().put("mode", mode).put("intervalSeconds", intervalSeconds).put("adaptive", adaptive).put("sos", sos)

    companion object {
        val DEFAULT = Tracking("default", 900, adaptive = false, sos = false)

        fun from(json: JSONObject?): Tracking? {
            json ?: return null
            val seconds = json.optInt("intervalSeconds", 900).coerceIn(60, 3600)
            return Tracking(json.optString("mode", "standard").take(20), seconds, json.optBoolean("adaptive", false), json.optBoolean("sos", false))
        }
    }
}

object Pace {
    const val STILL_AFTER_MS = 10 * 60_000L
    const val MOVED_METRES = 50.0
    const val EDGE_METRES = 150.0

    /** Minimum time between location updates for a continuous (close or SOS) watch. */
    fun minTimeMs(tracking: Tracking, moving: Boolean, nearEdge: Boolean): Long =
        if (tracking.sos || !tracking.adaptive || moving || nearEdge) 60_000L else 300_000L

    /** Minutes between one-shot location reports when not watching continuously. */
    fun periodicMinutes(tracking: Tracking, lostMode: Boolean, hasZones: Boolean): Int = when {
        lostMode -> 5
        tracking.continuous -> 5  // the continuous watch reports; this is only the fallback
        tracking.mode == "default" -> if (hasZones) 5 else 15
        else -> (tracking.intervalSeconds / 60).coerceIn(1, 60)
    }

    fun nearEdge(lat: Double, lon: Double, zones: List<Zone>): Boolean =
        zones.any { kotlin.math.abs(distance(lat, lon, it.lat, it.lon) - it.radius) <= maxOf(EDGE_METRES, it.radius * 0.5) }

    /** Great-circle distance in metres. */
    fun distance(lat1: Double, lon1: Double, lat2: Double, lon2: Double): Double {
        val p1 = Math.toRadians(lat1); val p2 = Math.toRadians(lat2)
        val dp = p2 - p1; val dl = Math.toRadians(lon2 - lon1)
        val h = sin(dp / 2) * sin(dp / 2) + cos(p1) * cos(p2) * sin(dl / 2) * sin(dl / 2)
        return 2 * 6_371_000 * asin(sqrt(h))
    }
}
