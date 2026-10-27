package uk.co.fenrirsecurity.agent.core

import org.json.JSONArray
import org.json.JSONObject
import java.net.URI
import java.net.URLDecoder
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

// Plain Kotlin (no Android imports) so it is unit-tested on the JVM: enrolment links, the command format the
// cloud sends, and the JSON the agent posts back. It mirrors agent/linux/pkg/fleet/client.go.

/** Where to enrol: the console's QR code (https://server/enroll-phone#t=TOKEN) or fenrir://enroll?server=&token=. */
data class EnrollTarget(val server: String, val token: String)

object EnrollLink {
    fun parse(text: String): EnrollTarget? {
        val raw = text.trim()
        if (raw.isEmpty()) return null
        val uri = try { URI(raw) } catch (_: Exception) { return null }
        return when (uri.scheme?.lowercase()) {
            "fenrir" -> {
                val query = params(uri.rawQuery)
                val server = query["server"]?.let(::normaliseServer) ?: return null
                val token = query["token"]?.takeIf { it.isNotBlank() } ?: return null
                EnrollTarget(server, token)
            }
            "https", "http" -> {
                if (uri.path?.trimEnd('/') != "/enroll-phone") return null
                val token = params(uri.rawFragment)["t"]?.takeIf { it.isNotBlank() } ?: return null
                val port = if (uri.port == -1) "" else ":${uri.port}"
                EnrollTarget("${uri.scheme.lowercase()}://${uri.host}$port", token)
            }
            else -> null
        }
    }

    /** "fenrir.example.com" -> "https://fenrir.example.com"; drops a trailing slash or /api/v1. */
    fun normaliseServer(value: String): String? {
        var server = value.trim().trimEnd('/')
        if (server.isEmpty()) return null
        if (!server.startsWith("https://") && !server.startsWith("http://")) server = "https://$server"
        server = server.removeSuffix("/api/v1").trimEnd('/')
        val uri = try { URI(server) } catch (_: Exception) { return null }
        return if (uri.host.isNullOrBlank()) null else server
    }

    private fun params(raw: String?): Map<String, String> {
        if (raw.isNullOrEmpty()) return emptyMap()
        return raw.split('&').mapNotNull { part ->
            val index = part.indexOf('=')
            if (index <= 0) null
            else URLDecoder.decode(part.substring(0, index), "UTF-8") to URLDecoder.decode(part.substring(index + 1), "UTF-8")
        }.toMap()
    }
}

/** A remote action from GET /commands/pending. The payload arrives as a JSON string. */
data class Command(val id: String, val type: String, val issuedBy: String, val targetPath: String, val payload: JSONObject) {
    fun int(name: String, default: Int, min: Int, max: Int): Int = payload.optInt(name, default).coerceIn(min, max)
    fun text(name: String, max: Int = 500): String = payload.optString(name, "").trim().take(max)

    companion object {
        fun listFrom(body: JSONObject): List<Command> {
            val items = body.optJSONArray("items") ?: return emptyList()
            return (0 until items.length()).mapNotNull { index ->
                val item = items.optJSONObject(index) ?: return@mapNotNull null
                val id = item.optString("id").takeIf { it.isNotBlank() } ?: return@mapNotNull null
                val payload = item.optString("payloadJson").takeIf { it.isNotBlank() }
                    ?.let { try { JSONObject(it) } catch (_: Exception) { JSONObject() } } ?: JSONObject()
                Command(id, item.optString("type"), item.optString("issuedBy"), item.optString("targetPath"), payload)
            }
        }
    }
}

/** Lost mode as the cloud wants it; echoed in every heartbeat reply so a missed command can't leave it wrong. */
data class LostMode(val enabled: Boolean, val message: String, val phone: String) {
    fun toJson(): JSONObject = JSONObject().put("enabled", enabled).put("message", message).put("phone", phone)

    companion object {
        val OFF = LostMode(false, "", "")
        fun from(json: JSONObject?): LostMode? = json?.let {
            LostMode(it.optBoolean("enabled", false), it.optString("message", "").take(300), it.optString("phone", "").take(40))
        }
    }
}

data class HeartbeatReply(val commandsPending: Int, val approved: Boolean, val lostMode: LostMode?)

/** One location fix, as posted to /location. */
data class Fix(
    val lat: Double, val lon: Double, val accuracy: Float?, val altitude: Double?, val speed: Float?,
    val source: String, val reason: String, val battery: Int?, val atMillis: Long,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("lat", lat); put("lon", lon); put("source", source); put("reason", reason); put("at", Iso.format(atMillis))
        accuracy?.let { put("accuracy", it.toDouble()) }
        altitude?.let { put("altitude", it) }
        speed?.let { put("speed", it.toDouble()) }
        battery?.let { put("battery", it) }
    }
}

object Iso {
    fun format(millis: Long): String = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US)
        .apply { timeZone = TimeZone.getTimeZone("UTC") }.format(Date(millis))
}

/** Builds the telemetry event the cloud reads installed apps and OS details from (inventory.snapshot). */
object Inventory {
    data class App(val name: String, val version: String, val vendor: String)

    fun event(eventId: String, apps: List<App>, osName: String, osVersion: String, manufacturer: String, model: String, nowMillis: Long): JSONObject {
        val software = JSONArray()
        apps.sortedBy { it.name.lowercase() }.take(5000).forEach {
            software.put(JSONObject().put("name", it.name.take(300)).put("version", it.version.take(100)).put("vendor", it.vendor.take(200)))
        }
        val payload = JSONObject().put("software", software).put("osName", osName).put("osVersion", osVersion)
            .put("manufacturer", manufacturer).put("model", model)
        return JSONObject().put("eventId", eventId).put("eventType", "inventory.snapshot").put("source", "android")
            .put("summary", "${apps.size} apps installed").put("occurredAt", Iso.format(nowMillis)).put("payloadJson", payload.toString())
    }
}
