package uk.co.fenrirsecurity.agent.core

import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI

/** An HTTP error from the cloud (401 = the device was decommissioned or its key revoked). */
class ApiException(val status: Int, val body: String) : IOException("HTTP $status: ${body.take(200)}")

data class Enrolment(val deviceId: String, val tenantId: String, val apiKey: String, val approved: Boolean)

/**
 * The agent API (the same endpoints as the Windows, Linux and macOS agents). Uses HttpURLConnection so it has no
 * dependencies; TLS uses the phone's trusted CAs. Blocking: call it from a background thread.
 */
class ControlPlane(baseUrl: String, var deviceId: String = "", var apiKey: String = "", private val timeoutMs: Int = 20_000) {
    val base: String = baseUrl.trimEnd('/')

    fun enroll(token: String, hostname: String, osVersion: String, serial: String, agentVersion: String): Enrolment {
        val body = JSONObject().put("hostname", hostname).put("osVersion", osVersion).put("serialNumber", serial)
            .put("platform", "android").put("agentVersion", agentVersion).put("enrollmentToken", token)
        val reply = request("POST", "/api/v1/enroll", body, mapOf("X-Fenrir-Token" to token))
        val enrolment = Enrolment(reply.getString("deviceId"), reply.optString("tenantId"), reply.getString("deviceApiKey"), reply.optBoolean("approved", true))
        deviceId = enrolment.deviceId
        apiKey = enrolment.apiKey
        return enrolment
    }

    fun heartbeat(agentVersion: String, metrics: JSONObject): HeartbeatReply {
        val body = JSONObject().put("agentVersion", agentVersion).put("platformVersion", agentVersion)
            .put("healthState", "healthy").put("isolated", false).put("metrics", metrics)
        val reply = request("POST", "/api/v1/devices/$deviceId/heartbeat", body)
        return HeartbeatReply(reply.optInt("commandsPending", 0), reply.optBoolean("approved", true), LostMode.from(reply.optJSONObject("lostMode")))
    }

    fun pendingCommands(limit: Int = 20): List<Command> =
        Command.listFrom(request("GET", "/api/v1/devices/$deviceId/commands/pending?limit=$limit", null))

    fun complete(commandId: String, ok: Boolean, result: JSONObject) {
        val body = JSONObject().put("status", if (ok) "completed" else "failed").put("resultJson", result.toString())
        request("POST", "/api/v1/devices/$deviceId/commands/$commandId/complete", body)
    }

    fun reportLocations(fixes: List<Fix>): Int {
        if (fixes.isEmpty()) return 0
        val points = JSONArray()
        fixes.takeLast(200).forEach { points.put(it.toJson()) }
        return request("POST", "/api/v1/devices/$deviceId/location", JSONObject().put("points", points)).optInt("stored", 0)
    }

    fun telemetry(events: List<JSONObject>) {
        if (events.isEmpty()) return
        val array = JSONArray()
        events.forEach { array.put(it) }
        request("POST", "/api/v1/devices/$deviceId/telemetry", JSONObject().put("events", array))
    }

    fun request(method: String, path: String, body: JSONObject?, headers: Map<String, String> = emptyMap()): JSONObject {
        val connection = URI(base + path).toURL().openConnection() as HttpURLConnection
        try {
            connection.requestMethod = method
            connection.connectTimeout = timeoutMs
            connection.readTimeout = timeoutMs
            connection.instanceFollowRedirects = false
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("User-Agent", "FenrirAndroid")
            if (apiKey.isNotEmpty()) connection.setRequestProperty("X-Device-Api-Key", apiKey)
            headers.forEach { (key, value) -> connection.setRequestProperty(key, value) }
            if (body != null) {
                val bytes = body.toString().toByteArray(Charsets.UTF_8)
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json")
                connection.setFixedLengthStreamingMode(bytes.size)
                connection.outputStream.use { it.write(bytes) }
            }
            val status = connection.responseCode
            val stream = if (status >= 400) connection.errorStream else connection.inputStream
            val text = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() } ?: ""
            if (status !in 200..299) throw ApiException(status, text)
            return if (text.isBlank()) JSONObject() else JSONObject(text)
        } finally {
            connection.disconnect()
        }
    }
}
