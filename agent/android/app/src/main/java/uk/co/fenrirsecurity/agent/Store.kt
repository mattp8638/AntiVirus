package uk.co.fenrirsecurity.agent

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import uk.co.fenrirsecurity.agent.core.Fix
import uk.co.fenrirsecurity.agent.core.LostMode
import uk.co.fenrirsecurity.agent.core.Tracking
import uk.co.fenrirsecurity.agent.core.Zone
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The agent's state, in app-private storage (backups are off). The device API key is encrypted with an
 * Android Keystore key that never leaves the phone's secure hardware.
 */
class Store(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences("fenrir-agent", Context.MODE_PRIVATE)

    var server: String
        get() = prefs.getString("server", "") ?: ""
        set(value) = prefs.edit().putString("server", value).apply()
    var deviceId: String
        get() = prefs.getString("deviceId", "") ?: ""
        set(value) = prefs.edit().putString("deviceId", value).apply()
    var apiKey: String
        get() = prefs.getString("apiKey", null)?.let { Secrets.decrypt(it) } ?: ""
        set(value) = prefs.edit().putString("apiKey", Secrets.encrypt(value)).apply()
    /** Saves a rotated key synchronously; it must be on disk before the agent first uses it. */
    fun saveApiKey(value: String): Boolean = prefs.edit().putString("apiKey", Secrets.encrypt(value)).commit()
    /** Set when the cloud rejects the key (the device was decommissioned): the agent stops until re-enrolled. */
    var removed: Boolean
        get() = prefs.getBoolean("removed", false)
        set(value) = prefs.edit().putBoolean("removed", value).apply()
    var lostMode: LostMode
        get() = LostMode.from(prefs.getString("lostMode", null)?.let { runCatching { JSONObject(it) }.getOrNull() }) ?: LostMode.OFF
        set(value) = prefs.edit().putString("lostMode", value.toJson().toString()).apply()

    /** Safe zones from the last heartbeat (re-registered with Android after a restart). */
    var zones: List<Zone>
        get() = Zone.list(prefs.getString("zones", null)?.let { runCatching { JSONArray(it) }.getOrNull() }) ?: emptyList()
        set(value) = prefs.edit().putString("zones", JSONArray().apply { value.forEach { put(it.toJson()) } }.toString()).apply()
    /** How often to report location, from the last heartbeat. */
    var tracking: Tracking
        get() = Tracking.from(prefs.getString("tracking", null)?.let { runCatching { JSONObject(it) }.getOrNull() }) ?: Tracking.DEFAULT
        set(value) = prefs.edit().putString("tracking", value.toJson().toString()).apply()
    /** True from pressing Help until a carer acknowledges or the person says they are OK. */
    var sosActive: Boolean
        get() = prefs.getBoolean("sosActive", false)
        set(value) = prefs.edit().putBoolean("sosActive", value).apply()
    /** The help request reached the server (it is retried until it does). */
    var sosHelpSent: Boolean
        get() = prefs.getBoolean("sosHelpSent", false)
        set(value) = prefs.edit().putBoolean("sosHelpSent", value).apply()
    /** Proximity-alert request codes registered with Android, so old ones are removed when the zones change. */
    var zoneCodes: Set<String>
        get() = prefs.getStringSet("zoneCodes", emptySet()).orEmpty()
        set(value) = prefs.edit().putStringSet("zoneCodes", value).apply()

    var lastHeartbeat: Long by LongPref("lastHeartbeat")
    var lastLocation: Long by LongPref("lastLocation")
    var lastInventory: Long by LongPref("lastInventory")
    var lastAppScan: Long by LongPref("lastAppScan")
    var lastContact: Long by LongPref("lastContact")
    var lastError: String
        get() = prefs.getString("lastError", "") ?: ""
        set(value) = prefs.edit().putString("lastError", value.take(300)).apply()

    /** APK SHA-256 by "package@lastUpdateTime", so only new and updated apps are read again. */
    @Synchronized fun apkHashes(): JSONObject = runCatching { JSONObject(prefs.getString("apkHashes", "{}") ?: "{}") }.getOrDefault(JSONObject())
    @Synchronized fun saveApkHashes(hashes: JSONObject) = prefs.edit().putString("apkHashes", hashes.toString()).apply()

    /** High-risk apps the user has already been warned about ("package@lastUpdateTime"), so each is mentioned once. */
    @Synchronized fun warnedOnce(key: String): Boolean {
        val warned = prefs.getStringSet("warnedApps", emptySet()).orEmpty()
        if (key in warned) return false
        prefs.edit().putStringSet("warnedApps", (warned + key).toList().takeLast(500).toSet()).apply()
        return true
    }

    // Policy ("android" section) and what applying it left behind.
    var policyRevision: String
        get() = prefs.getString("policyRevision", "") ?: ""
        set(value) = prefs.edit().putString("policyRevision", value).apply()
    var policyJson: String
        get() = prefs.getString("policyJson", "{}") ?: "{}"
        set(value) = prefs.edit().putString("policyJson", value).apply()
    var hiddenApps: Set<String>
        get() = prefs.getStringSet("hiddenApps", emptySet()).orEmpty()
        set(value) = prefs.edit().putStringSet("hiddenApps", value).apply()
    var wifiApplied: String
        get() = prefs.getString("wifiApplied", "") ?: ""
        set(value) = prefs.edit().putString("wifiApplied", value).apply()
    /** A work profile whose enrolment failed (server unreachable): kept so the user can retry from the app. */
    var pendingEnrolment: String
        get() = prefs.getString("pendingEnrolment", "") ?: ""
        set(value) = prefs.edit().putString("pendingEnrolment", value).apply()

    /** True the first time for a key: each policy prompt is shown once per policy revision. */
    @Synchronized fun promptedOnce(key: String): Boolean = once("prompted", key)
    /** True once per required app and URL, so a failing install is not retried every minute. */
    @Synchronized fun installAttempted(key: String): Boolean = once("installs", key)

    private fun once(set: String, key: String): Boolean {
        val seen = prefs.getStringSet(set, emptySet()).orEmpty()
        if (key in seen) return false
        prefs.edit().putStringSet(set, (seen + key).toList().takeLast(300).toSet()).apply()
        return true
    }

    val enrolled: Boolean get() = server.isNotEmpty() && deviceId.isNotEmpty() && apiKey.isNotEmpty() && !removed

    fun saveEnrolment(server: String, deviceId: String, apiKey: String) {
        prefs.edit().clear().apply()
        this.server = server
        this.deviceId = deviceId
        this.apiKey = apiKey
    }

    // Fixes and events wait here while the phone is offline (newest 200 / 50 kept).
    @Synchronized fun queueFix(fix: Fix) = append("pendingFixes", fix.toJson(), 200)
    @Synchronized fun pendingFixes(): List<JSONObject> = read("pendingFixes")
    @Synchronized fun clearFixes(count: Int) = drop("pendingFixes", count)
    @Synchronized fun queueEvent(event: JSONObject) = append("pendingEvents", event, 50)
    @Synchronized fun pendingEvents(): List<JSONObject> = read("pendingEvents")
    @Synchronized fun clearEvents(count: Int) = drop("pendingEvents", count)

    private fun read(key: String): List<JSONObject> {
        val array = runCatching { JSONArray(prefs.getString(key, "[]")) }.getOrDefault(JSONArray())
        return (0 until array.length()).mapNotNull { array.optJSONObject(it) }
    }
    private fun append(key: String, item: JSONObject, keep: Int) {
        val items = (read(key) + item).takeLast(keep)
        prefs.edit().putString(key, JSONArray(items).toString()).apply()
    }
    private fun drop(key: String, count: Int) {
        prefs.edit().putString(key, JSONArray(read(key).drop(count)).toString()).apply()
    }

    private inner class LongPref(private val key: String) {
        operator fun getValue(thisRef: Any?, property: kotlin.reflect.KProperty<*>): Long = prefs.getLong(key, 0L)
        operator fun setValue(thisRef: Any?, property: kotlin.reflect.KProperty<*>, value: Long) = prefs.edit().putLong(key, value).apply()
    }
}

/** AES-GCM with a non-exportable Android Keystore key. */
object Secrets {
    private const val ALIAS = "fenrir-device-key"

    private fun key(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (keyStore.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return generator.generateKey()
    }

    fun encrypt(plain: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val sealed = cipher.doFinal(plain.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(cipher.iv, Base64.NO_WRAP) + ":" + Base64.encodeToString(sealed, Base64.NO_WRAP)
    }

    fun decrypt(value: String): String? = try {
        val (iv, sealed) = value.split(":", limit = 2).map { Base64.decode(it, Base64.NO_WRAP) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv))
        String(cipher.doFinal(sealed), Charsets.UTF_8)
    } catch (_: Exception) {
        null
    }
}
