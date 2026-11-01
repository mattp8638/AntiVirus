package uk.co.fenrirsecurity.agent

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import uk.co.fenrirsecurity.agent.core.Fix
import uk.co.fenrirsecurity.agent.core.LostMode
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
    /** Set when the cloud rejects the key (the device was decommissioned): the agent stops until re-enrolled. */
    var removed: Boolean
        get() = prefs.getBoolean("removed", false)
        set(value) = prefs.edit().putBoolean("removed", value).apply()
    var lostMode: LostMode
        get() = LostMode.from(prefs.getString("lostMode", null)?.let { runCatching { JSONObject(it) }.getOrNull() }) ?: LostMode.OFF
        set(value) = prefs.edit().putString("lostMode", value.toJson().toString()).apply()

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
