package uk.co.fenrirsecurity.agent.core

import org.json.JSONArray
import org.json.JSONObject

// Plain Kotlin (no Android imports) so the scoring is unit-tested on the JVM. AppScanner gathers the facts on the phone.

/** What the phone knows about one installed app. */
data class AppFacts(
    val packageName: String,
    val label: String,
    val version: String,
    val installer: String?,
    val systemApp: Boolean,
    val sha256: String?,
    val signer: String?,
    val permissions: Set<String>,
    val accessibilityOn: Boolean,
    val deviceAdmin: Boolean,
    val notificationAccess: Boolean,
    val hasLauncherIcon: Boolean,
    val debuggable: Boolean,
    val firstInstallMillis: Long,
    val lastUpdateMillis: Long,
)

data class Assessment(val score: Int, val level: String, val reasons: List<String>)

/**
 * How risky an app looks from where it came from and what it can do. Banking trojans and stalkerware are sideloaded,
 * take over the screen through accessibility, read text messages (one-time codes), draw over other apps and hide their
 * icon; each of those adds to the score, and the combinations add more. The cloud adds threat intelligence on the APK
 * hash, the signer and the package name.
 */
object AppRisk {
    /** App stores whose installs count as reviewed. Anything else (a browser, a file manager, adb) is sideloading. */
    val TRUSTED_INSTALLERS = setOf(
        "com.android.vending", "com.google.android.feedback",  // Google Play
        "com.sec.android.app.samsungapps",                     // Galaxy Store
        "com.amazon.venezia",                                  // Amazon Appstore
        "com.huawei.appmarket",                                // AppGallery
        "com.xiaomi.market", "com.xiaomi.mipicks",             // Xiaomi GetApps
        "com.heytap.market", "com.oppo.market",                // OPPO, OnePlus
        "com.bbk.appstore", "com.vivo.appstore",               // vivo
    )

    const val READ_SMS = "android.permission.READ_SMS"
    const val RECEIVE_SMS = "android.permission.RECEIVE_SMS"
    const val OVERLAY = "android.permission.SYSTEM_ALERT_WINDOW"
    const val INSTALL_PACKAGES = "android.permission.REQUEST_INSTALL_PACKAGES"
    const val RECORD_AUDIO = "android.permission.RECORD_AUDIO"
    const val READ_CALL_LOG = "android.permission.READ_CALL_LOG"
    const val BACKGROUND_LOCATION = "android.permission.ACCESS_BACKGROUND_LOCATION"
    const val READ_CONTACTS = "android.permission.READ_CONTACTS"
    const val CAMERA = "android.permission.CAMERA"

    /** The permissions worth showing an administrator; the rest are left out of the report. */
    val NOTABLE = setOf(READ_SMS, RECEIVE_SMS, OVERLAY, INSTALL_PACKAGES, RECORD_AUDIO, READ_CALL_LOG, BACKGROUND_LOCATION,
        READ_CONTACTS, CAMERA, "android.permission.SEND_SMS", "android.permission.CALL_PHONE", "android.permission.READ_PHONE_STATE")

    fun sideloaded(app: AppFacts, trusted: Set<String> = TRUSTED_INSTALLERS): Boolean =
        !app.systemApp && (app.installer == null || app.installer !in trusted)

    fun assess(app: AppFacts, trusted: Set<String> = TRUSTED_INSTALLERS): Assessment {
        val reasons = mutableListOf<String>()
        var score = 0
        fun add(points: Int, why: String) { score += points; reasons += why }
        val side = sideloaded(app, trusted)
        val p = app.permissions
        val sms = READ_SMS in p || RECEIVE_SMS in p
        val overlay = OVERLAY in p
        val spying = listOf(RECORD_AUDIO, READ_CALL_LOG, BACKGROUND_LOCATION, READ_CONTACTS, CAMERA).count { it in p }

        if (side) add(20, "Installed from outside an app store" + (app.installer?.let { " (by $it)" } ?: ""))
        if (app.accessibilityOn) add(25, "Can see and control the screen (accessibility service is on)")
        if (sms) add(15, "Can read incoming text messages, including one-time codes")
        if (overlay) add(10, "Can draw over other apps")
        if (app.deviceAdmin) add(15, "Is a device administrator, which makes it hard to remove")
        if (app.notificationAccess) add(10, "Reads every notification")
        if (INSTALL_PACKAGES in p) add(10, "Can install other apps")
        if (side && !app.hasLauncherIcon) add(15, "Has no app icon, so it is hidden from the user")
        if (app.debuggable) add(10, "Is a debug build, not a released app")
        if (side && app.accessibilityOn && (sms || overlay)) {
            add(25, "Matches banking trojans: sideloaded, controls the screen and reads texts or draws over apps")
        }
        if (side && !app.hasLauncherIcon && spying >= 2) {
            add(25, "Matches stalkerware: hidden, sideloaded and can record, track or read call logs")
        }
        val capped = score.coerceAtMost(100)
        val level = when { capped >= 60 -> "high"; capped >= 30 -> "medium"; else -> "low" }
        return Assessment(capped, level, reasons)
    }

    fun toJson(app: AppFacts, assessment: Assessment, trusted: Set<String> = TRUSTED_INSTALLERS): JSONObject = JSONObject()
        .put("package", app.packageName).put("label", app.label.take(200)).put("version", app.version.take(100))
        .put("installer", app.installer ?: JSONObject.NULL).put("sideloaded", sideloaded(app, trusted)).put("system", app.systemApp)
        .put("sha256", app.sha256 ?: JSONObject.NULL).put("signer", app.signer ?: JSONObject.NULL)
        .put("permissions", JSONArray(app.permissions.filter { it in NOTABLE }.sorted()))
        .put("accessibility", app.accessibilityOn).put("deviceAdmin", app.deviceAdmin)
        .put("notificationAccess", app.notificationAccess).put("hidden", !app.hasLauncherIcon)
        .put("firstInstalled", Iso.format(app.firstInstallMillis)).put("updated", Iso.format(app.lastUpdateMillis))
        .put("risk", JSONObject().put("score", assessment.score).put("level", assessment.level).put("reasons", JSONArray(assessment.reasons)))

    /** The telemetry event the cloud reads app verdicts from: every app (full) or the ones just installed or updated. */
    fun event(eventId: String, apps: List<JSONObject>, full: Boolean, nowMillis: Long): JSONObject {
        val high = apps.count { it.optJSONObject("risk")?.optString("level") == "high" }
        val list = JSONArray()
        apps.take(3000).forEach { list.put(it) }
        val payload = JSONObject().put("full", full).put("apps", list)
        val summary = if (full) "${apps.size} apps checked, $high high risk" else "${apps.size} new or updated apps checked, $high high risk"
        return JSONObject().put("eventId", eventId).put("eventType", "mobile.apps.assessed").put("source", "android")
            .put("summary", summary).put("occurredAt", Iso.format(nowMillis)).put("payloadJson", payload.toString())
    }

    fun removedEvent(eventId: String, packageName: String, nowMillis: Long): JSONObject =
        JSONObject().put("eventId", eventId).put("eventType", "mobile.app.removed").put("source", "android")
            .put("summary", "$packageName was removed").put("occurredAt", Iso.format(nowMillis))
            .put("payloadJson", JSONObject().put("package", packageName).toString())

    fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
}
