package uk.co.fenrirsecurity.agent

import android.app.Activity
import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.admin.DevicePolicyManager
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.net.Uri
import android.net.wifi.WifiManager
import android.net.wifi.WifiNetworkSuggestion
import android.os.Build
import android.os.Bundle
import android.os.PersistableBundle
import android.os.UserManager
import android.provider.Settings
import org.json.JSONArray
import org.json.JSONObject
import uk.co.fenrirsecurity.agent.core.ControlPlane
import java.io.File
import java.net.HttpURLConnection
import java.net.URI
import java.security.MessageDigest
import java.time.LocalDate
import java.time.temporal.ChronoUnit
import kotlin.concurrent.thread

/**
 * The "android" policy section on the phone.
 *
 * In a work profile (Fenrir is the profile owner) the policy is enforced: passcode rules on the whole phone, and
 * restrictions, apps, permissions and VPN inside the work profile. With device admin only, Android no longer lets an
 * app set these, so each is checked instead: what is not met is reported (the console shows it and raises an alert)
 * and the user is asked once to fix it.
 *
 * compliance() is sent with every heartbeat as metrics.compliance: [{key, label, ok, detail, enforced}].
 */
object PhonePolicy {
    private fun admin(context: Context) = ComponentName(context, FenrirAdminReceiver::class.java)
    private fun dpm(context: Context) = context.service<DevicePolicyManager>()

    fun workProfile(context: Context): Boolean =
        dpm(context).isProfileOwnerApp(context.packageName) && context.service<UserManager>().isManagedProfile

    fun mode(context: Context): String = when {
        dpm(context).isDeviceOwnerApp(context.packageName) -> "device_owner"
        workProfile(context) -> "work_profile"
        else -> "device_admin"
    }

    private fun enforcing(context: Context) = mode(context) != "device_admin"

    /** Fetches the policy when its revision changed, then applies it. Called from the agent's cycle. */
    fun sync(context: Context, store: Store, api: ControlPlane, revision: String, force: Boolean = false) {
        if (!force && revision.isNotEmpty() && revision == store.policyRevision) return
        val (fetched, section) = api.policy(store.policyRevision)
        store.policyRevision = fetched
        store.policyJson = section.toString()
        apply(context, store)
    }

    fun policy(store: Store): JSONObject = runCatching { JSONObject(store.policyJson) }.getOrDefault(JSONObject())

    private fun lines(policy: JSONObject, key: String): List<String> {
        val array = policy.optJSONArray(key) ?: JSONArray()
        return (0 until array.length()).map { array.optString(it).trim() }.filter { it.isNotEmpty() }
    }

    private fun complexity(level: String): Int = when (level) {
        "low" -> DevicePolicyManager.PASSWORD_COMPLEXITY_LOW
        "medium" -> DevicePolicyManager.PASSWORD_COMPLEXITY_MEDIUM
        "high" -> DevicePolicyManager.PASSWORD_COMPLEXITY_HIGH
        else -> DevicePolicyManager.PASSWORD_COMPLEXITY_NONE
    }

    /** Enforces what this phone's management mode allows. Each step is independent: one refusal never stops the rest. */
    fun apply(context: Context, store: Store) {
        val p = policy(store)
        if (!enforcing(context)) {
            prompt(context, store)
            return
        }
        val dpm = dpm(context)
        val admin = admin(context)
        val parent = runCatching { dpm.getParentProfileInstance(admin) }.getOrNull()
        val level = p.optString("passcodeComplexity", "none")
        if (Build.VERSION.SDK_INT >= 31) {
            runCatching { (if (workProfile(context)) parent else dpm)?.setRequiredPasswordComplexity(complexity(level)) }
        } else {
            @Suppress("DEPRECATION")
            runCatching {
                val target = if (workProfile(context)) parent ?: dpm else dpm
                when (level) {
                    "low" -> target.setPasswordQuality(admin, DevicePolicyManager.PASSWORD_QUALITY_SOMETHING)
                    "medium" -> { target.setPasswordQuality(admin, DevicePolicyManager.PASSWORD_QUALITY_NUMERIC_COMPLEX); target.setPasswordMinimumLength(admin, 4) }
                    "high" -> { target.setPasswordQuality(admin, DevicePolicyManager.PASSWORD_QUALITY_ALPHANUMERIC); target.setPasswordMinimumLength(admin, 6) }
                    else -> target.setPasswordQuality(admin, DevicePolicyManager.PASSWORD_QUALITY_UNSPECIFIED)
                }
            }
        }
        val lockMinutes = p.optInt("screenLockMinutes", 0)
        runCatching { (if (workProfile(context)) parent else dpm)?.setMaximumTimeToLock(admin, lockMinutes * 60_000L) }
        runCatching { dpm.setMaximumFailedPasswordsForWipe(admin, p.optInt("wipeAfterFailedAttempts", 0)) }

        runCatching { dpm.setCameraDisabled(admin, p.optBoolean("disableCamera", false)) }
        runCatching { dpm.setScreenCaptureDisabled(admin, p.optBoolean("disableScreenCapture", false)) }
        restrict(context, UserManager.DISALLOW_DEBUGGING_FEATURES, p.optBoolean("blockDeveloperOptions", true))
        restrict(context, UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES, p.optBoolean("blockUnknownSources", true))
        restrict(context, UserManager.DISALLOW_CROSS_PROFILE_COPY_PASTE, p.optBoolean("blockCopyPasteToPersonal", true))
        restrict(context, UserManager.DISALLOW_MODIFY_ACCOUNTS, p.optBoolean("blockAddingAccounts", false))
        restrict(context, UserManager.DISALLOW_BLUETOOTH_SHARING, p.optBoolean("blockBluetoothSharing", false))

        runCatching {
            dpm.setPermissionPolicy(admin, when (p.optString("runtimePermissions", "prompt")) {
                "grant" -> DevicePolicyManager.PERMISSION_POLICY_AUTO_GRANT
                "deny" -> DevicePolicyManager.PERMISSION_POLICY_AUTO_DENY
                else -> DevicePolicyManager.PERMISSION_POLICY_PROMPT
            })
        }

        // Blocked apps are hidden in the work profile; apps no longer blocked come back.
        val blocked = lines(p, "blockedApps").toSet()
        for (name in store.hiddenApps - blocked) runCatching { dpm.setApplicationHidden(admin, name, false) }
        for (name in blocked) runCatching { dpm.setApplicationHidden(admin, name, true) }
        store.hiddenApps = blocked

        val vpn = p.optString("alwaysOnVpnApp").trim()
        runCatching { dpm.setAlwaysOnVpnPackage(admin, vpn.ifEmpty { null }, false) }

        requiredApps(context, store, p, silent = true)
        wifi(context, store, p)
    }

    private fun restrict(context: Context, restriction: String, on: Boolean) {
        runCatching {
            if (on) dpm(context).addUserRestriction(admin(context), restriction) else dpm(context).clearUserRestriction(admin(context), restriction)
        }
    }

    /** Device admin only: asks the user (once per policy revision) to fix what the policy needs. */
    private fun prompt(context: Context, store: Store) {
        val p = policy(store)
        val level = p.optString("passcodeComplexity", "none")
        if (level != "none" && !passcodeMeets(context, level)) {
            val intent = Intent(DevicePolicyManager.ACTION_SET_NEW_PASSWORD).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            if (Build.VERSION.SDK_INT >= 29) intent.putExtra(DevicePolicyManager.EXTRA_PASSWORD_COMPLEXITY, complexity(level))
            notifyOnce(context, store, "passcode", "Set a stronger screen lock", "Your IT team requires a ${level} screen lock on this phone.", intent)
        }
        for (name in lines(p, "blockedApps")) {
            if (installed(context, name)) {
                notifyOnce(context, store, "blocked:$name", "Remove ${label(context, name)}",
                    "Your IT team does not allow this app on phones they manage.", AppScanner.uninstallIntent(name))
            }
        }
        requiredApps(context, store, p, silent = false)
        wifi(context, store, p)
    }

    private fun installed(context: Context, name: String): Boolean =
        runCatching { context.packageManager.getPackageInfo(name, 0); true }.getOrDefault(false)

    private fun label(context: Context, name: String): String = runCatching {
        context.packageManager.getApplicationLabel(context.packageManager.getApplicationInfo(name, 0)).toString()
    }.getOrDefault(name)

    private data class Required(val packageName: String, val url: String, val sha256: String)

    private fun required(p: JSONObject): List<Required> = lines(p, "requiredApps").mapNotNull { line ->
        val parts = line.split('|').map { it.trim() }
        val name = parts[0]
        if (!Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)+$").matches(name)) null
        else Required(name, parts.getOrElse(1) { "" }.takeIf { it.startsWith("https://") } ?: "", parts.getOrElse(2) { "" }.lowercase())
    }

    /** Company APKs install silently in a work profile; store apps (and everything with device admin) are offered. */
    private fun requiredApps(context: Context, store: Store, p: JSONObject, silent: Boolean) {
        for (app in required(p)) {
            if (installed(context, app.packageName)) continue
            if (silent && app.url.isNotEmpty()) {
                if (store.installAttempted(app.packageName + "@" + app.url)) thread { install(context, store, app) }
                continue
            }
            val store_ = Intent(Intent.ACTION_VIEW, Uri.parse("market://details?id=${app.packageName}")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            notifyOnce(context, store, "required:${app.packageName}", "Install a work app", "Your IT team needs ${app.packageName} on this phone. Tap to install it.", store_)
        }
    }

    private fun install(context: Context, store: Store, app: Required) {
        val file = File(context.cacheDir, "required-${app.packageName}.apk")
        try {
            val connection = URI(app.url).toURL().openConnection() as HttpURLConnection
            connection.connectTimeout = 20_000
            connection.readTimeout = 60_000
            val digest = MessageDigest.getInstance("SHA-256")
            connection.inputStream.use { input ->
                file.outputStream().use { output ->
                    val buffer = ByteArray(64 * 1024)
                    var total = 0L
                    while (true) {
                        val read = input.read(buffer)
                        if (read < 0) break
                        total += read
                        if (total > 500L * 1024 * 1024) throw IllegalStateException("the APK is larger than 500 MB")
                        digest.update(buffer, 0, read)
                        output.write(buffer, 0, read)
                    }
                }
            }
            val sha = digest.digest().joinToString("") { "%02x".format(it) }
            if (app.sha256.isNotEmpty() && sha != app.sha256) throw IllegalStateException("the download's SHA-256 does not match the policy")
            val installer = context.packageManager.packageInstaller
            val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply { setAppPackageName(app.packageName) }
            val id = installer.createSession(params)
            installer.openSession(id).use { session ->
                session.openWrite("base.apk", 0, file.length()).use { out -> file.inputStream().use { it.copyTo(out) }; session.fsync(out) }
                val done = PendingIntent.getBroadcast(context, id, Intent(context, InstallResultReceiver::class.java).putExtra("package", app.packageName),
                    PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
                session.commit(done.intentSender)
            }
            store.queueEvent(Device.event("agent.app.install", "Installing required app ${app.packageName}", JSONObject().put("package", app.packageName).put("sha256", sha)))
        } catch (error: Exception) {
            store.queueEvent(Device.event("agent.app.install.failed", "Could not install required app ${app.packageName}",
                JSONObject().put("package", app.packageName).put("reason", error.message ?: error.javaClass.simpleName)))
        } finally {
            file.delete()
        }
    }

    /** Wi-Fi networks are suggested to Android (it asks the user once); the list is replaced when policy changes. */
    private fun wifi(context: Context, store: Store, p: JSONObject) {
        if (Build.VERSION.SDK_INT < 29) return
        val wanted = lines(p, "wifiNetworks")
        val fingerprint = wanted.joinToString("\n").hashCode().toString()
        if (fingerprint == store.wifiApplied) return
        val wifi = context.applicationContext.service<WifiManager>()
        val suggestions = wanted.mapNotNull { line ->
            val parts = line.split('|')
            val ssid = parts[0].trim().takeIf { it.isNotEmpty() } ?: return@mapNotNull null
            val type = parts.getOrElse(1) { "WPA2" }.trim().uppercase()
            val password = parts.drop(2).joinToString("|")
            runCatching {
                WifiNetworkSuggestion.Builder().setSsid(ssid).apply {
                    when (type) {
                        "WPA3" -> setWpa3Passphrase(password)
                        "OPEN" -> Unit
                        else -> setWpa2Passphrase(password)
                    }
                }.build()
            }.getOrNull()
        }
        runCatching { wifi.removeNetworkSuggestions(emptyList()) }  // an empty list removes this app's earlier suggestions
        if (suggestions.isEmpty() || wifi.addNetworkSuggestions(suggestions) == WifiManager.STATUS_NETWORK_SUGGESTIONS_SUCCESS) store.wifiApplied = fingerprint
    }

    private fun notifyOnce(context: Context, store: Store, key: String, title: String, text: String, intent: Intent) {
        if (!store.promptedOnce("${store.policyRevision}:$key")) return
        val pending = PendingIntent.getActivity(context, key.hashCode(), intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val notification = Notification.Builder(context, Notifications.MESSAGES)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setAutoCancel(true)
            .setContentIntent(pending)
            .build()
        context.service<NotificationManager>().notify(5000 + (key.hashCode() and 0xfff), notification)
    }

    // ---------------------------------------------------------------- compliance

    private fun passcodeMeets(context: Context, level: String): Boolean {
        val dpm = dpm(context)
        if (workProfile(context)) {
            val parent = runCatching { dpm.getParentProfileInstance(admin(context)) }.getOrNull()
            return runCatching { parent?.isActivePasswordSufficient ?: false }.getOrDefault(false)
        }
        if (Build.VERSION.SDK_INT >= 29) {
            val have = runCatching { dpm.passwordComplexity }.getOrNull()
            if (have != null) return have >= complexity(level)
        }
        // Older phones only say whether there is a screen lock at all.
        return level == "low" && context.service<android.app.KeyguardManager>().isDeviceSecure
    }

    fun compliance(context: Context, store: Store): JSONArray {
        val p = policy(store)
        val out = JSONArray()
        val enforced = enforcing(context)
        fun check(key: String, label: String, ok: Boolean, detail: String = "", byFenrir: Boolean = enforced) {
            out.put(JSONObject().put("key", key).put("label", label).put("ok", ok).put("detail", if (ok) "" else detail).put("enforced", byFenrir))
        }

        val level = p.optString("passcodeComplexity", "none")
        if (level != "none") check("passcode", "Screen lock ($level)", passcodeMeets(context, level),
            if (context.service<android.app.KeyguardManager>().isDeviceSecure) "the screen lock is weaker than policy requires" else "no screen lock is set")
        if (p.optBoolean("requireEncryption", true)) {
            val status = dpm(context).storageEncryptionStatus
            check("encryption", "Storage encrypted", status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE ||
                status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER || status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY,
                "storage is not encrypted", byFenrir = false)
        }
        if (p.optBoolean("blockDeveloperOptions", true) && !enforced) {
            val dev = Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
            val adb = Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
            check("developer", "No developer options", !dev && !adb, if (adb) "USB debugging is on" else "developer options are on")
        }
        val patchDays = p.optInt("minSecurityPatchDays", 90)
        if (patchDays > 0) {
            val age = runCatching { ChronoUnit.DAYS.between(LocalDate.parse(Build.VERSION.SECURITY_PATCH), LocalDate.now()) }.getOrNull()
            check("patch", "Security patch within $patchDays days", age != null && age <= patchDays,
                if (age == null) "the security patch level is unknown" else "the security patch is $age days old (${Build.VERSION.SECURITY_PATCH})", byFenrir = false)
        }
        val minVersion = p.optInt("minAndroidVersion", 0)
        if (minVersion > 0) {
            val major = Build.VERSION.RELEASE.substringBefore('.').toIntOrNull() ?: 0
            check("osversion", "Android $minVersion or later", major >= minVersion, "the phone runs Android ${Build.VERSION.RELEASE}", byFenrir = false)
        }
        if (p.optBoolean("flagRooted", true)) {
            val rooted = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/system/app/Superuser.apk").any { File(it).exists() } ||
                Build.TAGS?.contains("test-keys") == true
            check("rooted", "Not rooted", !rooted, "the phone looks rooted", byFenrir = false)
        }
        for (app in required(p)) {
            check("required:${app.packageName}", "Required app ${app.packageName}", installed(context, app.packageName), "not installed")
        }
        for (name in lines(p, "blockedApps")) {
            val hidden = enforced && runCatching { dpm(context).isApplicationHidden(admin(context), name) }.getOrDefault(false)
            check("blocked:$name", "Blocked app $name", hidden || !installed(context, name), "installed")
        }
        return out
    }
}

/**
 * Work profile set-up (a personal phone). The Fenrir app on the personal side asks Android to create a work profile
 * with Fenrir as its owner, passing the server and enrolment code; Android then runs Fenrir inside the new profile,
 * which enrols with the server and applies the policy there. The personal side is not enrolled.
 */
object WorkProfile {
    const val REQUEST = 41
    // Android signals the finished profile twice (the provisioning activity and the admin broadcast): enrol once.
    private val enrolling = java.util.concurrent.atomic.AtomicBoolean(false)

    fun available(context: Context): Boolean =
        context.service<DevicePolicyManager>().isProvisioningAllowed(DevicePolicyManager.ACTION_PROVISION_MANAGED_PROFILE)

    fun start(activity: Activity, server: String, token: String): String? {
        if (!available(activity)) return "This phone cannot add a work profile (it may already have one, or the manufacturer does not allow it)."
        val extras = PersistableBundle().apply { putString("server", server); putString("token", token) }
        val intent = Intent(DevicePolicyManager.ACTION_PROVISION_MANAGED_PROFILE)
            .putExtra(DevicePolicyManager.EXTRA_PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME, ComponentName(activity, FenrirAdminReceiver::class.java))
            .putExtra(DevicePolicyManager.EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE, extras)
        if (intent.resolveActivity(activity.packageManager) == null) return "This phone does not support work profiles."
        activity.startActivityForResult(intent, REQUEST)
        return null
    }

    /** Retries a work-profile enrolment that failed (the server was unreachable when the profile was made). */
    fun retry(context: Context) {
        val pending = runCatching { JSONObject(Store(context).pendingEnrolment) }.getOrNull() ?: return
        Store(context).pendingEnrolment = ""
        finish(context, PersistableBundle().apply { putString("server", pending.optString("server")); putString("token", pending.optString("token")) })
    }

    /** Runs inside the new work profile once Android has created it: name it, switch it on and enrol it. */
    fun finish(context: Context, extras: PersistableBundle?) {
        val dpm = context.service<DevicePolicyManager>()
        val admin = ComponentName(context, FenrirAdminReceiver::class.java)
        runCatching { dpm.setProfileName(admin, "Work") }
        runCatching { dpm.setProfileEnabled(admin) }
        val store = Store(context)
        if (store.enrolled) return
        val server = extras?.getString("server").orEmpty()
        val token = extras?.getString("token").orEmpty()
        if (server.isBlank() || token.isBlank()) return
        if (!enrolling.compareAndSet(false, true)) return
        thread {
            try {
                val api = ControlPlane(server)
                val enrolment = api.enroll(token, Device.hostname(context) + " (work profile)", Device.osVersion(), Device.serial(context) + "-work", BuildConfig.VERSION_NAME)
                store.saveEnrolment(server, enrolment.deviceId, enrolment.apiKey)
                AgentService.start(context, "boot")
            } catch (error: Exception) {
                store.pendingEnrolment = JSONObject().put("server", server).put("token", token).toString()
                store.lastError = "Work profile enrolment failed: ${error.message}"
            } finally {
                enrolling.set(false)
            }
        }
    }
}

/**
 * Android's provisioning hand-offs: which mode Fenrir wants (a work profile), the policy-compliance step it shows in the
 * new profile, and "provisioning successful". Each finishes the set-up in the profile and closes.
 */
class ProvisioningActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        when (intent?.action) {
            DevicePolicyManager.ACTION_GET_PROVISIONING_MODE -> {
                if (Build.VERSION.SDK_INT >= 29) {
                    setResult(RESULT_OK, Intent().putExtra(DevicePolicyManager.EXTRA_PROVISIONING_MODE, DevicePolicyManager.PROVISIONING_MODE_MANAGED_PROFILE))
                }
            }
            else -> {
                val extras: PersistableBundle? = if (Build.VERSION.SDK_INT >= 33)
                    intent?.getParcelableExtra(DevicePolicyManager.EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE, PersistableBundle::class.java)
                else @Suppress("DEPRECATION") intent?.getParcelableExtra(DevicePolicyManager.EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE)
                WorkProfile.finish(this, extras)
                setResult(RESULT_OK)
            }
        }
        finish()
    }
}

/** The result of a silent install of a required app (work profile). */
class InstallResultReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val name = intent.getStringExtra("package") ?: return
        val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
        val store = Store(context)
        if (status == PackageInstaller.STATUS_SUCCESS) {
            store.queueEvent(Device.event("agent.app.installed", "Installed required app $name", JSONObject().put("package", name)))
        } else if (status != PackageInstaller.STATUS_PENDING_USER_ACTION) {
            store.queueEvent(Device.event("agent.app.install.failed", "Android did not install required app $name",
                JSONObject().put("package", name).put("status", status).put("reason", intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: "")))
        }
        AgentService.checkNow(context)
    }
}
