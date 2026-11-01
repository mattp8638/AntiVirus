package uk.co.fenrirsecurity.agent

import android.app.PendingIntent
import android.app.admin.DevicePolicyManager
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import org.json.JSONObject
import uk.co.fenrirsecurity.agent.core.AppFacts
import uk.co.fenrirsecurity.agent.core.AppRisk
import uk.co.fenrirsecurity.agent.core.Assessment
import java.io.File
import java.security.MessageDigest
import java.util.UUID

/**
 * App protection: gathers what AppRisk scores for each installed app (where it came from, what it can do, the APK and
 * signing-certificate SHA-256 the cloud checks against threat intelligence). Pure system apps are left out, like the
 * app list. APK hashes are cached per app version, so only new and updated apps are read again.
 */
object AppScanner {
    private const val MAX_HASH_BYTES = 512L * 1024 * 1024

    @Suppress("DEPRECATION")
    private val FLAGS = PackageManager.GET_PERMISSIONS or
        (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES)

    /** Every app (only = null) or just these packages. Blocking: call from a background thread. */
    fun scan(context: Context, store: Store, only: Collection<String>? = null): List<Pair<AppFacts, Assessment>> {
        val pm = context.packageManager
        val packages: List<PackageInfo> = if (only == null) {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(FLAGS)
        } else {
            only.mapNotNull { name -> runCatching { @Suppress("DEPRECATION") pm.getPackageInfo(name, FLAGS) }.getOrNull() }
        }
        val accessibility = enabledComponents(context, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
        val listeners = enabledComponents(context, "enabled_notification_listeners")
        val admins = context.service<DevicePolicyManager>().activeAdmins.orEmpty().map { it.packageName }.toSet()
        val cache = store.apkHashes()
        val results = packages.mapNotNull { info ->
            if (info.packageName == context.packageName) return@mapNotNull null
            val facts = facts(context, info, accessibility, listeners, admins, cache) ?: return@mapNotNull null
            facts to AppRisk.assess(facts)
        }
        store.saveApkHashes(cache)
        return results
    }

    private fun enabledComponents(context: Context, key: String): Set<String> =
        runCatching { Settings.Secure.getString(context.contentResolver, key) }.getOrNull().orEmpty().split(':')
            .mapNotNull { ComponentName.unflattenFromString(it)?.packageName }.toSet()

    private fun facts(context: Context, info: PackageInfo, accessibility: Set<String>, listeners: Set<String>, admins: Set<String>,
                      cache: JSONObject): AppFacts? {
        val app = info.applicationInfo ?: return null
        val system = app.flags and ApplicationInfo.FLAG_SYSTEM != 0
        val updated = app.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
        if (system && !updated) return null
        val pm = context.packageManager
        val name = info.packageName
        val installer = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) pm.getInstallSourceInfo(name).installingPackageName
            else @Suppress("DEPRECATION") pm.getInstallerPackageName(name)
        }.getOrNull()
        return AppFacts(
            packageName = name,
            label = runCatching { pm.getApplicationLabel(app).toString() }.getOrDefault(name),
            version = info.versionName ?: "",
            installer = installer,
            systemApp = system,
            sha256 = apkHash(app, info, cache),
            signer = signer(info),
            permissions = info.requestedPermissions?.toSet().orEmpty(),
            accessibilityOn = name in accessibility,
            deviceAdmin = name in admins,
            notificationAccess = name in listeners,
            hasLauncherIcon = pm.getLaunchIntentForPackage(name) != null,
            debuggable = app.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0,
            firstInstallMillis = info.firstInstallTime,
            lastUpdateMillis = info.lastUpdateTime,
        )
    }

    /** SHA-256 of the base APK, from the cache while the app version is unchanged. */
    private fun apkHash(app: ApplicationInfo, info: PackageInfo, cache: JSONObject): String? {
        val key = "${info.packageName}@${info.lastUpdateTime}"
        cache.optString(key).takeIf { it.isNotEmpty() }?.let { return it }
        val file = File(app.sourceDir ?: return null)
        if (!file.canRead() || file.length() > MAX_HASH_BYTES) return null
        val hash = runCatching {
            val digest = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buffer = ByteArray(1 shl 16)
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    digest.update(buffer, 0, read)
                }
            }
            AppRisk.hex(digest.digest())
        }.getOrNull() ?: return null
        // Drop the entry for the version this one replaced.
        cache.keys().asSequence().filter { it.startsWith("${info.packageName}@") }.toList().forEach { cache.remove(it) }
        cache.put(key, hash)
        return hash
    }

    private fun signer(info: PackageInfo): String? {
        val certificate = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            info.signingInfo?.apkContentsSigners?.firstOrNull()
        } else {
            @Suppress("DEPRECATION") info.signatures?.firstOrNull()
        } ?: return null
        return AppRisk.hex(MessageDigest.getInstance("SHA-256").digest(certificate.toByteArray()))
    }

    fun event(results: List<Pair<AppFacts, Assessment>>, full: Boolean): JSONObject =
        AppRisk.event(UUID.randomUUID().toString(), results.map { (facts, assessment) -> AppRisk.toJson(facts, assessment) }, full,
            System.currentTimeMillis())

    fun installed(context: Context, packageName: String): Boolean =
        runCatching { context.packageManager.getPackageInfo(packageName, 0) }.isSuccess

    /**
     * Removes an app. A device-owner (company-owned) Fenrir removes it silently; otherwise the phone shows the user a
     * notification that opens Android's own "uninstall this app?" screen. Returns what happened, for the console.
     */
    fun uninstall(context: Context, packageName: String, label: String): JSONObject {
        if (Device.isDeviceOwner(context) && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val flags = PendingIntent.FLAG_UPDATE_CURRENT or (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) PendingIntent.FLAG_MUTABLE else 0)
            val status = PendingIntent.getBroadcast(context, packageName.hashCode(),
                Intent(context, UninstallResultReceiver::class.java).putExtra(UninstallResultReceiver.EXTRA_TARGET, packageName), flags)
            context.packageManager.packageInstaller.uninstall(packageName, status.intentSender)
            return JSONObject().put("silent", true).put("requested", true)
        }
        Notifications.removeApp(context, label, packageName, "Your IT team asks you to remove this app.")
        return JSONObject().put("silent", false).put("askedUser", true)
    }

    /** Opens Android's uninstall confirmation for an app (needs REQUEST_DELETE_PACKAGES). */
    fun uninstallIntent(packageName: String): Intent =
        Intent(Intent.ACTION_DELETE, Uri.parse("package:$packageName")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
}

/** The result of a silent (device-owner) uninstall; reported to the cloud as an event. */
class UninstallResultReceiver : BroadcastReceiver() {
    companion object { const val EXTRA_TARGET = "target" }

    override fun onReceive(context: Context, intent: Intent) {
        val target = intent.getStringExtra(EXTRA_TARGET) ?: return
        val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
        val message = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: ""
        val store = Store(context)
        if (status == PackageInstaller.STATUS_SUCCESS) {
            store.queueEvent(AppRisk.removedEvent(UUID.randomUUID().toString(), target, System.currentTimeMillis()))
        } else {
            store.queueEvent(Device.event("mobile.app.uninstall.failed", "Android did not remove $target",
                JSONObject().put("package", target).put("status", status).put("message", message)))
        }
        AgentService.checkNow(context)
    }
}
