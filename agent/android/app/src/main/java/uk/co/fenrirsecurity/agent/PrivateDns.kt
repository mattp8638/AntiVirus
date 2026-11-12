package uk.co.fenrirsecurity.agent

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import org.json.JSONObject
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import kotlin.concurrent.thread
import kotlin.random.Random

/**
 * Scam and phishing site blocking through Android's Private DNS (policy "privateDns": "fenrir").
 *
 * On a company-owned phone (Fenrir is the device owner, Android 10+) the phone's Private DNS is set to the server's
 * DNS-over-TLS hostname, so every app's lookups go through Fenrir's DNS filtering with nothing running on the phone.
 *
 * Private DNS in "hostname" mode has no fallback of its own: if the server cannot be reached the phone has no internet.
 * So before setting it, and every few minutes and on every network change after, Fenrir checks the server itself
 * (a TLS connection to port 853 that must answer a lookup). Two failures in a row put the phone back on automatic
 * Private DNS (the network's normal DNS) for 30 minutes and report it; it is set again once the server answers.
 *
 * The check also tells the server which phone is behind the current public address (the probe name carries the
 * phone's DNS token), so its lookups use its own policy.
 */
object PrivateDns {
    private const val PORT = 853
    private const val CHECK_EVERY_MS = 3 * 60_000L
    private const val SUSPEND_MS = 30 * 60_000L
    private const val FAILURES_BEFORE_FALLBACK = 2

    private fun admin(context: Context) = ComponentName(context, FenrirAdminReceiver::class.java)
    private fun dpm(context: Context) = context.service<DevicePolicyManager>()

    fun supported(context: Context): Boolean =
        Build.VERSION.SDK_INT >= 29 && dpm(context).isDeviceOwnerApp(context.packageName)

    private data class Wanted(val host: String, val probe: String)

    private fun wanted(policy: JSONObject): Wanted? {
        if (policy.optString("privateDns") != "fenrir") return null
        val host = policy.optString("privateDnsHost").trim().lowercase()
        val probe = policy.optString("privateDnsProbe").trim().lowercase()
        if (!Regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$").matches(host)) return null
        return Wanted(host, probe)
    }

    /** Called from the agent's cycle (and after policy changes and network changes). Never throws. */
    @Synchronized
    fun check(context: Context, store: Store, force: Boolean = false) {
        runCatching { checkInner(context, store, force) }
            .onFailure { store.lastError = "Private DNS: ${it.message ?: it.javaClass.simpleName}" }
    }

    private fun checkInner(context: Context, store: Store, force: Boolean) {
        if (Build.VERSION.SDK_INT < 29 || !supported(context)) return
        val target = wanted(PhonePolicy.policy(store))
        val now = System.currentTimeMillis()
        if (target == null) {
            if (store.privateDnsHost.isNotEmpty()) revert(context, store, "the policy no longer asks for it")
            return
        }
        if (store.privateDnsHost.isNotEmpty() && store.privateDnsHost != target.host) revert(context, store, "the server's DNS hostname changed")
        if (!force && now - store.privateDnsLastCheck < CHECK_EVERY_MS) return
        if (store.privateDnsHost.isEmpty() && now < store.privateDnsSuspendedUntil) return
        store.privateDnsLastCheck = now

        val error = probe(context, store, target)
        if (error == null) {
            store.privateDnsFailures = 0
            if (store.privateDnsHost != target.host) {
                val result = dpm(context).setGlobalPrivateDnsModeSpecifiedHost(admin(context), target.host)
                if (result == DevicePolicyManager.PRIVATE_DNS_SET_NO_ERROR) {
                    val resumed = store.privateDnsSuspendedUntil > 0
                    store.privateDnsHost = target.host
                    store.privateDnsSuspendedUntil = 0
                    store.queueEvent(Device.event(if (resumed) "dns.private.resumed" else "dns.private.enabled",
                        "Scam and phishing site blocking is on (Private DNS ${target.host})", JSONObject().put("host", target.host)))
                } else {
                    suspend(store, now)
                    store.queueEvent(Device.event("dns.private.refused", "Android would not use ${target.host} for Private DNS",
                        JSONObject().put("host", target.host).put("result", result)))
                }
            }
            return
        }
        store.privateDnsFailures = store.privateDnsFailures + 1
        if (store.privateDnsHost.isEmpty()) {
            suspend(store, now)  // never switched on: try again later, nothing to undo
            return
        }
        if (store.privateDnsFailures >= FAILURES_BEFORE_FALLBACK) {
            revert(context, store, error)
            suspend(store, now)
            store.queueEvent(Device.event("dns.private.fallback",
                "Fenrir's DNS could not be reached, so the phone went back to normal DNS: $error",
                JSONObject().put("host", target.host).put("reason", error)))
        } else {
            store.privateDnsLastCheck = 0  // check again on the next cycle rather than in 3 minutes
        }
    }

    private fun suspend(store: Store, now: Long) {
        store.privateDnsSuspendedUntil = now + SUSPEND_MS
        store.privateDnsFailures = 0
    }

    private fun revert(context: Context, store: Store, reason: String) {
        if (Build.VERSION.SDK_INT >= 29) runCatching { dpm(context).setGlobalPrivateDnsModeOpportunistic(admin(context)) }
        if (store.privateDnsHost.isNotEmpty()) {
            store.queueEvent(Device.event("dns.private.disabled", "Private DNS set back to automatic: $reason",
                JSONObject().put("host", store.privateDnsHost).put("reason", reason)))
        }
        store.privateDnsHost = ""
    }

    /** Null when the server answered both the phone's probe and a real lookup; otherwise why not. */
    private fun probe(context: Context, store: Store, target: Wanted): String? {
        val addresses = runCatching { InetAddress.getAllByName(target.host).toList() }.getOrDefault(emptyList())
        if (addresses.isNotEmpty()) store.privateDnsAddress = addresses.first().hostAddress ?: ""
        val address = addresses.firstOrNull() ?: store.privateDnsAddress.takeIf { it.isNotEmpty() }?.let { InetAddress.getByName(it) }
            ?: return "could not look up ${target.host}"
        return try {
            Socket().use { raw ->
                raw.connect(InetSocketAddress(address, PORT), 5_000)
                raw.soTimeout = 5_000
                val tls = (SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(raw, target.host, PORT, false) as SSLSocket
                tls.use { socket ->
                    socket.startHandshake()
                    if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(target.host, socket.session)) {
                        return "the certificate is not for ${target.host}"
                    }
                    val output = DataOutputStream(socket.outputStream)
                    val input = DataInputStream(socket.inputStream)
                    if (target.probe.isNotEmpty() && lookup(output, input, target.probe, 16) == null) return "the server did not recognise this phone"
                    if (lookup(output, input, "connectivitycheck.gstatic.com", 1) == null) return "the server could not resolve names"
                    null
                }
            }
        } catch (error: IOException) {
            "${target.host}:$PORT did not answer (${error.message ?: error.javaClass.simpleName})"
        }
    }

    /** One DNS-over-TLS lookup (RFC 7858 framing). Returns the answer count when the reply is NOERROR with answers. */
    private fun lookup(output: DataOutputStream, input: DataInputStream, name: String, type: Int): Int? {
        val id = Random.nextInt(0, 0x10000)
        val query = java.io.ByteArrayOutputStream().apply {
            val data = DataOutputStream(this)
            data.writeShort(id); data.writeShort(0x0100); data.writeShort(1); data.writeShort(0); data.writeShort(0); data.writeShort(0)
            for (label in name.trimEnd('.').split('.')) {
                val bytes = label.toByteArray(Charsets.US_ASCII)
                data.writeByte(bytes.size); data.write(bytes)
            }
            data.writeByte(0); data.writeShort(type); data.writeShort(1)
        }.toByteArray()
        output.writeShort(query.size)
        output.write(query)
        output.flush()
        val length = input.readUnsignedShort()
        if (length < 12) return null
        val reply = ByteArray(length)
        input.readFully(reply)
        val replyId = ((reply[0].toInt() and 0xff) shl 8) or (reply[1].toInt() and 0xff)
        val rcode = reply[3].toInt() and 0x0f
        val answers = ((reply[6].toInt() and 0xff) shl 8) or (reply[7].toInt() and 0xff)
        return if (replyId == id && rcode == 0 && answers > 0) answers else null
    }

    /** A compliance line for company-owned phones whose policy asks for it (others cannot be set this way). */
    fun compliance(context: Context, store: Store): JSONObject? {
        if (!supported(context)) return null
        val target = wanted(PhonePolicy.policy(store)) ?: return null
        val ok = store.privateDnsHost == target.host
        val detail = when {
            ok -> ""
            store.privateDnsSuspendedUntil > System.currentTimeMillis() -> "Fenrir's DNS (${target.host}) could not be reached, so normal DNS is used until it can be"
            else -> "being switched on"
        }
        return JSONObject().put("key", "privatedns").put("label", "Scam and phishing site blocking").put("ok", ok)
            .put("detail", detail).put("enforced", true)
    }

    /** Checks again straight away when the phone changes network or a network stops validating. */
    @Volatile private var watching = false

    @Synchronized
    fun watchNetworks(context: Context, store: Store) {
        if (watching || !supported(context)) return
        val app = context.applicationContext
        val manager = app.service<ConnectivityManager>()
        runCatching {
            manager.registerDefaultNetworkCallback(object : ConnectivityManager.NetworkCallback() {
                private var last: Network? = null
                override fun onAvailable(network: Network) {
                    if (network != last) { last = network; soon(app, store) }
                }
                override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                    if (store.privateDnsHost.isNotEmpty() && !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
                        soon(app, store)
                    }
                }
            })
            watching = true  // process-wide, so a restarted service does not register a second callback
        }
    }

    @Volatile private var lastSoon = 0L

    private fun soon(context: Context, store: Store) {
        val now = System.currentTimeMillis()
        if (now - lastSoon < 30_000L) return
        lastSoon = now
        thread(name = "fenrir-private-dns") {
            Thread.sleep(3_000)  // let the new network settle
            check(context, store, force = true)
        }
    }
}
