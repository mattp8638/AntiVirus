package uk.co.fenrirsecurity.agent

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.provider.Settings
import android.text.InputType
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import uk.co.fenrirsecurity.agent.core.ApiException
import uk.co.fenrirsecurity.agent.core.ControlPlane
import uk.co.fenrirsecurity.agent.core.EnrollLink
import uk.co.fenrirsecurity.agent.core.EnrollTarget
import java.text.DateFormat
import java.util.Date
import kotlin.concurrent.thread

/**
 * Setup and status. Not enrolled: scan the console's QR code (or open its link, or type the server and code).
 * Enrolled: a checklist of what Fenrir needs (location all the time, notifications, device admin, no battery
 * restrictions) with a button for each, and the connection status.
 */
class MainActivity : Activity() {
    private lateinit var store: Store
    private lateinit var content: LinearLayout
    private val main = Handler(Looper.getMainLooper())
    // Live status once enrolled. The setup form is not redrawn on a timer, or it would wipe what is being typed.
    private val refresher = object : Runnable { override fun run() { if (store.enrolled) render(); main.postDelayed(this, 3000) } }
    private var busy = false
    private var message: String? = null

    private val blue = Color.rgb(59, 130, 246)
    private val muted = Color.rgb(141, 155, 181)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = Store(this)
        content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(48, 48, 48, 96) }
        setContentView(ScrollView(this).apply { fitsSystemWindows = true; addView(content) })
        handleLink(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleLink(intent)
    }

    override fun onResume() {
        super.onResume()
        render()
        main.postDelayed(refresher, 3000)
        if (store.enrolled) AgentService.start(this)
    }

    override fun onPause() {
        main.removeCallbacks(refresher)
        super.onPause()
    }

    private fun handleLink(intent: Intent?) {
        val link = intent?.dataString ?: return
        EnrollLink.parse(link)?.let { if (!store.enrolled) enrol(it) }
    }

    private fun render() {
        content.removeAllViews()
        content.addView(title("Fenrir"))
        if (!store.enrolled) renderSetup() else renderStatus()
        message?.let { content.addView(label(it, Color.rgb(253, 230, 138))) }
    }

    private fun renderSetup() {
        if (store.removed) content.addView(label("Your IT team removed this phone from management. Scan a new code to set it up again.", muted))
        content.addView(label("Set up this phone with your IT team. In their Fenrir console: Deploy agents → Add a phone, then scan the code.", muted))
        content.addView(button("Scan enrolment code", primary = true) { scan() })
        content.addView(heading("Or enter it by hand"))
        val server = input("Server, e.g. fenrir.example.com", InputType.TYPE_TEXT_VARIATION_URI)
        val code = input("Enrolment code", InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD)
        content.addView(server)
        content.addView(code)
        content.addView(button("Enrol") {
            val target = EnrollLink.normaliseServer(server.text.toString())
            if (target == null || code.text.isBlank()) { message = "Enter the server and the code"; render() }
            else enrol(EnrollTarget(target, code.text.toString().trim()))
        })
    }

    private fun renderStatus() {
        val lost = store.lostMode
        if (lost.enabled) content.addView(card("Lost mode is on", "This phone was reported lost. It is locked and sharing its location.", Color.rgb(127, 29, 29)))
        val last = store.lastContact
        content.addView(label(
            "Managed by ${store.server.removePrefix("https://")}\n" +
                (if (last > 0) "Last check-in ${DateFormat.getTimeInstance(DateFormat.SHORT).format(Date(last))}" else "Connecting…") +
                (store.lastError.takeIf { it.isNotBlank() }?.let { "\nProblem: $it" } ?: ""),
            muted,
        ))
        content.addView(heading("What Fenrir needs"))
        val fine = granted(Manifest.permission.ACCESS_FINE_LOCATION)
        step("Location", fine, "So your phone can be found if it is lost.") {
            requestPermissions(arrayOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION), 1)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            step("Location all the time", granted(Manifest.permission.ACCESS_BACKGROUND_LOCATION),
                "Choose \"Allow all the time\" so it works while the app is closed.", enabled = fine) {
                requestPermissions(arrayOf(Manifest.permission.ACCESS_BACKGROUND_LOCATION), 2)
            }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            step("Notifications", granted(Manifest.permission.POST_NOTIFICATIONS), "For messages from IT and the find-my-phone alarm.") {
                requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 3)
            }
        }
        step("Device admin", Device.adminActive(this), "Lets IT lock or erase the phone if it is stolen.") {
            startActivity(Device.adminRequest(this))
        }
        val power = service<PowerManager>()
        step("No battery restrictions", power.isIgnoringBatteryOptimizations(packageName), "Stops Android pausing Fenrir to save battery.") {
            startActivity(Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:$packageName")))
        }
        if (Build.VERSION.SDK_INT >= 34) {
            val nm = service<android.app.NotificationManager>()
            step("Lost-mode screen", nm.canUseFullScreenIntent(), "Lets the lost-mode message appear over the lock screen.") {
                startActivity(Intent(Settings.ACTION_MANAGE_APP_USE_FULL_SCREEN_INTENT, Uri.parse("package:$packageName")))
            }
        }
        content.addView(label("Version ${BuildConfig.VERSION_NAME} · device ${store.deviceId}", muted))
    }

    private fun step(name: String, done: Boolean, why: String, enabled: Boolean = true, action: () -> Unit) {
        val row = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(0, 18, 0, 18) }
        row.addView(TextView(this).apply {
            text = (if (done) "✓  " else "•  ") + name
            textSize = 17f
            setTextColor(if (done) Color.rgb(134, 239, 172) else Color.WHITE)
            setTypeface(typeface, Typeface.BOLD)
        })
        row.addView(label(why, muted))
        if (!done) row.addView(button(if (enabled) "Turn on" else "Allow location first") { if (enabled) action() }.apply { isEnabled = enabled })
        content.addView(row)
    }

    private fun scan() {
        val options = GmsBarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build()
        GmsBarcodeScanning.getClient(this, options).startScan()
            .addOnSuccessListener { barcode ->
                val target = barcode.rawValue?.let(EnrollLink::parse)
                if (target == null) { message = "That isn't a Fenrir enrolment code."; render() } else enrol(target)
            }
            .addOnFailureListener { error -> message = "The scanner isn't available (${error.message}). Enter the code by hand."; render() }
    }

    private fun enrol(target: EnrollTarget) {
        if (busy) return
        busy = true
        message = "Enrolling with ${target.server.removePrefix("https://")}…"
        render()
        thread {
            val result = try {
                val api = ControlPlane(target.server)
                val enrolment = api.enroll(target.token, Device.hostname(this), Device.osVersion(), Device.serial(this), BuildConfig.VERSION_NAME)
                store.saveEnrolment(target.server, enrolment.deviceId, enrolment.apiKey)
                null
            } catch (error: ApiException) {
                when (error.status) { 401, 403 -> "The code was not accepted: it may have been used already or expired. Ask IT for a new one."; else -> "Enrolment failed (HTTP ${error.status})." }
            } catch (error: Exception) {
                "Couldn't reach the server: ${error.message}"
            }
            main.post {
                busy = false
                message = result ?: "Enrolled. Now allow what Fenrir needs below."
                if (result == null) {
                    AgentService.start(this)
                    requestPermissions(arrayOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION), 1)
                }
                render()
            }
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (store.enrolled) AgentService.start(this)
        render()
    }

    private fun granted(permission: String) = checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED

    private fun title(text: String) = TextView(this).apply {
        this.text = text; textSize = 28f; setTextColor(Color.WHITE); setTypeface(typeface, Typeface.BOLD); setPadding(0, 0, 0, 24)
    }
    private fun heading(text: String) = TextView(this).apply {
        this.text = text.uppercase(); textSize = 13f; setTextColor(muted); setTypeface(typeface, Typeface.BOLD); setPadding(0, 36, 0, 8)
    }
    private fun label(text: String, color: Int) = TextView(this).apply {
        this.text = text; textSize = 15f; setTextColor(color); setPadding(0, 8, 0, 8)
    }
    private fun card(title: String, body: String, color: Int) = TextView(this).apply {
        text = "$title\n$body"; textSize = 16f; setTextColor(Color.WHITE); setPadding(32, 28, 32, 28)
        background = GradientDrawable().apply { setColor(color); cornerRadius = 24f }
    }
    private fun input(hint: String, type: Int) = EditText(this).apply {
        this.hint = hint; inputType = InputType.TYPE_CLASS_TEXT or type; setTextColor(Color.WHITE); setHintTextColor(muted); isSingleLine = true
    }
    private fun button(text: String, primary: Boolean = false, onClick: () -> Unit) = Button(this).apply {
        this.text = text
        isAllCaps = false
        textSize = 16f
        if (primary) { setTextColor(Color.WHITE); background = GradientDrawable().apply { setColor(blue); cornerRadius = 20f } }
        setOnClickListener { onClick() }
        layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply { topMargin = 12 }
        visibility = View.VISIBLE
    }
}
