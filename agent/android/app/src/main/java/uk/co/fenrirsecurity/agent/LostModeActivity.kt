package uk.co.fenrirsecurity.agent

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.graphics.Color
import android.graphics.Typeface
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.Gravity
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

/** Shown over the lock screen while the phone is in lost mode: the owner's message and a number to call. */
class LostModeActivity : Activity() {
    companion object {
        const val ACTION_CLOSE = "uk.co.fenrirsecurity.agent.CLOSE_LOST_MODE"
    }

    private val close = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) = finish()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
            setShowWhenLocked(true)
            setTurnScreenOn(true)
        } else {
            @Suppress("DEPRECATION")
            window.addFlags(WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON)
        }
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        val filter = IntentFilter(ACTION_CLOSE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) registerReceiver(close, filter, Context.RECEIVER_NOT_EXPORTED)
        else registerReceiver(close, filter)
        render()
    }

    override fun onResume() {
        super.onResume()
        if (!Store(this).lostMode.enabled) finish()
    }

    override fun onDestroy() {
        runCatching { unregisterReceiver(close) }
        super.onDestroy()
    }

    @Deprecated("Deprecated in Java")
    @Suppress("MissingSuperCall")
    override fun onBackPressed() {
        // Back does nothing: the screen goes away when lost mode is turned off from the console.
    }

    private fun render() {
        val lost = Store(this).lostMode
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(64, 96, 64, 96)
            setBackgroundColor(Color.rgb(127, 29, 29))
            fitsSystemWindows = true
        }
        fun text(value: String, size: Float, bold: Boolean = false) = TextView(this).apply {
            this.text = value
            textSize = size
            setTextColor(Color.WHITE)
            gravity = Gravity.CENTER
            if (bold) setTypeface(typeface, Typeface.BOLD)
            setPadding(0, 16, 0, 16)
        }
        root.addView(text("This phone has been reported lost", 26f, bold = true))
        root.addView(text(lost.message.ifBlank { "Please contact the owner." }, 19f))
        if (lost.phone.isNotBlank()) {
            root.addView(text(lost.phone, 30f, bold = true))
            root.addView(Button(this).apply {
                text = "Call the owner"
                textSize = 18f
                setOnClickListener { startActivity(Intent(Intent.ACTION_DIAL, Uri.parse("tel:" + lost.phone.filter { it.isDigit() || it == '+' }))) }
            })
        }
        root.addView(text("Its location is being shared with its owner.", 14f))
        setContentView(root)
    }
}
