package uk.co.fenrirsecurity.agent

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.app.Activity
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.graphics.Bitmap
import android.graphics.Path
import android.graphics.PixelFormat
import android.graphics.Point
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.ImageReader
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.provider.Settings
import android.util.DisplayMetrics
import android.view.Display
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.URLEncoder
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.roundToInt

/**
 * Remote screen sharing and control for Android, over the same relay protocol as the desktop agents
 * (docs/REMOTE_PROTOCOL.md): the phone sends whole-screen JPEG frames (binary 0x01) and receives taps, swipes, scrolls,
 * typing and Back/Home/Recents.
 *
 * Android decides two things Fenrir cannot: the phone's user allows every session in Android's own screen-sharing
 * prompt, and control works only while Fenrir's accessibility service is switched on (Settings > Accessibility).
 * Without it the technician can still see the screen.
 */
object Remote {
    @Volatile var current: RemoteSession? = null
    internal val http: OkHttpClient by lazy {
        OkHttpClient.Builder().connectTimeout(20, TimeUnit.SECONDS).readTimeout(0, TimeUnit.MILLISECONDS)
            .pingInterval(20, TimeUnit.SECONDS).build()
    }

    /** Starts a session from a remote.session.start command; null when it is under way, else why not. */
    fun start(context: Context, payload: JSONObject): String? {
        val mode = payload.optString("mode", "desktop")
        if (mode != "desktop") return "Android phones support screen sharing only (not $mode)"
        val relay = payload.optString("relayUrl")
        val token = payload.optString("token")
        if (!relay.startsWith("wss://") && !relay.startsWith("ws://") || token.isBlank()) return "The session has no relay address"
        current?.finish("replaced by a new session")
        val session = RemoteSession(context.applicationContext, payload)
        current = session
        session.connect()
        return null
    }

    fun controlAvailable(): Boolean = FenrirAccessibilityService.instance != null

    fun accessibilityEnabled(context: Context): Boolean {
        val enabled = Settings.Secure.getString(context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: return false
        return enabled.split(':').any { it.startsWith(context.packageName + "/") }
    }
}

class RemoteSession(private val context: Context, payload: JSONObject) {
    val sessionId: String = payload.optString("sessionId")
    private val relayUrl: String = payload.optString("relayUrl")
    private val token: String = payload.optString("token")
    private val technician: String = payload.optString("technician").ifBlank { "Your IT team" }
    val viewOnly: Boolean = payload.optBoolean("viewOnly", false)
    private val idleMinutes = payload.optInt("idleTimeoutMinutes", 30).coerceIn(1, 480)

    @Volatile var quality: Int = payload.optInt("quality", 70).coerceIn(10, 95); private set
    @Volatile var fps: Int = payload.optInt("maxFps", 15).coerceIn(1, 30); private set
    @Volatile var streaming = false; private set
    @Volatile var refreshRequested = true
    @Volatile private var granted = false
    @Volatile private var ended = false
    @Volatile private var lastActivity = System.currentTimeMillis()
    @Volatile var lastSentAt = 0L; private set
    private val unacked = AtomicInteger(0)
    private var seq = 0
    private var socket: WebSocket? = null
    private val timers = Executors.newSingleThreadScheduledExecutor()

    // Screen geometry: captured size (what the viewer sees) and the real display size (where gestures land).
    @Volatile var captureW = 0; @Volatile var captureH = 0
    @Volatile var realW = 0; @Volatile var realH = 0

    // A press in progress (md .. mu), turned into one gesture when released.
    private val stroke = ArrayList<Point>()
    private var strokeStarted = 0L

    fun connect() {
        val url = relayUrl + (if ('?' in relayUrl) "&" else "?") + "token=" + URLEncoder.encode(token, "UTF-8")
        val request = Request.Builder().url(url).header("X-Fenrir-Session-Token", token).header("User-Agent", "FenrirAndroid").build()
        socket = Remote.http.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                send(JSONObject().put("ch", "sys").put("t", "consent").put("state", "pending"))
                RemoteNotifications.request(context, technician)
                // Android's prompt must be answered; an unanswered request ends after two minutes.
                timers.schedule({ if (!granted && !ended) declined("nobody allowed screen sharing on the phone") }, 2, TimeUnit.MINUTES)
                timers.scheduleWithFixedDelay({
                    if (!ended && System.currentTimeMillis() - lastActivity > idleMinutes * 60_000L) finish("idle for $idleMinutes minutes")
                }, 1, 1, TimeUnit.MINUTES)
            }

            override fun onMessage(webSocket: WebSocket, text: String) = handle(text)
            override fun onMessage(webSocket: WebSocket, bytes: ByteString) = Unit  // no uploads on phones
            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) = finish(reason.ifBlank { "the session was closed" }, tellRelay = false)
            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) =
                finish("connection lost: ${t.message ?: t.javaClass.simpleName}", tellRelay = false)
        })
    }

    /** Called by ScreenCaptureService once Android's prompt was accepted and capture runs. */
    fun captureStarted() {
        granted = true
        RemoteNotifications.cancelRequest(context)
        send(JSONObject().put("ch", "sys").put("t", "consent").put("state", "granted"))
        send(info())
        if (!viewOnly && !Remote.controlAvailable()) {
            send(JSONObject().put("ch", "sys").put("t", "error").put("message",
                "You can see the phone's screen. To control it, the user turns on Fenrir in Settings > Accessibility."))
        }
    }

    fun declined(why: String) {
        if (ended) return
        send(JSONObject().put("ch", "sys").put("t", "consent").put("state", "denied"))
        finish(why)
    }

    private fun info(): JSONObject {
        val caps = org.json.JSONArray().put("desktop").put("chat")
        if (Remote.controlAvailable()) caps.put("nav")
        return JSONObject().put("ch", "sys").put("t", "info").put("hostname", Device.hostname(context)).put("os", Device.osVersion())
            .put("user", "").put("home", "/").put("capabilities", caps).put("quality", quality).put("maxFps", fps)
            .put("monitors", org.json.JSONArray().put(JSONObject().put("index", 0).put("x", 0).put("y", 0)
                .put("w", captureW).put("h", captureH).put("primary", true)))
    }

    private fun handle(text: String) {
        val m = runCatching { JSONObject(text) }.getOrNull() ?: return
        val channel = m.optString("ch")
        val type = m.optString("t")
        if (channel != "sys" || type != "ping") lastActivity = System.currentTimeMillis()
        when (channel) {
            "sys" -> when (type) {
                "ping" -> send(JSONObject().put("ch", "sys").put("t", "pong").put("ts", m.opt("ts")))
                "end" -> finish(m.optString("reason").ifBlank { "the technician ended the session" }, tellRelay = false)
            }
            "screen" -> when (type) {
                "start", "settings" -> {
                    if (m.has("quality")) quality = m.optInt("quality", quality).coerceIn(10, 95)
                    if (m.has("fps")) fps = m.optInt("fps", fps).coerceIn(1, 30)
                    streaming = true
                    refreshRequested = true
                }
                "refresh" -> refreshRequested = true
                "ack" -> if (unacked.decrementAndGet() < 0) unacked.set(0)
                "stop" -> streaming = false
            }
            "input" -> if (!viewOnly) input(type, m)
            "chat" -> if (type == "msg") Notifications.message(context, "Message from IT support", m.optString("text").take(2000))
        }
    }

    /** True when the capture should send a frame now (flow control: at most two frames unacknowledged). */
    fun wantsFrame(): Boolean =
        granted && streaming && !ended && unacked.get() < 2 && System.currentTimeMillis() - lastSentAt >= 1000L / fps

    fun sendFrame(jpeg: ByteArray, width: Int, height: Int) {
        val header = ByteBuffer.allocate(13)
        header.put(1.toByte()).putShort(0).putShort(0).putShort(width.toShort()).putShort(height.toShort())
            .putShort(width.toShort()).putShort(height.toShort())
        val frame = ByteArray(13 + jpeg.size)
        System.arraycopy(header.array(), 0, frame, 0, 13)
        System.arraycopy(jpeg, 0, frame, 13, jpeg.size)
        val socket = socket ?: return
        if (!socket.send(frame.toByteString())) return
        unacked.incrementAndGet()
        lastSentAt = System.currentTimeMillis()
        refreshRequested = false
        send(JSONObject().put("ch", "screen").put("t", "frame.end").put("seq", ++seq).put("tiles", 1))
    }

    private fun point(m: JSONObject): Point {
        val sx = if (captureW > 0 && realW > 0) realW.toDouble() / captureW else 1.0
        val sy = if (captureH > 0 && realH > 0) realH.toDouble() / captureH else 1.0
        return Point((m.optDouble("x", 0.0) * sx).roundToInt(), (m.optDouble("y", 0.0) * sy).roundToInt())
    }

    private fun input(type: String, m: JSONObject) {
        val control = FenrirAccessibilityService.instance
        when (type) {
            "md" -> if (m.optInt("b", 0) == 0) { stroke.clear(); stroke.add(point(m)); strokeStarted = System.currentTimeMillis() }
            "mm" -> if (stroke.isNotEmpty() && stroke.size < 300) {
                val p = point(m)
                val last = stroke.last()
                if (abs(p.x - last.x) + abs(p.y - last.y) >= 6) stroke.add(p)
            }
            "mu" -> if (stroke.isNotEmpty()) {
                if (m.has("x")) stroke.add(point(m))
                control?.gesture(stroke.toList(), (System.currentTimeMillis() - strokeStarted).coerceIn(40, 10_000))
                stroke.clear()
            }
            "wh" -> {
                // One wheel notch scrolls about a fifth of the screen: a swipe the other way.
                val p = point(m)
                val distance = max(realH, 1) / 5
                val dy = m.optInt("dy", 0)
                val dx = m.optInt("dx", 0)
                control?.gesture(listOf(p, Point(p.x - dx * distance, p.y - dy * distance)), 250)
            }
            "kd" -> {
                val key = m.optString("key")
                when (m.optString("code")) {
                    "Backspace" -> control?.backspace()
                    "Enter", "NumpadEnter" -> control?.enter()
                    "Escape" -> control?.nav("back")
                    else -> if (key.length == 1) control?.type(key)
                }
            }
            "type" -> control?.type(m.optString("text").take(4000))
            "nav" -> control?.nav(m.optString("action"))
            "clip.set" -> runCatching {
                context.service<ClipboardManager>().setPrimaryClip(ClipData.newPlainText("From IT support", m.optString("text").take(20_000)))
            }
            "lock" -> Device.lock(context)
        }
    }

    fun send(message: JSONObject) {
        socket?.send(message.toString())
    }

    @Synchronized
    fun finish(reason: String, tellRelay: Boolean = true) {
        if (ended) return
        ended = true
        streaming = false
        if (tellRelay) send(JSONObject().put("ch", "sys").put("t", "end").put("reason", reason))
        runCatching { socket?.close(1000, reason.take(120)) }
        if (Remote.current === this) Remote.current = null
        RemoteNotifications.cancelRequest(context)
        ScreenCaptureService.stop(context)
        timers.shutdownNow()
    }
}

/** Opens Android's screen-sharing prompt (it can only be shown from an activity). */
class ScreenShareActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Remote.current == null) { finish(); return }
        startActivityForResult(service<MediaProjectionManager>().createScreenCaptureIntent(), 1)
    }

    @Deprecated("Activity result callback")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode == RESULT_OK && data != null) ScreenCaptureService.start(this, resultCode, data)
        else Remote.current?.declined("the phone's user declined screen sharing")
        finish()
    }
}

/**
 * Captures the screen while a session runs. Android requires a foreground service of type mediaProjection, with its
 * own notification ("Sharing your screen", with Stop), for as long as the screen is shared.
 */
class ScreenCaptureService : Service() {
    companion object {
        private const val ACTION_STOP = "uk.co.fenrirsecurity.agent.STOP_SHARING"
        private const val MAX_SIDE = 1280

        fun start(context: Context, resultCode: Int, data: Intent) {
            context.startForegroundService(Intent(context, ScreenCaptureService::class.java).putExtra("code", resultCode).putExtra("data", data))
        }

        fun stop(context: Context) {
            runCatching { context.stopService(Intent(context, ScreenCaptureService::class.java)) }
        }

        fun stopIntent(context: Context): PendingIntent = PendingIntent.getService(context, 7,
            Intent(context, ScreenCaptureService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
    }

    private var projection: MediaProjection? = null
    private var display: VirtualDisplay? = null
    private var reader: ImageReader? = null
    private val thread = HandlerThread("fenrir-capture").apply { start() }
    private val handler = Handler(thread.looper)
    private var lastJpeg: ByteArray? = null
    private var lastHash: String = ""
    private var landscape = false

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val notification = RemoteNotifications.sharing(this)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(RemoteNotifications.ID_SHARING, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION)
        } else {
            startForeground(RemoteNotifications.ID_SHARING, notification)
        }
        if (intent?.action == ACTION_STOP) {
            Remote.current?.finish("the phone's user stopped sharing")
            stopSelf()
            return START_NOT_STICKY
        }
        if (projection != null) return START_NOT_STICKY
        val data: Intent? = if (Build.VERSION.SDK_INT >= 33) intent?.getParcelableExtra("data", Intent::class.java)
                            else @Suppress("DEPRECATION") intent?.getParcelableExtra("data")
        val session = Remote.current
        if (data == null || session == null) { stopSelf(); return START_NOT_STICKY }
        val started = runCatching {
            val mp = service<MediaProjectionManager>().getMediaProjection(intent!!.getIntExtra("code", 0), data)
            projection = mp
            mp.registerCallback(object : MediaProjection.Callback() {
                override fun onStop() { Remote.current?.finish("the phone's user stopped sharing") }
            }, handler)
            createDisplay(session)
        }
        if (started.isFailure) {
            session.declined("Android refused screen capture: ${started.exceptionOrNull()?.message}")
            stopSelf()
        } else {
            session.captureStarted()
            resendIfAsked()
        }
        return START_NOT_STICKY
    }

    @Suppress("DEPRECATION")
    private fun realSize(): Point {
        val size = Point()
        service<DisplayManager>().getDisplay(Display.DEFAULT_DISPLAY).getRealSize(size)
        return size
    }

    private fun createDisplay(session: RemoteSession) {
        val real = realSize()
        landscape = real.x > real.y
        val scale = minOf(1.0, MAX_SIDE.toDouble() / max(real.x, real.y))
        val w = ((real.x * scale).roundToInt() / 2) * 2
        val h = ((real.y * scale).roundToInt() / 2) * 2
        session.realW = real.x; session.realH = real.y
        session.captureW = w; session.captureH = h
        val metrics = DisplayMetrics().also { @Suppress("DEPRECATION") service<DisplayManager>().getDisplay(Display.DEFAULT_DISPLAY).getRealMetrics(it) }
        val density = max(1, (metrics.densityDpi * scale).roundToInt())
        val newReader = ImageReader.newInstance(w, h, PixelFormat.RGBA_8888, 2)
        newReader.setOnImageAvailableListener({ capture(it) }, handler)
        val old = reader
        reader = newReader
        val existing = display
        if (existing == null) {
            display = projection!!.createVirtualDisplay("fenrir-remote", w, h, density, DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
                newReader.surface, null, handler)
        } else {
            existing.resize(w, h, density)
            existing.surface = newReader.surface
        }
        old?.close()
        lastHash = ""
        session.refreshRequested = true
    }

    private fun capture(source: ImageReader) {
        val image = runCatching { source.acquireLatestImage() }.getOrNull() ?: return
        try {
            val session = Remote.current ?: return
            // Turned the phone: capture at the new shape so the picture is not squashed.
            val real = realSize()
            if ((real.x > real.y) != landscape) { image.close(); createDisplay(session); return }
            if (!session.wantsFrame()) return
            val plane = image.planes[0]
            val pixelStride = plane.pixelStride
            val rowPadding = plane.rowStride - pixelStride * image.width
            val padded = Bitmap.createBitmap(image.width + rowPadding / pixelStride, image.height, Bitmap.Config.ARGB_8888)
            padded.copyPixelsFromBuffer(plane.buffer)
            val bitmap = if (rowPadding == 0) padded else Bitmap.createBitmap(padded, 0, 0, image.width, image.height)
            val out = ByteArrayOutputStream()
            bitmap.compress(Bitmap.CompressFormat.JPEG, session.quality, out)
            if (bitmap !== padded) bitmap.recycle()
            padded.recycle()
            val jpeg = out.toByteArray()
            val hash = MessageDigest.getInstance("MD5").digest(jpeg).joinToString("") { "%02x".format(it) }
            if (hash == lastHash && !session.refreshRequested) return
            lastHash = hash
            lastJpeg = jpeg
            session.sendFrame(jpeg, image.width, image.height)
        } catch (_: Exception) {
            // a single bad frame is skipped
        } finally {
            runCatching { image.close() }
        }
        resendIfAsked()
    }

    /** Android delivers images only when the screen changes; a refresh on a still screen resends the last frame. */
    private var resendScheduled = false

    private fun resendIfAsked() {
        if (resendScheduled) return
        resendScheduled = true
        handler.postDelayed({
            resendScheduled = false
            val session = Remote.current ?: return@postDelayed
            val jpeg = lastJpeg
            if (session.refreshRequested && jpeg != null && session.wantsFrame()) session.sendFrame(jpeg, session.captureW, session.captureH)
            if (session.refreshRequested) resendIfAsked()
        }, 300)
    }

    override fun onDestroy() {
        runCatching { display?.release() }
        runCatching { reader?.close() }
        runCatching { projection?.stop() }
        projection = null
        thread.quitSafely()
        RemoteNotifications.cancelSharing(this)
        super.onDestroy()
    }
}

/** Taps, swipes, typing and Back/Home/Recents for remote control. Switched on by the user in Settings > Accessibility. */
class FenrirAccessibilityService : AccessibilityService() {
    companion object {
        @Volatile var instance: FenrirAccessibilityService? = null
    }

    override fun onServiceConnected() {
        super.onServiceConnected()
        instance = this
    }

    override fun onUnbind(intent: Intent?): Boolean {
        instance = null
        return super.onUnbind(intent)
    }

    override fun onDestroy() {
        instance = null
        super.onDestroy()
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) = Unit
    override fun onInterrupt() = Unit

    fun gesture(points: List<Point>, durationMs: Long) {
        if (points.isEmpty()) return
        val path = Path()
        path.moveTo(points[0].x.toFloat(), points[0].y.toFloat())
        for (p in points.drop(1)) path.lineTo(p.x.toFloat(), p.y.toFloat())
        val duration = durationMs.coerceIn(1, GestureDescription.getMaxGestureDuration())
        runCatching { dispatchGesture(GestureDescription.Builder().addStroke(GestureDescription.StrokeDescription(path, 0, duration)).build(), null, null) }
    }

    fun nav(action: String) {
        val global = when (action) {
            "back" -> GLOBAL_ACTION_BACK
            "home" -> GLOBAL_ACTION_HOME
            "recents" -> GLOBAL_ACTION_RECENTS
            "notifications" -> GLOBAL_ACTION_NOTIFICATIONS
            else -> return
        }
        performGlobalAction(global)
    }

    private fun focused(): AccessibilityNodeInfo? = rootInActiveWindow?.findFocus(AccessibilityNodeInfo.FOCUS_INPUT)

    private fun currentText(node: AccessibilityNodeInfo): String =
        if (Build.VERSION.SDK_INT >= 26 && node.isShowingHintText) "" else node.text?.toString() ?: ""

    private fun setText(node: AccessibilityNodeInfo, text: String) {
        val args = Bundle().apply { putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, text) }
        node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args)
    }

    fun type(text: String) {
        val node = focused() ?: return
        setText(node, currentText(node) + text)
    }

    fun backspace() {
        val node = focused() ?: return
        setText(node, currentText(node).dropLast(1))
    }

    fun enter() {
        val node = focused() ?: return
        if (Build.VERSION.SDK_INT >= 30) node.performAction(AccessibilityNodeInfo.AccessibilityAction.ACTION_IME_ENTER.id)
        else type("\n")
    }
}

object RemoteNotifications {
    private const val CHANNEL = "remote"
    const val ID_REQUEST = 20
    const val ID_SHARING = 21

    private fun channel(context: Context) {
        context.service<NotificationManager>().createNotificationChannel(
            NotificationChannel(CHANNEL, "Remote support", NotificationManager.IMPORTANCE_HIGH).apply {
                description = "When your IT team asks to see this phone's screen, and while it is shared."
            })
    }

    /** "IT wants to see your screen": tapping it opens Android's own screen-sharing prompt. */
    fun request(context: Context, technician: String) {
        channel(context)
        val open = PendingIntent.getActivity(context, 20, Intent(context, ScreenShareActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val notification = Notification.Builder(context, CHANNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("$technician wants to see your screen")
            .setContentText("Tap to allow screen sharing. Ignore this to decline.")
            .setCategory(Notification.CATEGORY_CALL)
            .setAutoCancel(true)
            .setContentIntent(open)
            .setFullScreenIntent(open, true)
            .build()
        context.service<NotificationManager>().notify(ID_REQUEST, notification)
    }

    fun cancelRequest(context: Context) = context.service<NotificationManager>().cancel(ID_REQUEST)

    fun sharing(context: Context): Notification {
        channel(context)
        return Notification.Builder(context, CHANNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("Sharing your screen with IT support")
            .setContentText("Tap Stop to end it at any time.")
            .setOngoing(true)
            .addAction(Notification.Action.Builder(null as android.graphics.drawable.Icon?, "Stop", ScreenCaptureService.stopIntent(context)).build())
            .build()
    }

    fun cancelSharing(context: Context) = context.service<NotificationManager>().cancel(ID_SHARING)
}

/**
 * The live connection the desktop agents also hold (/api/v1/devices/{id}/realtime): the server pushes "commands"
 * when something is queued for the phone (a remote session above all), instead of waiting for the next check-in.
 * Pings every 25 seconds keep the phone online in the console.
 */
class RealtimeLink(private val store: Store, private val onCommands: () -> Unit) {
    private var socket: WebSocket? = null
    @Volatile private var open = false
    @Volatile private var stopped = false
    private var lastAttempt = 0L
    private val pinger = Executors.newSingleThreadScheduledExecutor()

    init {
        pinger.scheduleWithFixedDelay({ if (open) socket?.send("ping") }, 25, 25, TimeUnit.SECONDS)
    }

    /** Called from the agent's cycle: connects when not connected (at most once a minute). */
    fun ensure() {
        if (stopped || open || !store.enrolled) return
        val now = System.currentTimeMillis()
        if (now - lastAttempt < 60_000) return
        lastAttempt = now
        val base = store.server.trimEnd('/')
        val url = (if (base.startsWith("https://")) "wss://" + base.removePrefix("https://") else "ws://" + base.removePrefix("http://")) +
            "/api/v1/devices/${store.deviceId}/realtime"
        val request = Request.Builder().url(url).header("X-Device-Api-Key", store.apiKey).header("User-Agent", "FenrirAndroid").build()
        socket = Remote.http.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) { open = true }
            override fun onMessage(webSocket: WebSocket, text: String) {
                if ("\"commands\"" in text || "\"pollNow\":true" in text) onCommands()
            }
            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) { open = false }
            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) { open = false }
        })
    }

    fun stop() {
        stopped = true
        open = false
        runCatching { socket?.close(1000, "stopping") }
        pinger.shutdownNow()
    }
}
