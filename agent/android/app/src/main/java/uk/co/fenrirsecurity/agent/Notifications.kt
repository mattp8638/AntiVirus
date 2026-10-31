package uk.co.fenrirsecurity.agent

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent

object Notifications {
    const val STATUS = "status"
    const val MESSAGES = "messages"
    const val URGENT = "urgent"
    const val PROTECTION = "protection"

    const val ID_STATUS = 1
    const val ID_ALARM = 2
    const val ID_LOST = 3
    private const val ID_MESSAGE_BASE = 100
    private const val ID_APP_BASE = 1000

    fun createChannels(context: Context) {
        val manager = context.service<NotificationManager>()
        manager.createNotificationChannels(listOf(
            NotificationChannel(STATUS, "Protection status", NotificationManager.IMPORTANCE_LOW).apply {
                description = "Shows that Fenrir is connected. Android needs this to keep it running."
                setShowBadge(false)
            },
            NotificationChannel(MESSAGES, "Messages from IT", NotificationManager.IMPORTANCE_HIGH),
            NotificationChannel(URGENT, "Lost mode and alarm", NotificationManager.IMPORTANCE_HIGH).apply {
                description = "Lost-mode screen and the find-my-phone alarm."
                lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            },
            NotificationChannel(PROTECTION, "App protection", NotificationManager.IMPORTANCE_HIGH).apply {
                description = "Dangerous apps Fenrir finds on this phone."
            },
        ))
    }

    private fun openApp(context: Context): PendingIntent = PendingIntent.getActivity(
        context, 0, Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    fun status(context: Context, text: String): Notification =
        Notification.Builder(context, STATUS)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("Fenrir is protecting this phone")
            .setContentText(text)
            .setOngoing(true)
            .setContentIntent(openApp(context))
            .build()

    fun updateStatus(context: Context, text: String) =
        context.service<NotificationManager>().notify(ID_STATUS, status(context, text))

    fun message(context: Context, title: String, text: String) {
        val notification = Notification.Builder(context, MESSAGES)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(title.ifBlank { "Message from IT" })
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setAutoCancel(true)
            .setContentIntent(openApp(context))
            .build()
        context.service<NotificationManager>().notify(ID_MESSAGE_BASE + (System.currentTimeMillis() % 1000).toInt(), notification)
    }

    fun alarm(context: Context) {
        val stop = PendingIntent.getService(
            context, 1, Intent(context, AgentService::class.java).setAction(AgentService.ACTION_STOP_ALARM),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val notification = Notification.Builder(context, URGENT)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("Find my phone")
            .setContentText("Your IT team is ringing this phone. Tap Stop to silence it.")
            .setOngoing(true)
            .setCategory(Notification.CATEGORY_ALARM)
            .addAction(Notification.Action.Builder(null as android.graphics.drawable.Icon?, "Stop", stop).build())
            .setContentIntent(stop)
            .build()
        context.service<NotificationManager>().notify(ID_ALARM, notification)
    }

    /** Lost mode: a full-screen notification is the reliable way to put LostModeActivity over the lock screen. */
    fun lost(context: Context, message: String) {
        val screen = PendingIntent.getActivity(
            context, 2, Intent(context, LostModeActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val notification = Notification.Builder(context, URGENT)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("This phone has been reported lost")
            .setContentText(message)
            .setOngoing(true)
            .setCategory(Notification.CATEGORY_ALARM)
            .setVisibility(Notification.VISIBILITY_PUBLIC)
            .setFullScreenIntent(screen, true)
            .setContentIntent(screen)
            .build()
        context.service<NotificationManager>().notify(ID_LOST, notification)
    }

    /** A dangerous app: tapping opens Android's own "uninstall this app?" screen. */
    fun removeApp(context: Context, label: String, packageName: String, why: String) {
        val uninstall = PendingIntent.getActivity(
            context, packageName.hashCode(), AppScanner.uninstallIntent(packageName),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val notification = Notification.Builder(context, PROTECTION)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("Remove $label")
            .setContentText(why)
            .setStyle(Notification.BigTextStyle().bigText("$why Tap to remove it."))
            .setAutoCancel(true)
            .addAction(Notification.Action.Builder(null as android.graphics.drawable.Icon?, "Remove", uninstall).build())
            .setContentIntent(uninstall)
            .build()
        context.service<NotificationManager>().notify(ID_APP_BASE + (packageName.hashCode() and 0xffff), notification)
    }

    fun cancel(context: Context, id: Int) = context.service<NotificationManager>().cancel(id)
}
