package uk.co.fenrirsecurity.agent

import android.content.Context

/** A system service that every phone has (notification, power, location...). */
inline fun <reified T : Any> Context.service(): T =
    getSystemService(T::class.java) ?: error("${T::class.java.simpleName} is not available on this device")
