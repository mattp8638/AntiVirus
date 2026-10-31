package uk.co.fenrirsecurity.agent.core

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppRiskTest {
    private fun app(
        installer: String? = "com.android.vending", permissions: Set<String> = emptySet(), accessibility: Boolean = false,
        icon: Boolean = true, system: Boolean = false, admin: Boolean = false,
    ) = AppFacts("com.example.app", "Example", "1.0", installer, system, "ab".repeat(32), "cd".repeat(32), permissions,
        accessibility, admin, false, icon, false, 0L, 0L)

    @Test
    fun aStoreAppWithOrdinaryPermissionsIsLowRisk() {
        val result = AppRisk.assess(app(permissions = setOf(AppRisk.CAMERA)))
        assertEquals("low", result.level)
        assertEquals(0, result.score)
    }

    @Test
    fun sideloadingAloneIsNotEnoughToAlarm() {
        val result = AppRisk.assess(app(installer = "com.android.chrome"))
        assertEquals("low", result.level)
        assertTrue(result.reasons.single().contains("by com.android.chrome"))
    }

    @Test
    fun theBankingTrojanPatternIsHighRisk() {
        val result = AppRisk.assess(app(installer = "com.android.chrome", accessibility = true,
            permissions = setOf(AppRisk.READ_SMS, AppRisk.OVERLAY)))
        assertEquals("high", result.level)
        assertTrue(result.reasons.any { it.startsWith("Matches banking trojans") })
    }

    @Test
    fun theStalkerwarePatternIsHighRisk() {
        val result = AppRisk.assess(app(installer = null, icon = false,
            permissions = setOf(AppRisk.RECORD_AUDIO, AppRisk.READ_CALL_LOG, AppRisk.BACKGROUND_LOCATION)))
        assertEquals("high", result.level)
        assertTrue(result.reasons.any { it.startsWith("Matches stalkerware") })
    }

    @Test
    fun updatedSystemAppsAreNotSideloaded() {
        assertFalse(AppRisk.sideloaded(app(installer = null, system = true)))
        assertTrue(AppRisk.sideloaded(app(installer = null)))
        assertTrue(AppRisk.sideloaded(app(installer = "com.example.mdm")))
        assertFalse(AppRisk.sideloaded(app(installer = "com.example.mdm"), AppRisk.TRUSTED_INSTALLERS + "com.example.mdm"))
    }

    @Test
    fun scoresAreCappedAt100() {
        val result = AppRisk.assess(app(installer = null, icon = false, accessibility = true, admin = true,
            permissions = AppRisk.NOTABLE))
        assertEquals(100, result.score)
    }

    @Test
    fun theReportCarriesOnlyNotablePermissionsAndTheVerdictInputs() {
        val facts = app(installer = "com.android.chrome", permissions = setOf(AppRisk.READ_SMS, "android.permission.INTERNET"))
        val json = AppRisk.toJson(facts, AppRisk.assess(facts))
        assertEquals("com.example.app", json.getString("package"))
        assertTrue(json.getBoolean("sideloaded"))
        assertEquals(1, json.getJSONArray("permissions").length())
        assertEquals("ab".repeat(32), json.getString("sha256"))
        assertEquals("medium", json.getJSONObject("risk").getString("level"))
    }

    @Test
    fun theEventIsWhatTheCloudReads() {
        val facts = app()
        val event = AppRisk.event("e1", listOf(AppRisk.toJson(facts, AppRisk.assess(facts))), true, 0L)
        assertEquals("mobile.apps.assessed", event.getString("eventType"))
        val payload = JSONObject(event.getString("payloadJson"))
        assertTrue(payload.getBoolean("full"))
        assertEquals(1, payload.getJSONArray("apps").length())
        val removed = AppRisk.removedEvent("e2", "com.example.app", 0L)
        assertEquals("com.example.app", JSONObject(removed.getString("payloadJson")).getString("package"))
    }

    @Test
    fun hexIsLowerCase() {
        assertEquals("00ff10", AppRisk.hex(byteArrayOf(0, -1, 16)))
    }
}
