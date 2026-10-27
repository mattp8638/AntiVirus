package uk.co.fenrirsecurity.agent.core

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ProtocolTest {
    @Test
    fun parsesConsoleQrLink() {
        val target = EnrollLink.parse("https://www.fenrir-security.co.uk/enroll-phone#t=fet_abc%2B123")
        assertEquals(EnrollTarget("https://www.fenrir-security.co.uk", "fet_abc+123"), target)
        assertEquals("http://localhost:8080", EnrollLink.parse("http://localhost:8080/enroll-phone#t=x")?.server)
    }

    @Test
    fun parsesAppLink() {
        val target = EnrollLink.parse("fenrir://enroll?server=https%3A%2F%2Ffenrir.example.com%2Fapi%2Fv1&token=fet_1")
        assertEquals(EnrollTarget("https://fenrir.example.com", "fet_1"), target)
    }

    @Test
    fun rejectsOtherLinks() {
        assertNull(EnrollLink.parse(""))
        assertNull(EnrollLink.parse("https://evil.example/login#t=fet_1"))
        assertNull(EnrollLink.parse("https://fenrir.example.com/enroll-phone"))
        assertNull(EnrollLink.parse("fenrir://enroll?server=https%3A%2F%2Fa.b"))
        assertNull(EnrollLink.parse("javascript:alert(1)"))
    }

    @Test
    fun normalisesTypedServer() {
        assertEquals("https://fenrir.example.com", EnrollLink.normaliseServer("fenrir.example.com/"))
        assertEquals("https://fenrir.example.com", EnrollLink.normaliseServer("https://fenrir.example.com/api/v1"))
        assertNull(EnrollLink.normaliseServer("  "))
    }

    @Test
    fun readsPendingCommands() {
        val body = JSONObject("""{"items":[{"id":"cmd1","type":"device.alarm","issuedBy":"jo","payloadJson":"{\"seconds\":500}"},
            {"id":"cmd2","type":"device.lock","payloadJson":""},{"type":"no-id"},{"id":"cmd3","type":"x","payloadJson":"not json"}]}""")
        val commands = Command.listFrom(body)
        assertEquals(listOf("cmd1", "cmd2", "cmd3"), commands.map { it.id })
        assertEquals(300, commands[0].int("seconds", 60, 5, 300))
        assertEquals(60, commands[1].int("seconds", 60, 5, 300))
        assertEquals(0, commands[2].payload.length())
    }

    @Test
    fun lostModeFromHeartbeat() {
        assertNull(LostMode.from(null))
        val lost = LostMode.from(JSONObject("""{"enabled":true,"message":"Call me","phone":"+44"}"""))!!
        assertTrue(lost.enabled)
        assertEquals("Call me", lost.message)
        assertFalse(LostMode.OFF.enabled)
    }

    @Test
    fun fixAndInventoryJson() {
        val fix = Fix(51.5, -0.12, 12f, null, null, "gps", "locate", 80, 0L).toJson()
        assertEquals("1970-01-01T00:00:00Z", fix.getString("at"))
        assertFalse(fix.has("altitude"))
        val event = Inventory.event("e1", listOf(Inventory.App("Zoom", "6.0", "zoom.us"), Inventory.App("authenticator", "1", "")),
            "Android", "15", "Google", "Pixel 8", 0L)
        assertEquals("inventory.snapshot", event.getString("eventType"))
        val payload = JSONObject(event.getString("payloadJson"))
        assertEquals("authenticator", payload.getJSONArray("software").getJSONObject(0).getString("name"))
    }

    // A full round trip against a running Fenrir Cloud, when FENRIR_TEST_SERVER and FENRIR_TEST_TOKEN are set.
    @Test
    fun liveRoundTrip() {
        val server = System.getenv("FENRIR_TEST_SERVER") ?: return
        val token = System.getenv("FENRIR_TEST_TOKEN") ?: return
        val api = ControlPlane(server)
        val enrolment = api.enroll(token, "JVM-Test-Phone", "Android 15 (JVM test)", "JVM-1", "0.1.0")
        assertTrue(enrolment.deviceId.startsWith("dev"))
        val metrics = JSONObject().put("batteryPercent", 77).put("charging", true).put("network", "Wi-Fi").put("screenLockSecure", true)
        val beat = api.heartbeat("0.1.0", metrics)
        assertFalse(beat.lostMode?.enabled ?: true)
        assertEquals(1, api.reportLocations(listOf(Fix(51.5, -0.12, 10f, null, null, "gps", "locate", 77, System.currentTimeMillis()))))
        api.telemetry(listOf(Inventory.event("evt-jvm-1", listOf(Inventory.App("Fenrir", "0.1.0", "Fenrir")), "Android", "15", "Google", "Pixel", System.currentTimeMillis())))
        assertEquals(0, api.pendingCommands().size)
    }
}
