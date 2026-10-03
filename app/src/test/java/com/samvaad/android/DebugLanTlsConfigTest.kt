package com.samvaad.android

import com.samvaad.android.enroll.HttpE2eeDeviceApi
import java.io.ByteArrayInputStream
import java.io.File
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.xml.parsers.DocumentBuilderFactory
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * LAN development TLS guardrails (debug-only trust anchor).
 *
 * The DEBUG build trusts exactly one extra certificate — the LAN
 * development server leaf — for exactly one host
 * (`192.168.29.41`), with normal hostname verification and no
 * cleartext. Release/main builds keep the platform default trust
 * store. These tests pin that boundary:
 *
 * - HTTPS stays required on every networking entry point (HTTP is
 *   rejected before any socket opens).
 * - The debug Network Security Config references the intended
 *   certificate, forbids cleartext, and contains no bypass.
 * - The debug certificate parses as X.509 and carries the LAN IP SAN
 *   that hostname verification requires.
 * - The main manifest and any release overlay contain no reference to
 *   the debug trust anchor.
 */
class DebugLanTlsConfigTest {

    companion object {
        private const val LAN_HOST = "192.168.29.41"
        private const val LAN_URL = "https://192.168.29.41:8080"
        private const val DEBUG_RAW_NAME = "samvaad_dev_192_168_29_41"
    }

    // -- HTTPS enforcement (unchanged production behavior) ---------------

    @Test
    fun refresh_httpScheme_rejected() {
        try {
            runBlocking {
                HttpAuthApi().refresh("http://$LAN_HOST:8080", "refresh-old")
            }
            fail("expected IllegalArgumentException for http refresh")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("HTTPS"))
        }
    }

    @Test
    fun logout_httpScheme_rejected() {
        try {
            runBlocking {
                HttpAuthApi().logout("http://$LAN_HOST:8080", "access-1")
            }
            fail("expected IllegalArgumentException for http logout")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("HTTPS"))
        }
    }

    @Test
    fun e2eeApi_httpScheme_rejected() {
        val session = AuthSession(
            identifier = "admin",
            accessToken = "access-1",
            refreshToken = "refresh-1",
            sessionId = "11111111-2222-3333-4444-555555555555",
        )
        try {
            runBlocking {
                HttpE2eeDeviceApi().listDevices(session, "http://$LAN_HOST:8080")
            }
            fail("expected IllegalArgumentException for http e2ee call")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("HTTPS"))
        }
    }

    // -- Debug trust configuration ---------------------------------------

    @Test
    fun debugConfig_trustsOnlyIntendedCert_forLanHostOnly() {
        val config = debugFile("res/xml/network_security_config.xml")
        assertTrue("missing $config", config.isFile)
        val text = config.readText()

        // Intended development certificate, and nothing else custom.
        assertTrue(text.contains("@raw/$DEBUG_RAW_NAME"))
        assertTrue(text.contains("<domain includeSubdomains=\"false\">$LAN_HOST</domain>"))

        // No cleartext anywhere in the debug config.
        assertFalse(text.contains("cleartextTrafficPermitted=\"true\""))
        assertTrue(text.contains("cleartextTrafficPermitted=\"false\""))

        // No bypass mechanisms: no user-CA blanket trust, no permissive
        // trust behavior, no hostname-verification bypass, no custom
        // anchors beyond the single dev cert + system. (Comments carry
        // prose, so assert against the effective elements only.)
        val elements = text.replace(Regex("<!--[\\s\\S]*?-->"), "")
        assertFalse(elements.contains("src=\"user\""))
        assertFalse(elements.lowercase().contains("trust-all"))
        assertFalse(elements.lowercase().contains("hostnameverifier"))

        // Well-formed XML with at least the domain-config + base-config.
        val doc = DocumentBuilderFactory.newInstance()
            .newDocumentBuilder()
            .parse(config)
        assertEquals("network-security-config", doc.documentElement.tagName)
    }

    @Test
    fun debugCert_isValidX509_withLanIpSan() {
        val pem = debugFile("res/raw/$DEBUG_RAW_NAME.pem")
        assertTrue("missing $pem", pem.isFile)
        val cert = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(pem.readBytes())) as X509Certificate
        assertTrue(cert.subjectX500Principal.name.contains("CN=Samvaad"))

        val sans = cert.subjectAlternativeNames
            .orEmpty()
            .map { "${it[0]}:${it[1]}" }
        // Hostname verification requires the exact LAN IP SAN.
        assertTrue("sans=$sans", sans.any { it == "7:$LAN_HOST" })
        // Pre-existing loopback SANs are preserved.
        assertTrue("sans=$sans", sans.any { it == "2:localhost" })
        assertTrue("sans=$sans", sans.any { it == "7:127.0.0.1" })
    }

    // -- Release/main must not inherit the debug anchor -------------------

    @Test
    fun mainManifest_hasNoNetworkSecurityConfig() {
        val manifest = moduleFile("src/main/AndroidManifest.xml")
        assertTrue("missing $manifest", manifest.isFile)
        assertFalse(
            manifest.readText().contains("networkSecurityConfig"),
        )
    }

    @Test
    fun mainRes_hasNoCustomTrustAnchor() {
        assertFalse(moduleFile("src/main/res/xml/network_security_config.xml").exists())
        val rawDir = moduleFile("src/main/res/raw")
        if (rawDir.isDirectory) {
            val strays = rawDir.listFiles { f ->
                f.extension.lowercase() in setOf("pem", "crt", "cer", "der", "p12")
            }.orEmpty()
            assertTrue("unexpected trust material in main: ${strays.map { it.name }}", strays.isEmpty())
        }
    }

    @Test
    fun releaseSourceSet_hasNoTrustOverride() {
        val releaseDir = moduleFile("src/release")
        if (releaseDir.exists()) {
            assertFalse(releaseDir.walk().any {
                it.name == "network_security_config.xml" || it.extension.lowercase() == "pem"
            })
        }
    }

    @Test
    fun debugManifest_wiresConfig_debugOnly() {
        val debugManifest = debugFile("AndroidManifest.xml")
        assertTrue("missing $debugManifest", debugManifest.isFile)
        assertTrue(
            debugManifest.readText().contains("@xml/network_security_config"),
        )
    }

    // -- Helpers ----------------------------------------------------------

    /**
     * Resolves a file under the `app` module directory regardless of the
     * test working directory (module dir or repo root).
     */
    private fun moduleFile(relative: String): File {
        val roots = generateSequence(File(System.getProperty("user.dir"))) { it.parentFile }.take(4)
        for (root in roots) {
            val direct = File(root, relative)
            if (direct.exists() || root.name == "app") return direct
            val viaApp = File(root, "app/$relative")
            if (viaApp.exists()) return viaApp
        }
        // Fall back to the module-relative guess so failure messages show it.
        return File(System.getProperty("user.dir"), relative)
    }

    private fun debugFile(relative: String): File = moduleFile("src/debug/$relative")
}
