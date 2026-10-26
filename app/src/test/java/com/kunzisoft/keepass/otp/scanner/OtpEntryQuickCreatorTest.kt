package com.kunzisoft.keepass.otp.scanner

import com.kunzisoft.keepass.database.element.template.TemplateBuilder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class OtpEntryQuickCreatorTest {

    @Test
    fun parseStandardOtpAuthUriWithIssuerParam() {
        val uri = "otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&period=30&digits=6"
        val parsed = OtpEntryQuickCreator.parse(uri)

        assertNotNull(parsed)
        assertEquals("GitHub", parsed!!.displayTitle)
        assertEquals("alice@example.com", parsed.displayAccount)
        assertEquals(30, parsed.otpElement.period)
        assertEquals(6, parsed.otpElement.digits)

        val entry = OtpEntryQuickCreator.buildEntryInfo(parsed)
        assertEquals("GitHub", entry.title)
        assertEquals("alice@example.com", entry.username)
        assertEquals(TemplateBuilder.UUID_TOTP, entry.template?.uuid)
    }

    @Test
    fun parseOtpAuthUriWithEncodedPath() {
        val uri = "otpauth://totp/Google%3Abob%40gmail.com?secret=JBSWY3DPEHPK3PXP"
        val parsed = OtpEntryQuickCreator.parse(uri)

        assertNotNull(parsed)
        assertEquals("Google", parsed!!.displayTitle)
        assertEquals("bob@gmail.com", parsed.displayAccount)
    }

    @Test
    fun parseRawBase32SecretFallback() {
        val rawBase32 = "JBSWY3DPEHPK3PXP"
        val parsed = OtpEntryQuickCreator.parse(rawBase32)

        assertNotNull(parsed)
        assertTrue(parsed!!.rawUri.startsWith("otpauth://totp/Token?secret=JBSWY3DPEHPK3PXP"))
        assertEquals("Token", parsed.displayTitle)
    }

    @Test
    fun parseInvalidStringReturnsNull() {
        assertNull(OtpEntryQuickCreator.parse("https://www.google.com"))
        assertNull(OtpEntryQuickCreator.parse("plain text with spaces"))
        assertNull(OtpEntryQuickCreator.parse("123"))
    }
}
