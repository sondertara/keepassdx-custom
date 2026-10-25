/*
 * Copyright 2026 Jeremy Jamet / Kunzisoft.
 *
 * This file is part of KeePassDX.
 *
 *  KeePassDX is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  KeePassDX is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with KeePassDX.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
package com.kunzisoft.keepass.importer

import com.kunzisoft.keepass.importer.parsers.GoogleAuthMigrationDecoder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.util.Base64

class GoogleAuthMigrationDecoderTest {

    private fun writeVarint(out: ByteArrayOutputStream, value: Long) {
        var v = value
        while (v >= 0x80) {
            out.write(((v and 0x7F) or 0x80).toInt())
            v = v ushr 7
        }
        out.write(v.toInt())
    }

    private fun buildOtpParameters(
        secret: ByteArray,
        name: String,
        issuer: String,
        algorithm: Int = 1,
        digits: Int = 1,
        type: Int = 2
    ): ByteArray {
        val out = ByteArrayOutputStream()

        // 1. Secret (field 1, wire 2)
        writeVarint(out, (1L shl 3) or 2L)
        writeVarint(out, secret.size.toLong())
        out.write(secret)

        // 2. Name (field 2, wire 2)
        val nameBytes = name.toByteArray(StandardCharsets.UTF_8)
        writeVarint(out, (2L shl 3) or 2L)
        writeVarint(out, nameBytes.size.toLong())
        out.write(nameBytes)

        // 3. Issuer (field 3, wire 2)
        val issuerBytes = issuer.toByteArray(StandardCharsets.UTF_8)
        writeVarint(out, (3L shl 3) or 2L)
        writeVarint(out, issuerBytes.size.toLong())
        out.write(issuerBytes)

        // 4. Algorithm (field 4, wire 0)
        writeVarint(out, (4L shl 3) or 0L)
        writeVarint(out, algorithm.toLong())

        // 5. Digits (field 5, wire 0)
        writeVarint(out, (5L shl 3) or 0L)
        writeVarint(out, digits.toLong())

        // 6. Type (field 6, wire 0)
        writeVarint(out, (6L shl 3) or 0L)
        writeVarint(out, type.toLong())

        return out.toByteArray()
    }

    private fun buildMigrationUri(otpParamList: List<ByteArray>): String {
        val outer = ByteArrayOutputStream()
        for (param in otpParamList) {
            // Field 1, wire 2
            writeVarint(outer, (1L shl 3) or 2L)
            writeVarint(outer, param.size.toLong())
            outer.write(param)
        }

        val b64 = Base64.getUrlEncoder().withoutPadding().encodeToString(outer.toByteArray())
        val encodedParam = URLEncoder.encode(b64, "UTF-8")
        return "otpauth-migration://offline?data=$encodedParam"
    }

    @Test
    fun testDetectMigrationUri() {
        assertTrue(GoogleAuthMigrationDecoder.isMigrationUri("otpauth-migration://offline?data=xyz"))
        assertTrue(GoogleAuthMigrationDecoder.isMigrationUri("  OTPAUTH-MIGRATION://offline?data=xyz "))
    }

    @Test
    fun testDecodeMigrationPayload() {
        val secretBytes = "Hello2FASecret12".toByteArray(StandardCharsets.UTF_8)
        val param1 = buildOtpParameters(secretBytes, "alice@gmail.com", "Google")
        val param2 = buildOtpParameters(secretBytes, "GitHub:bob", "GitHub", algorithm = 2, digits = 2)

        val uri = buildMigrationUri(listOf(param1, param2))

        val entries = GoogleAuthMigrationDecoder.decode(uri)
        assertEquals(2, entries.size)

        val entry1 = entries[0]
        assertEquals("Google", entry1.title)
        assertEquals("alice@gmail.com", entry1.username)
        assertNotNull(entry1.totpUriOrSecret)
        assertTrue(entry1.totpUriOrSecret!!.startsWith("otpauth://totp/Google:alice%40gmail.com"))
        assertTrue(entry1.totpUriOrSecret!!.contains("digits=6"))

        val entry2 = entries[1]
        assertEquals("GitHub", entry2.title)
        assertEquals("bob", entry2.username)
        assertTrue(entry2.totpUriOrSecret!!.contains("digits=8"))
        assertTrue(entry2.totpUriOrSecret!!.contains("algorithm=SHA256"))
    }
}
