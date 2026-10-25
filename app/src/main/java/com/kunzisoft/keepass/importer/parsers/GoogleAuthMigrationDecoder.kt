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
package com.kunzisoft.keepass.importer.parsers

import android.util.Base64
import android.util.Log
import com.kunzisoft.keepass.importer.model.ImportedEntry
import com.kunzisoft.keepass.utils.CodecUtil
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

/**
 * Pure Kotlin, zero-dependency protobuf parser for Google Authenticator migration payload:
 * otpauth-migration://offline?data=...
 */
object GoogleAuthMigrationDecoder {

    private const val TAG = "GoogleAuthMigration"
    const val SCHEME_PREFIX = "otpauth-migration://offline"

    fun isMigrationUri(uriString: String): Boolean {
        return uriString.trim().startsWith(SCHEME_PREFIX, ignoreCase = true)
    }

    /**
     * Decode migration URI into a list of [ImportedEntry].
     */
    fun decode(uriString: String): List<ImportedEntry> {
        val trimmed = uriString.trim()
        val queryIdx = trimmed.indexOf("data=")
        val dataParam = if (queryIdx != -1) {
            val afterData = trimmed.substring(queryIdx + 5)
            val ampIdx = afterData.indexOf('&')
            if (ampIdx != -1) afterData.substring(0, ampIdx) else afterData
        } else {
            return emptyList()
        }

        val decodedData = try {
            URLDecoder.decode(dataParam, StandardCharsets.UTF_8.name())
        } catch (e: Exception) {
            dataParam
        }

        val protoBytes = try {
            decodeBase64(decodedData)
        } catch (e: Exception) {
            safeLog("Base64 decode failed for migration data", e)
            return emptyList()
        }

        return parseMigrationPayload(protoBytes)
    }

    private fun decodeBase64(data: String): ByteArray {
        return try {
            Base64.decode(data, Base64.DEFAULT or Base64.URL_SAFE)
        } catch (e: Throwable) {
            // JVM unit test fallback
            try {
                java.util.Base64.getUrlDecoder().decode(data)
            } catch (e2: Exception) {
                java.util.Base64.getDecoder().decode(data)
            }
        }
    }

    private fun urlEncode(str: String): String {
        return try {
            URLEncoder.encode(str, StandardCharsets.UTF_8.name()).replace("+", "%20")
        } catch (e: Exception) {
            str
        }
    }

    private fun safeLog(msg: String, e: Throwable? = null) {
        try {
            Log.e(TAG, msg, e)
        } catch (t: Throwable) {
            System.err.println("$TAG: $msg ${e?.message ?: ""}")
        }
    }

    private fun parseMigrationPayload(bytes: ByteArray): List<ImportedEntry> {
        val entries = mutableListOf<ImportedEntry>()
        val stream = ByteArrayInputStream(bytes)

        while (stream.available() > 0) {
            val tagAndType = readVarint(stream) ?: break
            val fieldNumber = (tagAndType ushr 3).toInt()
            val wireType = (tagAndType and 0x07).toInt()

            if (fieldNumber == 1 && wireType == 2) {
                // OtpParameters message
                val length = readVarint(stream)?.toInt() ?: break
                val messageBytes = ByteArray(length)
                stream.read(messageBytes)
                parseOtpParameters(messageBytes)?.let { entry ->
                    entries.add(entry)
                }
            } else {
                skipField(stream, wireType)
            }
        }

        return entries
    }

    private fun parseOtpParameters(bytes: ByteArray): ImportedEntry? {
        val stream = ByteArrayInputStream(bytes)
        var secret: ByteArray? = null
        var name = ""
        var issuer = ""
        var algorithm = 1 // 1: SHA1, 2: SHA256, 3: SHA512
        var digits = 1 // 1: 6 digits, 2: 8 digits
        var type = 2 // 1: HOTP, 2: TOTP
        var counter = 0L

        while (stream.available() > 0) {
            val tagAndType = readVarint(stream) ?: break
            val fieldNumber = (tagAndType ushr 3).toInt()
            val wireType = (tagAndType and 0x07).toInt()

            when (fieldNumber) {
                1 -> { // secret (bytes)
                    val len = readVarint(stream)?.toInt() ?: break
                    secret = ByteArray(len)
                    stream.read(secret)
                }
                2 -> { // name (string)
                    val len = readVarint(stream)?.toInt() ?: break
                    val strBytes = ByteArray(len)
                    stream.read(strBytes)
                    name = String(strBytes, StandardCharsets.UTF_8)
                }
                3 -> { // issuer (string)
                    val len = readVarint(stream)?.toInt() ?: break
                    val strBytes = ByteArray(len)
                    stream.read(strBytes)
                    issuer = String(strBytes, StandardCharsets.UTF_8)
                }
                4 -> { // algorithm
                    algorithm = readVarint(stream)?.toInt() ?: 1
                }
                5 -> { // digits
                    digits = readVarint(stream)?.toInt() ?: 1
                }
                6 -> { // type
                    type = readVarint(stream)?.toInt() ?: 2
                }
                7 -> { // counter
                    counter = readVarint(stream) ?: 0L
                }
                else -> skipField(stream, wireType)
            }
        }

        if (secret == null || secret.isEmpty()) return null

        val base32Secret = String(CodecUtil.encodeBase32(secret))

        // Determine title and username
        var finalTitle = issuer
        var finalUsername = name

        if (name.contains(":")) {
            val parts = name.split(":", limit = 2)
            if (finalTitle.isEmpty()) {
                finalTitle = parts[0].trim()
            }
            finalUsername = parts[1].trim()
        }

        if (finalTitle.isEmpty()) {
            finalTitle = if (finalUsername.isNotEmpty()) finalUsername else "2FA Token"
        }

        val digitsCount = if (digits == 2) 8 else 6
        val algoString = when (algorithm) {
            2 -> "SHA256"
            3 -> "SHA512"
            else -> "SHA1"
        }

        val otpTypeStr = if (type == 1) "hotp" else "totp"
        val otpUri = buildString {
            append("otpauth://$otpTypeStr/")
            append(urlEncode(finalTitle))
            if (finalUsername.isNotEmpty() && finalUsername != finalTitle) {
                append(":")
                append(urlEncode(finalUsername))
            }
            append("?secret=").append(base32Secret)
            if (issuer.isNotEmpty()) {
                append("&issuer=").append(urlEncode(issuer))
            }
            append("&algorithm=").append(algoString)
            append("&digits=").append(digitsCount)
            if (type == 1) {
                append("&counter=").append(counter)
            } else {
                append("&period=30")
            }
        }

        return ImportedEntry(
            title = finalTitle,
            username = finalUsername,
            totpUriOrSecret = otpUri,
            tags = mutableListOf("2FA")
        )
    }

    private fun readVarint(stream: InputStream): Long? {
        var result = 0L
        var shift = 0
        while (shift < 64) {
            val b = stream.read()
            if (b == -1) return null
            result = result or ((b and 0x7F).toLong() shl shift)
            if ((b and 0x80) == 0) {
                return result
            }
            shift += 7
        }
        return null
    }

    private fun skipField(stream: InputStream, wireType: Int) {
        when (wireType) {
            0 -> readVarint(stream) // Varint
            1 -> stream.skip(8)     // 64-bit
            2 -> {                  // Length-delimited
                val len = readVarint(stream) ?: 0L
                stream.skip(len)
            }
            5 -> stream.skip(4)     // 32-bit
            else -> {}
        }
    }
}
