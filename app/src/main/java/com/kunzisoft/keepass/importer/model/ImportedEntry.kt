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
package com.kunzisoft.keepass.importer.model

import com.kunzisoft.keepass.database.element.Field
import com.kunzisoft.keepass.database.element.security.ProtectedString
import com.kunzisoft.keepass.model.EntryInfo
import com.kunzisoft.keepass.otp.OtpEntryFields.setOtp
import java.util.Arrays

/**
 * In-memory representation of an imported vault entry from any third-party provider.
 */
data class ImportedEntry(
    var title: String = "",
    var username: String = "",
    var password: CharArray = CharArray(0),
    var url: String = "",
    val additionalUrls: MutableList<String> = mutableListOf(),
    var notes: String = "",
    var totpUriOrSecret: String? = null,
    var folderPath: String? = null,
    val customFields: MutableMap<String, Pair<String, Boolean>> = mutableMapOf(),
    val tags: MutableList<String> = mutableListOf()
) {

    /**
     * Securely zero-out password memory after conversion into ProtectedString.
     */
    fun clearSensitive() {
        Arrays.fill(password, '\u0000')
    }

    /**
     * Convert this in-memory imported entry into a KeePassDX [EntryInfo].
     */
    fun toEntryInfo(): EntryInfo {
        val entry = EntryInfo().apply {
            this.title = this@ImportedEntry.title.ifEmpty { "Imported Entry" }
            this.username = this@ImportedEntry.username
            this.password = this@ImportedEntry.password.clone()
            this.url = this@ImportedEntry.url
            this.notes = this@ImportedEntry.notes

            this@ImportedEntry.tags.forEach { tag ->
                if (tag.isNotEmpty()) {
                    this.tags.put(tag)
                }
            }

            // Additional URLs (URL_1, URL_2...)
            this@ImportedEntry.additionalUrls.forEachIndexed { index, extraUrl ->
                if (extraUrl.isNotEmpty()) {
                    val fieldName = "URL_${index + 1}"
                    this.addOrReplaceField(
                        Field(fieldName, ProtectedString(enableProtection = false, extraUrl))
                    )
                }
            }

            // Custom fields
            this@ImportedEntry.customFields.forEach { (fieldName, pair) ->
                val (value, isProtected) = pair
                if (fieldName.isNotEmpty() && value.isNotEmpty()) {
                    this.addOrReplaceField(
                        Field(fieldName, ProtectedString(enableProtection = isProtected, value))
                    )
                }
            }

            // Setup OTP if present
            this@ImportedEntry.totpUriOrSecret?.let { totpStr ->
                if (totpStr.isNotEmpty()) {
                    val formatted = if (totpStr.startsWith("otpauth://", ignoreCase = true)) {
                        totpStr
                    } else {
                        "otpauth://totp/${this.title}?secret=${totpStr.replace(" ", "")}"
                    }
                    this.setOtp(formatted, addTag = true)
                }
            }
        }

        clearSensitive()
        return entry
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ImportedEntry
        if (title != other.title) return false
        if (username != other.username) return false
        if (!password.contentEquals(other.password)) return false
        if (url != other.url) return false
        if (notes != other.notes) return false
        if (totpUriOrSecret != other.totpUriOrSecret) return false
        if (folderPath != other.folderPath) return false

        return true
    }

    override fun hashCode(): Int {
        var result = title.hashCode()
        result = 31 * result + username.hashCode()
        result = 31 * result + password.contentHashCode()
        result = 31 * result + url.hashCode()
        result = 31 * result + notes.hashCode()
        result = 31 * result + (totpUriOrSecret?.hashCode() ?: 0)
        result = 31 * result + (folderPath?.hashCode() ?: 0)
        return result
    }
}
