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

import com.kunzisoft.keepass.importer.model.ImportBatchResult
import com.kunzisoft.keepass.importer.model.ImportedGroup
import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader
import java.nio.charset.StandardCharsets

/**
 * Importer for Google Authenticator migration payload or text exports.
 */
class GoogleAuthMigrationImporter : VaultImporter {

    override val id: String = "google_auth_migration"
    override val displayName: String = "Google Authenticator (2FA 迁移协议)"
    override val supportedExtensions: List<String> = listOf("txt", "data")

    override fun parse(inputStream: InputStream): ImportBatchResult {
        val result = ImportBatchResult(sourceName = displayName)
        val reader = BufferedReader(InputStreamReader(inputStream, StandardCharsets.UTF_8))
        val group = ImportedGroup(name = "Google Authenticator")

        reader.useLines { lines ->
            lines.forEach { line ->
                val trimmed = line.trim()
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    return@forEach
                }

                if (GoogleAuthMigrationDecoder.isMigrationUri(trimmed)) {
                    val decodedEntries = GoogleAuthMigrationDecoder.decode(trimmed)
                    group.entries.addAll(decodedEntries)
                }
            }
        }

        if (group.entries.isNotEmpty()) {
            result.groups.add(group)
        }

        result.recalculateStats()
        return result
    }
}
