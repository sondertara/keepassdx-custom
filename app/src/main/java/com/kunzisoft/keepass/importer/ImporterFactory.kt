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

import com.kunzisoft.keepass.importer.parsers.BitwardenJsonImporter
import com.kunzisoft.keepass.importer.parsers.ChromeCsvImporter
import com.kunzisoft.keepass.importer.parsers.GenericCsvImporter
import com.kunzisoft.keepass.importer.parsers.GoogleAuthMigrationDecoder
import com.kunzisoft.keepass.importer.parsers.GoogleAuthMigrationImporter
import com.kunzisoft.keepass.importer.parsers.OnePasswordCsvImporter
import com.kunzisoft.keepass.importer.parsers.ProtonPassJsonImporter
import com.kunzisoft.keepass.importer.parsers.VaultImporter
import java.util.Locale

/**
 * Factory and registry for all supported vault importers.
 */
object ImporterFactory {

    val allImporters: List<VaultImporter> = listOf(
        BitwardenJsonImporter(),
        ProtonPassJsonImporter(),
        OnePasswordCsvImporter(),
        ChromeCsvImporter(),
        GenericCsvImporter(),
        GoogleAuthMigrationImporter()
    )

    fun getImporterById(id: String): VaultImporter? {
        return allImporters.firstOrNull { it.id == id }
    }

    /**
     * Detect the most appropriate importer based on filename and preview of the first few bytes/lines.
     */
    fun detectImporter(fileName: String, previewText: String): VaultImporter {
        val lowerName = fileName.lowercase(Locale.ROOT)
        val cleanPreview = previewText.removePrefix("\uFEFF").trim()
        val lowerPreview = cleanPreview.lowercase(Locale.ROOT)

        // 1. Google Authenticator Migration check
        if (lowerPreview.contains(GoogleAuthMigrationDecoder.SCHEME_PREFIX)) {
            return GoogleAuthMigrationImporter()
        }

        // 2. JSON check
        if (lowerName.endsWith(".json") || cleanPreview.startsWith("{")) {
            if (lowerPreview.contains("\"folders\"") || lowerPreview.contains("\"items\"") || lowerPreview.contains("\"bitwarden\"")) {
                return BitwardenJsonImporter()
            }
            if (lowerPreview.contains("\"vaults\"") || lowerPreview.contains("\"proton\"")) {
                return ProtonPassJsonImporter()
            }
            // Default JSON
            return BitwardenJsonImporter()
        }

        // 3. CSV check
        val firstLine = cleanPreview.lineSequence().firstOrNull()?.trim()?.lowercase(Locale.ROOT) ?: ""

        // Google Chrome / Google Password Manager / Chromium
        if (firstLine.contains("name,url,username,password")
            || firstLine.contains("名称,网址,用户名,密码")
            || firstLine.contains("chrome")
            || lowerName.contains("chrome")
            || lowerName.contains("google")
            || ((lowerName.contains("password") || lowerName.contains("密码")) && firstLine.contains("name,url"))
        ) {
            return ChromeCsvImporter()
        }

        // 1Password
        if (firstLine.contains("1password")
            || firstLine.contains("type,title,notes")
            || firstLine.contains("fields,")
            || lowerName.contains("1password")
        ) {
            return OnePasswordCsvImporter()
        }

        return GenericCsvImporter()
    }
}
