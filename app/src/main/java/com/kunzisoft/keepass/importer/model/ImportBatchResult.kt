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

/**
 * Result of parsing a vault export file.
 */
data class ImportBatchResult(
    val sourceName: String,
    val groups: MutableList<ImportedGroup> = mutableListOf(),
    val rootEntries: MutableList<ImportedEntry> = mutableListOf(),
    var totalEntriesCount: Int = 0,
    var totpEntriesCount: Int = 0,
    val warnings: MutableList<String> = mutableListOf()
) {
    /**
     * Get all entries across root and all groups.
     */
    fun getAllEntries(): List<ImportedEntry> {
        val all = mutableListOf<ImportedEntry>()
        all.addAll(rootEntries)
        groups.forEach { group ->
            all.addAll(group.getAllEntries())
        }
        return all
    }

    /**
     * Recalculate statistics (total count and TOTP count).
     */
    fun recalculateStats() {
        val all = getAllEntries()
        totalEntriesCount = all.size
        totpEntriesCount = all.count { !it.totpUriOrSecret.isNullOrBlank() }
    }
}
