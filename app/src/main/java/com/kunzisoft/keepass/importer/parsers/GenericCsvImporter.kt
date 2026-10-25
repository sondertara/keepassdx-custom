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
import com.kunzisoft.keepass.importer.model.ImportedEntry
import com.kunzisoft.keepass.importer.model.ImportedGroup
import java.io.InputStream
import java.util.Locale

/**
 * Universal CSV Importer with fuzzy column matching.
 * Works with KeePassXC, 1Password, Chrome, Bitwarden, and custom spreadsheets.
 */
open class GenericCsvImporter(
    override val id: String = "generic_csv",
    override val displayName: String = "Generic / KeePassXC (CSV)",
    override val supportedExtensions: List<String> = listOf("csv")
) : VaultImporter {

    override fun parse(inputStream: InputStream): ImportBatchResult {
        val result = ImportBatchResult(sourceName = displayName)
        val records = CsvReader.parse(inputStream)

        if (records.isEmpty()) {
            return result
        }

        val headers = records[0].map { it.trim().lowercase(Locale.US) }
        val titleIdx = findHeaderIndex(headers, listOf("title", "name", "account", "label", "website name"))
        val usernameIdx = findHeaderIndex(headers, listOf("username", "user", "login", "email", "login name", "account name"))
        val passwordIdx = findHeaderIndex(headers, listOf("password", "pass", "login password"))
        val urlIdx = findHeaderIndex(headers, listOf("url", "website", "web", "uri", "login url", "site"))
        val notesIdx = findHeaderIndex(headers, listOf("notes", "note", "comment", "comments", "extra"))
        val groupIdx = findHeaderIndex(headers, listOf("group", "folder", "category", "group path"))
        val totpIdx = findHeaderIndex(headers, listOf("totp", "otp", "one-time password", "otpauth", "verification code", "2fa"))

        val groupMap = mutableMapOf<String, ImportedGroup>()

        for (rowIdx in 1 until records.size) {
            val row = records[rowIdx]
            if (row.all { it.isBlank() }) continue

            val title = getCell(row, titleIdx)
            val username = getCell(row, usernameIdx)
            val password = getCell(row, passwordIdx)
            val url = getCell(row, urlIdx)
            val notes = getCell(row, notesIdx)
            val groupName = getCell(row, groupIdx)
            val totp = getCell(row, totpIdx)

            val entry = ImportedEntry(
                title = title.ifEmpty { url.ifEmpty { "Entry $rowIdx" } },
                username = username,
                password = password.toCharArray(),
                url = url,
                notes = notes,
                totpUriOrSecret = totp.takeIf { it.isNotEmpty() },
                folderPath = groupName.takeIf { it.isNotEmpty() }
            )

            // Save other unmatched columns as custom fields
            headers.forEachIndexed { colIdx, colName ->
                if (colIdx !in listOf(titleIdx, usernameIdx, passwordIdx, urlIdx, notesIdx, groupIdx, totpIdx)
                    && colIdx < row.size) {
                    val value = row[colIdx].trim()
                    if (value.isNotEmpty()) {
                        entry.customFields[colName] = Pair(value, false)
                    }
                }
            }

            if (groupName.isNotEmpty()) {
                val group = groupMap.getOrPut(groupName) {
                    val g = ImportedGroup(name = groupName)
                    result.groups.add(g)
                    g
                }
                group.entries.add(entry)
            } else {
                result.rootEntries.add(entry)
            }
        }

        result.recalculateStats()
        return result
    }

    private fun findHeaderIndex(headers: List<String>, candidates: List<String>): Int {
        for (candidate in candidates) {
            val idx = headers.indexOf(candidate)
            if (idx != -1) return idx
        }
        for (candidate in candidates) {
            val idx = headers.indexOfFirst { it.contains(candidate) }
            if (idx != -1) return idx
        }
        return -1
    }

    private fun getCell(row: List<String>, index: Int): String {
        return if (index >= 0 && index < row.size) row[index].trim() else ""
    }
}
