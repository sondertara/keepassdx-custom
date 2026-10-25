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
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader
import java.nio.charset.StandardCharsets

/**
 * Importer for Proton Pass JSON export format.
 */
class ProtonPassJsonImporter : VaultImporter {

    override val id: String = "proton_pass_json"
    override val displayName: String = "Proton Pass (JSON)"
    override val supportedExtensions: List<String> = listOf("json")

    override fun parse(inputStream: InputStream): ImportBatchResult {
        val result = ImportBatchResult(sourceName = displayName)
        val jsonText = BufferedReader(InputStreamReader(inputStream, StandardCharsets.UTF_8)).use {
            it.readText()
        }

        val root = JSONObject(jsonText)

        // Support multiple vaults structure
        if (root.has("vaults")) {
            val vaults = root.getJSONArray("vaults")
            for (v in 0 until vaults.length()) {
                val vaultObj = vaults.getJSONObject(v)
                val vaultName = vaultObj.optString("name").ifEmpty { "Proton Vault $v" }
                val group = ImportedGroup(name = vaultName)
                result.groups.add(group)

                if (vaultObj.has("items")) {
                    parseItemsArray(vaultObj.getJSONArray("items"), group.entries)
                }
            }
        } else if (root.has("items")) {
            parseItemsArray(root.getJSONArray("items"), result.rootEntries)
        }

        result.recalculateStats()
        return result
    }

    private fun parseItemsArray(itemsArray: JSONArray, destination: MutableList<ImportedEntry>) {
        for (i in 0 until itemsArray.length()) {
            val itemObj = itemsArray.getJSONObject(i)
            val dataObj = itemObj.optJSONObject("data") ?: itemObj
            val metadataObj = dataObj.optJSONObject("metadata")
            val contentObj = dataObj.optJSONObject("content")

            val title = metadataObj?.optStringOrNull("name")
                ?: itemObj.optStringSafe("name", "")
            val notes = metadataObj?.optStringOrNull("note")
                ?: itemObj.optStringSafe("note", "")

            val entry = ImportedEntry(
                title = title,
                notes = notes
            )

            if (contentObj != null) {
                entry.username = contentObj.optStringSafe("username", "")
                entry.password = contentObj.optStringSafe("password", "").toCharArray()

                // URLs
                if (contentObj.has("urls")) {
                    val urlsArr = contentObj.getJSONArray("urls")
                    for (u in 0 until urlsArr.length()) {
                        val urlStr = urlsArr.optString(u)
                        if (urlStr.isNotEmpty() && !urlStr.equals("null", ignoreCase = true)) {
                            if (entry.url.isEmpty()) {
                                entry.url = urlStr
                            } else {
                                entry.additionalUrls.add(urlStr)
                            }
                        }
                    }
                }

                // TOTP
                val totp = contentObj.optStringOrNull("totpUri")
                if (!totp.isNullOrBlank()
                    && !totp.equals("null", ignoreCase = true)
                    && !totp.equals("none", ignoreCase = true)
                    && (totp.startsWith("otpauth://", ignoreCase = true) || totp.replace(" ", "").length >= 8)
                ) {
                    entry.totpUriOrSecret = totp.trim()
                }
            }

            destination.add(entry)
        }
    }
}
