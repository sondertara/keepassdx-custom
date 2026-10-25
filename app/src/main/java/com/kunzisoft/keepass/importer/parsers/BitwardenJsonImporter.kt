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
 * Importer for Bitwarden standard JSON export.
 */
class BitwardenJsonImporter : VaultImporter {

    override val id: String = "bitwarden_json"
    override val displayName: String = "Bitwarden (JSON)"
    override val supportedExtensions: List<String> = listOf("json")

    override fun parse(inputStream: InputStream): ImportBatchResult {
        val result = ImportBatchResult(sourceName = displayName)
        val jsonText = BufferedReader(InputStreamReader(inputStream, StandardCharsets.UTF_8)).use {
            it.readText()
        }

        val root = JSONObject(jsonText)

        // Parse folders mapping
        val folderMap = mutableMapOf<String, ImportedGroup>()
        if (root.has("folders")) {
            val foldersArray = root.getJSONArray("folders")
            for (i in 0 until foldersArray.length()) {
                val folderObj = foldersArray.getJSONObject(i)
                val fId = folderObj.optString("id")
                val fName = folderObj.optString("name").ifEmpty { "Folder $i" }
                if (fId.isNotEmpty()) {
                    val group = ImportedGroup(name = fName)
                    folderMap[fId] = group
                    result.groups.add(group)
                }
            }
        }

        // Parse vault items
        if (root.has("items")) {
            val itemsArray = root.getJSONArray("items")
            for (i in 0 until itemsArray.length()) {
                val itemObj = itemsArray.getJSONObject(i)
                val type = itemObj.optInt("type", 1) // 1: Login, 2: Note, 3: Card, 4: Identity
                val name = itemObj.optString("name")
                val notes = itemObj.optString("notes")
                val folderId = itemObj.optString("folderId", "")

                val entry = ImportedEntry(
                    title = name,
                    notes = notes
                )

                when (type) {
                    1 -> { // Login
                        if (itemObj.has("login")) {
                            val loginObj = itemObj.getJSONObject("login")
                            entry.username = loginObj.optString("username")
                            entry.password = loginObj.optString("password").toCharArray()

                            // URIs
                            if (loginObj.has("uris")) {
                                val urisArray = loginObj.getJSONArray("uris")
                                for (u in 0 until urisArray.length()) {
                                    val uObj = urisArray.getJSONObject(u)
                                    val uri = uObj.optString("uri")
                                    if (uri.isNotEmpty()) {
                                        if (entry.url.isEmpty()) {
                                            entry.url = uri
                                        } else {
                                            entry.additionalUrls.add(uri)
                                        }
                                    }
                                }
                            }

                            // TOTP
                            val totp = loginObj.optString("totp", "")
                            if (totp.isNotEmpty()) {
                                entry.totpUriOrSecret = totp
                            }
                        }
                    }
                    2 -> { // Secure Note
                        entry.tags.add("Secure Note")
                    }
                    3 -> { // Credit Card
                        entry.tags.add("Credit Card")
                        if (itemObj.has("card")) {
                            val cardObj = itemObj.getJSONObject("card")
                            cardObj.optString("cardholderName").takeIf { it.isNotEmpty() }?.let {
                                entry.customFields["Cardholder"] = Pair(it, false)
                            }
                            cardObj.optString("number").takeIf { it.isNotEmpty() }?.let {
                                entry.customFields["CardNumber"] = Pair(it, true)
                            }
                            cardObj.optString("expMonth").takeIf { it.isNotEmpty() }?.let {
                                entry.customFields["ExpMonth"] = Pair(it, false)
                            }
                            cardObj.optString("expYear").takeIf { it.isNotEmpty() }?.let {
                                entry.customFields["ExpYear"] = Pair(it, false)
                            }
                            cardObj.optString("code").takeIf { it.isNotEmpty() }?.let {
                                entry.customFields["CVV"] = Pair(it, true)
                            }
                        }
                    }
                }

                // Custom fields
                if (itemObj.has("fields")) {
                    val fieldsArray = itemObj.getJSONArray("fields")
                    for (f in 0 until fieldsArray.length()) {
                        val fObj = fieldsArray.getJSONObject(f)
                        val fName = fObj.optString("name")
                        val fVal = fObj.optString("value")
                        val fType = fObj.optInt("type", 0) // 1 is hidden/protected
                        if (fName.isNotEmpty() && fVal.isNotEmpty()) {
                            entry.customFields[fName] = Pair(fVal, fType == 1)
                        }
                    }
                }

                // Associate to folder or root
                val targetGroup = folderMap[folderId]
                if (targetGroup != null) {
                    targetGroup.entries.add(entry)
                } else {
                    result.rootEntries.add(entry)
                }
            }
        }

        result.recalculateStats()
        return result
    }
}
