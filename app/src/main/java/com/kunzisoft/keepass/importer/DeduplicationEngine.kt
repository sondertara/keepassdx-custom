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

import com.kunzisoft.keepass.database.ContextualDatabase
import com.kunzisoft.keepass.database.element.Entry
import com.kunzisoft.keepass.database.element.EntryId
import com.kunzisoft.keepass.database.element.Field
import com.kunzisoft.keepass.database.element.Group
import com.kunzisoft.keepass.database.element.security.ProtectedString
import com.kunzisoft.keepass.importer.model.ImportBatchResult
import com.kunzisoft.keepass.importer.model.ImportedEntry
import com.kunzisoft.keepass.importer.model.ImportedGroup
import com.kunzisoft.keepass.otp.OtpElement
import com.kunzisoft.keepass.otp.OtpEntryFields
import java.util.Locale

/**
 * Engine for detecting, merging, and cleaning duplicate credentials both during import
 * and across the existing KeePass database.
 */
object DeduplicationEngine {

    enum class MatchMode {
        /** Same normalized Title + Username (and fallback content if username is empty). */
        TITLE_AND_USERNAME,
        /** Identical Title + Username + Password. */
        EXACT_CONTENT,
        /** Entries sharing the exact same non-empty password. */
        SAME_PASSWORD
    }

    enum class ImportConflictStrategy {
        /** Skip importing entries that already exist in the database or earlier in the file. */
        SKIP_DUPLICATES,
        /** Update existing database entries with non-empty fields from imported duplicates. */
        UPDATE_EXISTING,
        /** Import all entries without deduplication. */
        KEEP_ALL
    }

    data class DuplicateEntryItem(
        val entryId: EntryId,
        val title: String,
        val username: String,
        val passwordLength: Int,
        val url: String,
        val hasOtp: Boolean,
        val hasNotes: Boolean,
        val groupPath: String,
        val lastModifiedTimeMillis: Long,
        val completenessScore: Int
    )

    data class DuplicateGroup(
        val key: String,
        val displayTitle: String,
        val displaySubtitle: String,
        val items: List<DuplicateEntryItem>,
        var selectedKeepEntryId: EntryId
    )

    data class PrecheckResult(
        val totalToImport: Int,
        val duplicateCount: Int
    )

    /**
     * Collect all active entries in the database (excluding the Recycle Bin).
     */
    fun collectActiveEntries(database: ContextualDatabase): List<Pair<Entry, String>> {
        val root = database.rootGroup ?: return emptyList()
        val recycleBinId = if (database.isRecycleBinEnabled) database.recycleBin?.nodeId else null
        val list = ArrayList<Pair<Entry, String>>(128)

        fun traverse(group: Group, path: String) {
            for (entry in group.getChildEntries()) {
                list.add(entry to path)
            }
            for (subGroup in group.getChildGroups()) {
                if (recycleBinId != null && subGroup.nodeId == recycleBinId) continue
                val subPath = if (path.isEmpty() || path == "/") {
                    "/${subGroup.title}"
                } else {
                    "$path/${subGroup.title}"
                }
                traverse(subGroup, subPath)
            }
        }

        traverse(root, "/")
        return list
    }

    /**
     * Compute a normalized deduplication key for an existing database [Entry].
     */
    fun buildKeyForDatabaseEntry(entry: Entry, mode: MatchMode = MatchMode.TITLE_AND_USERNAME): String? {
        val title = entry.title.trim().lowercase(Locale.ROOT)
        val username = entry.username.trim().lowercase(Locale.ROOT)
        val passwordStr = String(entry.password)
        val urlHost = extractHost(entry.url)
        val notes = entry.notes.trim()

        return when (mode) {
            MatchMode.TITLE_AND_USERNAME -> {
                val effectiveTitle = title.ifEmpty { urlHost }
                if (effectiveTitle.isEmpty() && username.isEmpty()) return null
                if (username.isNotEmpty()) {
                    "acct:$effectiveTitle|$username"
                } else {
                    val fallback = passwordStr.ifEmpty { notes }
                    if (fallback.isEmpty()) return null
                    "acct_nouser:$effectiveTitle|$fallback"
                }
            }
            MatchMode.EXACT_CONTENT -> {
                if (title.isEmpty() && username.isEmpty() && passwordStr.isEmpty()) return null
                "exact:$title|$username|$passwordStr"
            }
            MatchMode.SAME_PASSWORD -> {
                if (passwordStr.isEmpty()) return null
                "pwd:$passwordStr"
            }
        }
    }

    /**
     * Compute a normalized deduplication key for an [ImportedEntry].
     */
    fun buildKeyForImportedEntry(imported: ImportedEntry): String? {
        val title = imported.title.trim().lowercase(Locale.ROOT)
        val username = imported.username.trim().lowercase(Locale.ROOT)
        val passwordStr = String(imported.password)
        val urlHost = extractHost(imported.url)
        val notes = imported.notes.trim()
        val effectiveTitle = title.ifEmpty { urlHost }

        if (effectiveTitle.isEmpty() && username.isEmpty()) return null
        return if (username.isNotEmpty()) {
            "acct:$effectiveTitle|$username"
        } else {
            val fallback = passwordStr.ifEmpty { imported.otpUri.trim().ifEmpty { notes } }
            if (fallback.isEmpty()) return null
            "acct_nouser:$effectiveTitle|$fallback"
        }
    }

    /**
     * Pre-check how many entries in [batchResult] are duplicates of existing database entries
     * or internal duplicates within the file itself.
     */
    fun precheckImportBatch(
        database: ContextualDatabase?,
        batchResult: ImportBatchResult
    ): PrecheckResult {
        val knownKeys = HashSet<String>()
        if (database != null) {
            for ((entry, _) in collectActiveEntries(database)) {
                buildKeyForDatabaseEntry(entry, MatchMode.TITLE_AND_USERNAME)?.let {
                    knownKeys.add(it)
                }
            }
        }

        var duplicateCount = 0
        var totalCount = 0

        fun checkList(entries: List<ImportedEntry>) {
            for (imp in entries) {
                totalCount++
                val key = buildKeyForImportedEntry(imp)
                if (key != null) {
                    if (!knownKeys.add(key)) {
                        duplicateCount++
                    }
                }
            }
        }

        checkList(batchResult.rootEntries)
        fun checkGroup(group: ImportedGroup) {
            checkList(group.entries)
            group.childrenGroups.forEach { checkGroup(it) }
        }
        batchResult.groups.forEach { checkGroup(it) }

        return PrecheckResult(totalToImport = totalCount, duplicateCount = duplicateCount)
    }

    /**
     * Merge non-empty fields from [imported] into an existing database [Entry].
     */
    fun mergeImportedIntoExistingEntry(
        database: ContextualDatabase,
        existingEntry: Entry,
        imported: ImportedEntry
    ) {
        if (imported.password.isNotEmpty()) {
            existingEntry.password = imported.password.copyOf()
        }
        if (imported.url.isNotBlank() && existingEntry.url.isBlank()) {
            existingEntry.url = imported.url
        }
        if (imported.notes.isNotBlank() && !existingEntry.notes.contains(imported.notes.trim())) {
            existingEntry.notes = if (existingEntry.notes.isBlank()) {
                imported.notes
            } else {
                "${existingEntry.notes}\n${imported.notes}"
            }
        }
        if (imported.otpUri.isNotBlank()) {
            val importedInfo = imported.toEntryInfo()
            importedInfo.otpModel?.let { otpModel ->
                OtpEntryFields.buildOtpField(OtpElement(otpModel), null, null).let { otpField ->
                    existingEntry.putExtraField(otpField)
                }
            }
        }
        for ((k, v) in imported.customFields) {
            if (k.isNotBlank() && v.isNotBlank()) {
                existingEntry.putExtraField(Field(k, ProtectedString(false, v)))
            }
        }
        existingEntry.touch(modified = true, touchParents = true)
        database.updateEntry(existingEntry)
    }

    /**
     * Scan the entire database (excluding Recycle Bin) for duplicate entry groups.
     */
    fun scanDatabaseDuplicates(
        database: ContextualDatabase,
        mode: MatchMode
    ): List<DuplicateGroup> {
        val activeEntries = collectActiveEntries(database)
        val grouped = LinkedHashMap<String, MutableList<Pair<Entry, String>>>()

        for (pair in activeEntries) {
            val key = buildKeyForDatabaseEntry(pair.first, mode) ?: continue
            grouped.getOrPut(key) { ArrayList() }.add(pair)
        }

        val duplicateGroups = ArrayList<DuplicateGroup>()
        for ((key, pairs) in grouped) {
            if (pairs.size < 2) continue

            val items = pairs.map { (entry, path) ->
                val extraFields = entry.getExtraFields()
                val hasOtp = entry.getOtpElement() != null
                        || extraFields.any { it.name.equals("otp", ignoreCase = true) || it.name.contains("TOTP", ignoreCase = true) }
                val score = (if (entry.username.isNotBlank()) 2 else 0) +
                        (if (entry.password.isNotEmpty()) 2 else 0) +
                        (if (entry.url.isNotBlank()) 1 else 0) +
                        (if (entry.notes.isNotBlank()) 1 else 0) +
                        (if (hasOtp) 3 else 0) +
                        extraFields.size

                DuplicateEntryItem(
                    entryId = entry.nodeId,
                    title = entry.title.ifBlank { extractHost(entry.url).ifBlank { "未命名条目" } },
                    username = entry.username,
                    passwordLength = entry.password.size,
                    url = entry.url,
                    hasOtp = hasOtp,
                    hasNotes = entry.notes.isNotBlank(),
                    groupPath = path,
                    lastModifiedTimeMillis = entry.lastModificationTime.date.time,
                    completenessScore = score
                )
            }.sortedWith(
                compareByDescending<DuplicateEntryItem> { it.completenessScore }
                    .thenByDescending { it.lastModifiedTimeMillis }
            )

            val primary = items.first()
            val subtitle = when (mode) {
                MatchMode.SAME_PASSWORD -> "共用相同密码 (${primary.passwordLength} 位) · ${items.size} 个条目"
                else -> {
                    val userPart = primary.username.ifBlank { "无用户名" }
                    "$userPart · ${items.size} 个重复副本"
                }
            }

            duplicateGroups.add(
                DuplicateGroup(
                    key = key,
                    displayTitle = primary.title,
                    displaySubtitle = subtitle,
                    items = items,
                    selectedKeepEntryId = primary.entryId
                )
            )
        }

        return duplicateGroups.sortedByDescending { it.items.size }
    }

    /**
     * Resolve a single [DuplicateGroup] by keeping [DuplicateGroup.selectedKeepEntryId],
     * merging any missing fields from redundant copies into the kept entry, and moving
     * redundant copies to the Recycle Bin (or deleting if Recycle Bin is unavailable).
     *
     * @return Number of redundant entries removed.
     */
    fun resolveDuplicateGroup(
        database: ContextualDatabase,
        group: DuplicateGroup,
        recycleBinTitle: String,
        mergeMissingFields: Boolean = true
    ): Int {
        val keepEntry = database.getEntryById(group.selectedKeepEntryId) ?: return 0
        var removedCount = 0

        for (item in group.items) {
            if (item.entryId == group.selectedKeepEntryId) continue
            val dupEntry = database.getEntryById(item.entryId) ?: continue

            if (mergeMissingFields) {
                mergeDatabaseEntries(keepEntry, dupEntry)
            }

            if (database.canRecycle(dupEntry)) {
                database.recycle(dupEntry, recycleBinTitle)
            } else {
                database.deleteEntry(dupEntry)
            }
            removedCount++
        }

        if (removedCount > 0) {
            keepEntry.touch(modified = true, touchParents = true)
            database.updateEntry(keepEntry)
            database.indicateNotSavedData()
            database.wasReloaded = true
        }
        return removedCount
    }

    /**
     * Resolve all [groups] in batch.
     * @return Total number of redundant entries removed.
     */
    fun resolveAllDuplicateGroups(
        database: ContextualDatabase,
        groups: List<DuplicateGroup>,
        recycleBinTitle: String,
        mergeMissingFields: Boolean = true
    ): Int {
        var totalRemoved = 0
        for (group in groups) {
            totalRemoved += resolveDuplicateGroup(database, group, recycleBinTitle, mergeMissingFields)
        }
        return totalRemoved
    }

    private fun mergeDatabaseEntries(target: Entry, source: Entry) {
        if (target.username.isBlank() && source.username.isNotBlank()) {
            target.username = source.username
        }
        if (target.password.isEmpty() && source.password.isNotEmpty()) {
            target.password = source.password.copyOf()
        }
        if (target.url.isBlank() && source.url.isNotBlank()) {
            target.url = source.url
        }
        if (source.notes.isNotBlank() && !target.notes.contains(source.notes.trim())) {
            target.notes = if (target.notes.isBlank()) {
                source.notes
            } else {
                "${target.notes}\n${source.notes}"
            }
        }
        val targetFieldNames = target.getExtraFields().map { it.name }.toSet()
        for (field in source.getExtraFields()) {
            if (field.name !in targetFieldNames && field.protectedValue.toString().isNotBlank()) {
                target.putExtraField(field)
            }
        }
        val combinedTags = target.tags
        for (tag in source.tags.toStringList()) {
            combinedTags.put(tag)
        }
        target.tags = combinedTags
    }

    private fun extractHost(url: String): String {
        if (url.isBlank()) return ""
        return url.trim()
            .lowercase(Locale.ROOT)
            .removePrefix("https://")
            .removePrefix("http://")
            .removePrefix("www.")
            .substringBefore("/")
            .substringBefore(":")
    }
}
