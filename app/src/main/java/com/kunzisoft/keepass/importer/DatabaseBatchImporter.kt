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

import android.util.Log
import com.kunzisoft.keepass.database.ContextualDatabase
import com.kunzisoft.keepass.database.element.Entry
import com.kunzisoft.keepass.database.element.Group
import com.kunzisoft.keepass.database.element.GroupId
import com.kunzisoft.keepass.importer.model.ImportBatchResult
import com.kunzisoft.keepass.importer.model.ImportedEntry
import com.kunzisoft.keepass.importer.model.ImportedGroup
import com.kunzisoft.keepass.model.GroupInfo
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * High-performance, in-memory batch importer for third-party vault data.
 * Directly mounts imported groups and entries into [ContextualDatabase] with built-in deduplication.
 */
object DatabaseBatchImporter {

    private const val TAG = "DatabaseBatchImporter"

    data class BatchImportSummary(
        val totalEntries: Int,
        val totalGroups: Int,
        val skippedDuplicates: Int = 0,
        val updatedEntries: Int = 0,
        val rootGroupName: String
    )

    /**
     * Import a parsed [ImportBatchResult] into the given [database].
     */
    fun importBatch(
        database: ContextualDatabase,
        targetParentGroupId: GroupId?,
        batchResult: ImportBatchResult,
        createDedicatedGroup: Boolean = true,
        customDedicatedGroupName: String? = null,
        conflictStrategy: DeduplicationEngine.ImportConflictStrategy = DeduplicationEngine.ImportConflictStrategy.SKIP_DUPLICATES,
        onProgress: ((current: Int, total: Int) -> Unit)? = null
    ): BatchImportSummary {
        val rootParent = if (targetParentGroupId != null) {
            database.getGroupById(targetParentGroupId) ?: database.rootGroup
        } else {
            database.rootGroup
        } ?: throw IllegalStateException("No target parent or root group found in database.")

        var importedEntriesCount = 0
        var importedGroupsCount = 0
        var skippedDuplicatesCount = 0
        var updatedEntriesCount = 0
        var processedCount = 0
        val totalEntriesToImport = batchResult.totalEntriesCount

        // Pre-index existing entries if deduplication is active
        val existingEntryMap = HashMap<String, Entry>()
        if (conflictStrategy != DeduplicationEngine.ImportConflictStrategy.KEEP_ALL) {
            for ((entry, _) in DeduplicationEngine.collectActiveEntries(database)) {
                DeduplicationEngine.buildKeyForDatabaseEntry(entry)?.let { key ->
                    existingEntryMap.putIfAbsent(key, entry)
                }
            }
        }

        // Lazy destination group creation so we don't create an empty folder if all entries are skipped
        var lazyDedicatedGroup: Group? = null
        fun getOrCreateDestinationGroup(): Group {
            if (!createDedicatedGroup) return rootParent
            lazyDedicatedGroup?.let { return it }

            val dateStr = SimpleDateFormat("yyyy-MM-dd", Locale.getDefault()).format(Date())
            val groupName = customDedicatedGroupName?.ifEmpty { null }
                ?: "导入 - ${batchResult.sourceName} ($dateStr)"

            val groupInfo = GroupInfo().apply {
                title = groupName
            }
            val dedicated = database.createGroup(groupInfo)
                ?: throw IllegalStateException("Failed to create dedicated import group.")

            database.addGroupTo(dedicated, rootParent)
            dedicated.touch(modified = true, touchParents = true)
            importedGroupsCount++
            lazyDedicatedGroup = dedicated
            return dedicated
        }

        fun handleEntry(importedEntry: ImportedEntry, targetGroupProvider: () -> Group) {
            processedCount++
            val key = if (conflictStrategy != DeduplicationEngine.ImportConflictStrategy.KEEP_ALL) {
                DeduplicationEngine.buildKeyForImportedEntry(importedEntry)
            } else null

            val existing = if (key != null) existingEntryMap[key] else null
            if (existing != null) {
                when (conflictStrategy) {
                    DeduplicationEngine.ImportConflictStrategy.SKIP_DUPLICATES -> {
                        skippedDuplicatesCount++
                        onProgress?.invoke(processedCount, totalEntriesToImport)
                        return
                    }
                    DeduplicationEngine.ImportConflictStrategy.UPDATE_EXISTING -> {
                        DeduplicationEngine.mergeImportedIntoExistingEntry(database, existing, importedEntry)
                        updatedEntriesCount++
                        onProgress?.invoke(processedCount, totalEntriesToImport)
                        return
                    }
                    DeduplicationEngine.ImportConflictStrategy.KEEP_ALL -> {}
                }
            }

            val entryInfo = importedEntry.toEntryInfo()
            val entry = database.createEntry(entryInfo)
            if (entry != null) {
                val targetGroup = targetGroupProvider()
                database.addEntryTo(entry, targetGroup)
                entry.touch(modified = true, touchParents = true)
                if (key != null) {
                    existingEntryMap[key] = entry
                }
                importedEntriesCount++
                onProgress?.invoke(processedCount, totalEntriesToImport)
            } else {
                Log.w(TAG, "Failed to create entry for: ${importedEntry.title}")
            }
        }

        // 1. Import root entries
        batchResult.rootEntries.forEach { importedEntry ->
            handleEntry(importedEntry) { getOrCreateDestinationGroup() }
        }

        // 2. Recursively import subgroups
        fun importSubGroup(impGroup: ImportedGroup, parentGroupProvider: () -> Group) {
            var lazyCurrentGroup: Group? = null
            fun getOrCreateCurrentGroup(): Group {
                lazyCurrentGroup?.let { return it }
                val parentGroup = parentGroupProvider()
                val groupInfo = GroupInfo().apply {
                    title = impGroup.name.ifEmpty { "Group" }
                }
                val newGroup = database.createGroup(groupInfo)
                    ?: throw IllegalStateException("Failed to create group for: ${impGroup.name}")
                database.addGroupTo(newGroup, parentGroup)
                newGroup.touch(modified = true, touchParents = true)
                importedGroupsCount++
                lazyCurrentGroup = newGroup
                return newGroup
            }

            impGroup.entries.forEach { entryData ->
                handleEntry(entryData) { getOrCreateCurrentGroup() }
            }

            impGroup.childrenGroups.forEach { childGroup ->
                importSubGroup(childGroup) { getOrCreateCurrentGroup() }
            }
        }

        batchResult.groups.forEach { group ->
            importSubGroup(group) { getOrCreateDestinationGroup() }
        }

        // 3. Mark database modified and flag reload if anything changed
        if (importedEntriesCount > 0 || updatedEntriesCount > 0 || importedGroupsCount > 0) {
            (lazyDedicatedGroup ?: rootParent).touch(modified = true, touchParents = true)
            database.indicateNotSavedData()
            database.wasReloaded = true
        }

        return BatchImportSummary(
            totalEntries = importedEntriesCount,
            totalGroups = importedGroupsCount,
            skippedDuplicates = skippedDuplicatesCount,
            updatedEntries = updatedEntriesCount,
            rootGroupName = (lazyDedicatedGroup ?: rootParent).title
        )
    }
}
