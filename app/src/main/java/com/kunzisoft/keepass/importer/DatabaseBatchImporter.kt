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
import com.kunzisoft.keepass.database.element.Group
import com.kunzisoft.keepass.database.element.GroupId
import com.kunzisoft.keepass.importer.model.ImportBatchResult
import com.kunzisoft.keepass.importer.model.ImportedGroup
import com.kunzisoft.keepass.model.GroupInfo
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * High-performance, in-memory batch importer for third-party vault data.
 * Directly mounts imported groups and entries into [ContextualDatabase] without per-entry background task overhead.
 */
object DatabaseBatchImporter {

    private const val TAG = "DatabaseBatchImporter"

    data class BatchImportSummary(
        val totalEntries: Int,
        val totalGroups: Int,
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
        onProgress: ((current: Int, total: Int) -> Unit)? = null
    ): BatchImportSummary {
        val rootParent = if (targetParentGroupId != null) {
            database.getGroupById(targetParentGroupId) ?: database.rootGroup
        } else {
            database.rootGroup
        } ?: throw IllegalStateException("No target parent or root group found in database.")

        var importedEntriesCount = 0
        var importedGroupsCount = 0
        val totalEntriesToImport = batchResult.totalEntriesCount

        // 1. Determine base destination group
        val destinationGroup: Group = if (createDedicatedGroup) {
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
            dedicated
        } else {
            rootParent
        }

        // 2. Import root entries directly
        batchResult.rootEntries.forEach { importedEntry ->
            val entryInfo = importedEntry.toEntryInfo()
            val entry = database.createEntry(entryInfo)
            if (entry != null) {
                database.addEntryTo(entry, destinationGroup)
                entry.touch(modified = true, touchParents = true)
                importedEntriesCount++
                onProgress?.invoke(importedEntriesCount, totalEntriesToImport)
            } else {
                Log.w(TAG, "Failed to create entry for: ${importedEntry.title}")
            }
        }

        // 3. Recursively import subgroups
        fun importSubGroup(impGroup: ImportedGroup, parentGroup: Group) {
            val groupInfo = GroupInfo().apply {
                title = impGroup.name.ifEmpty { "Group" }
            }
            val newGroup = database.createGroup(groupInfo)
            if (newGroup == null) {
                Log.w(TAG, "Failed to create group for: ${impGroup.name}")
                return
            }

            database.addGroupTo(newGroup, parentGroup)
            newGroup.touch(modified = true, touchParents = true)
            importedGroupsCount++

            // Add entries in this subgroup
            impGroup.entries.forEach { entryData ->
                val entryInfo = entryData.toEntryInfo()
                val entry = database.createEntry(entryInfo)
                if (entry != null) {
                    database.addEntryTo(entry, newGroup)
                    entry.touch(modified = true, touchParents = true)
                    importedEntriesCount++
                    onProgress?.invoke(importedEntriesCount, totalEntriesToImport)
                } else {
                    Log.w(TAG, "Failed to create entry for: ${entryData.title}")
                }
            }

            // Recurse into children
            impGroup.childrenGroups.forEach { childGroup ->
                importSubGroup(childGroup, newGroup)
            }
        }

        batchResult.groups.forEach { group ->
            importSubGroup(group, destinationGroup)
        }

        // 4. Mark database modified and flag reload
        destinationGroup.touch(modified = true, touchParents = true)
        database.indicateNotSavedData()
        database.wasReloaded = true

        return BatchImportSummary(
            totalEntries = importedEntriesCount,
            totalGroups = importedGroupsCount,
            rootGroupName = destinationGroup.title
        )
    }
}
