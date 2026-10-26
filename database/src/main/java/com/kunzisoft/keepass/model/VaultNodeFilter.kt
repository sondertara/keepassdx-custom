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
package com.kunzisoft.keepass.model

import com.kunzisoft.keepass.database.element.Entry
import com.kunzisoft.keepass.database.element.Group
import com.kunzisoft.keepass.database.element.node.EmptyNodeFilter
import com.kunzisoft.keepass.database.element.node.NodeFilter
import com.kunzisoft.keepass.otp.OtpEntryFields
import java.util.Locale

enum class VaultCategory {
    ALL,
    PASSWORDS,
    PASSKEYS,
    TOTP,
    FAVORITES
}

/**
 * Filter and flattener for vault entries.
 */
object VaultNodeFilter {

    /**
     * Filter a list of [SortedNodeInfo] according to the selected [VaultCategory].
     */
    fun filter(
        nodes: List<SortedNodeInfo>,
        category: VaultCategory
    ): List<SortedNodeInfo> {
        return when (category) {
            VaultCategory.ALL -> nodes
            VaultCategory.PASSWORDS -> nodes.filter { node ->
                node is EntryInfo && node.password.isNotEmpty()
            }
            VaultCategory.PASSKEYS -> nodes.filter { node ->
                node is EntryInfo && isPasskeyEntry(node)
            }
            VaultCategory.TOTP -> nodes.filter { node ->
                node is EntryInfo && isTotpEntry(node)
            }
            VaultCategory.FAVORITES -> nodes.filter { node ->
                node is EntryInfo && isFavoriteEntry(node)
            }
        }
    }

    fun isPasskeyEntry(entry: EntryInfo): Boolean {
        return entry.passkey != null
                || entry.containsCustomField(PasskeyEntryFields.FIELD_USERNAME)
                || entry.tags.contains(PasskeyEntryFields.PASSKEY_TAG)
                || entry.tags.toStringList().any { it.equals("passkey", ignoreCase = true) }
    }

    fun isTotpEntry(entry: EntryInfo): Boolean {
        return entry.otpModel != null
                || entry.tags.contains(OtpEntryFields.OTP_TAG)
                || entry.tags.toStringList().any {
                    it.equals("otp", ignoreCase = true)
                            || it.equals("2fa", ignoreCase = true)
                            || it.equals("totp", ignoreCase = true)
                }
    }

    fun isFavoriteEntry(entry: EntryInfo): Boolean {
        return entry.tags.toStringList().any { tag ->
            val lower = tag.lowercase(Locale.ROOT)
            lower == "favorite" || lower == "favourites" || lower == "常用" || lower == "收藏" || lower == "星标"
        }
    }

    private fun isFavoriteRawEntry(entry: Entry): Boolean {
        return entry.tags.toStringList().any { tag ->
            val lower = tag.lowercase(Locale.ROOT)
            lower == "favorite" || lower == "favourites" || lower == "常用" || lower == "收藏" || lower == "星标"
        }
    }

    /**
     * Recursively collect all entries from [group] into a flattened list of [SortedEntryInfo].
     * Uses O(1) sequential indexing and cached group paths instead of O(N^2) indexInParent() lookups.
     */
    fun getFlattenedEntries(
        database: DatabaseInfo,
        group: Group,
        nodeFilter: NodeFilter = EmptyNodeFilter(),
        category: VaultCategory = VaultCategory.ALL
    ): List<SortedEntryInfo> {
        val result = ArrayList<SortedEntryInfo>(128)
        val recycleBinId = if (database.isRecycleBinEnabled) database.recycleBin?.nodeId else null
        val isTargetRecycleBin = recycleBinId != null && group.nodeId == recycleBinId
        var flatIndex = 0

        fun collect(currentGroup: Group, currentPath: String) {
            val childEntries = currentGroup.getChildEntries()
            for (i in childEntries.indices) {
                val entry = childEntries[i]
                if (!nodeFilter.filter(entry)) continue
                if (category == VaultCategory.FAVORITES && !isFavoriteRawEntry(entry)) continue

                val entryInfo = database.getEntryInfoFrom(entry)
                val matches = when (category) {
                    VaultCategory.ALL -> true
                    VaultCategory.PASSWORDS -> entryInfo.password.isNotEmpty()
                    VaultCategory.PASSKEYS -> isPasskeyEntry(entryInfo)
                    VaultCategory.TOTP -> isTotpEntry(entryInfo)
                    VaultCategory.FAVORITES -> isFavoriteEntry(entryInfo)
                }
                if (matches) {
                    result.add(
                        SortedEntryInfo(
                            entryToCopy = entryInfo,
                            path = currentPath,
                            indexInParent = flatIndex++,
                            isReferenced = false
                        )
                    )
                }
            }

            val childGroups = currentGroup.getChildGroups()
            for (i in childGroups.indices) {
                val subGroup = childGroups[i]
                if (!isTargetRecycleBin && recycleBinId != null && subGroup.nodeId == recycleBinId) {
                    continue
                }
                if (!nodeFilter.filter(subGroup)) continue
                val subPath = if (currentPath.isEmpty() || currentPath == "/") {
                    "/${subGroup.title}"
                } else {
                    "$currentPath/${subGroup.title}"
                }
                collect(subGroup, subPath)
            }
        }

        val startPath = if (group.nodeId == database.rootGroup?.nodeId) "/" else group.getPathString()
        collect(group, startPath)
        return result
    }
}
