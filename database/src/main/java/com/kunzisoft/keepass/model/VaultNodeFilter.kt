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
                || entry.tags.any { it.equals("passkey", ignoreCase = true) }
    }

    fun isTotpEntry(entry: EntryInfo): Boolean {
        return entry.otpModel != null
                || entry.tags.contains(OtpEntryFields.OTP_TAG)
                || entry.tags.any {
                    it.equals("otp", ignoreCase = true)
                            || it.equals("2fa", ignoreCase = true)
                            || it.equals("totp", ignoreCase = true)
                }
    }

    fun isFavoriteEntry(entry: EntryInfo): Boolean {
        return entry.tags.any { tag ->
            val lower = tag.lowercase(Locale.ROOT)
            lower == "favorite" || lower == "favourites" || lower == "常用" || lower == "收藏" || lower == "星标"
        }
    }

    /**
     * Recursively collect all entries from [group] into a flattened list of [SortedEntryInfo].
     */
    fun getFlattenedEntries(
        database: DatabaseInfo,
        group: Group,
        nodeFilter: NodeFilter = EmptyNodeFilter()
    ): List<SortedEntryInfo> {
        val collectedEntries = mutableListOf<Entry>()

        fun collect(currentGroup: Group) {
            val childEntries = currentGroup.getChildEntries().filter(nodeFilter.filter)
            collectedEntries.addAll(childEntries)

            currentGroup.getChildGroups().filter(nodeFilter.filter).forEach { subGroup ->
                collect(subGroup)
            }
        }

        collect(group)

        return collectedEntries.map { entry ->
            SortedEntryInfo(
                entryToCopy = database.getEntryInfoFrom(entry),
                path = entry.getPathString(),
                indexInParent = entry.indexInParent(),
                isReferenced = database.isEntryReferenced(entry)
            )
        }
    }
}
