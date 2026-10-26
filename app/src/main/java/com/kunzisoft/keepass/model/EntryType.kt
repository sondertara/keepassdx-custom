/*
 * Copyright 2026 KeePassDX Contributors.
 *
 * This file is part of KeePassDX.
 *
 * KeePassDX is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * KeePassDX is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with KeePassDX. If not, see <http://www.gnu.org/licenses/>.
 */
package com.kunzisoft.keepass.model

enum class EntryType {
    PASSWORD,
    TOTP,
    PASSKEY,
    CREDIT_CARD,
    SECURE_NOTE,
    EMAIL,
    WIFI,
    ID_CARD,
    BANK,
    CRYPTOCURRENCY;

    companion object {
        const val KEY_ENTRY_TYPE = "EXTRA_ENTRY_TYPE"

        fun fromString(value: String?): EntryType {
            return values().firstOrNull { it.name.equals(value, ignoreCase = true) } ?: PASSWORD
        }
    }
}
