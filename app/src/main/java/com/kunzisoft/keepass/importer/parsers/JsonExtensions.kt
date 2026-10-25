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

import org.json.JSONObject

/**
 * Defensive extensions for Android's org.json.JSONObject to avoid infamous 'null' string conversion traps.
 */
fun JSONObject.optStringSafe(key: String, fallback: String = ""): String {
    if (!has(key) || isNull(key)) return fallback
    val obj = opt(key)
    if (obj == null || obj == JSONObject.NULL) return fallback
    val str = obj.toString().trim()
    return if (str.equals("null", ignoreCase = true) || str.equals("none", ignoreCase = true)) {
        fallback
    } else {
        str
    }
}

fun JSONObject.optStringOrNull(key: String): String? {
    val res = optStringSafe(key, "")
    return if (res.isEmpty()) null else res
}
