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

import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader
import java.io.Reader
import java.nio.charset.StandardCharsets

/**
 * Robust, zero-dependency RFC 4180 CSV parser.
 * Handles embedded commas, newlines within quotes, escaped double quotes (""), and UTF-8 BOM.
 */
object CsvReader {

    fun parse(inputStream: InputStream): List<List<String>> {
        return parse(InputStreamReader(inputStream, StandardCharsets.UTF_8))
    }

    fun parse(reader: Reader): List<List<String>> {
        val bufferedReader = BufferedReader(reader)
        val records = mutableListOf<List<String>>()
        val currentRecord = mutableListOf<String>()
        val currentField = StringBuilder()

        var inQuotes = false
        var prevChar: Char? = null

        var rawCharInt: Int
        var isFirstChar = true

        while (bufferedReader.read().also { rawCharInt = it } != -1) {
            val c = rawCharInt.toChar()

            // Skip UTF-8 BOM if present at start
            if (isFirstChar) {
                isFirstChar = false
                if (c == '\uFEFF') {
                    continue
                }
            }

            if (inQuotes) {
                if (c == '"') {
                    // Check if next char is also quote (escaped quote)
                    bufferedReader.mark(1)
                    val nextInt = bufferedReader.read()
                    if (nextInt != -1 && nextInt.toChar() == '"') {
                        currentField.append('"')
                    } else {
                        // End of quoted field
                        inQuotes = false
                        if (nextInt != -1) {
                            bufferedReader.reset()
                        }
                    }
                } else {
                    currentField.append(c)
                }
            } else {
                when (c) {
                    '"' -> {
                        inQuotes = true
                    }
                    ',' -> {
                        currentRecord.add(currentField.toString())
                        currentField.setLength(0)
                    }
                    '\r' -> {
                        // Check for \r\n
                        bufferedReader.mark(1)
                        val nextInt = bufferedReader.read()
                        if (nextInt != -1 && nextInt.toChar() != '\n') {
                            bufferedReader.reset()
                        }
                        currentRecord.add(currentField.toString())
                        currentField.setLength(0)
                        if (currentRecord.isNotEmpty() && !(currentRecord.size == 1 && currentRecord[0].isEmpty())) {
                            records.add(ArrayList(currentRecord))
                        }
                        currentRecord.clear()
                    }
                    '\n' -> {
                        currentRecord.add(currentField.toString())
                        currentField.setLength(0)
                        if (currentRecord.isNotEmpty() && !(currentRecord.size == 1 && currentRecord[0].isEmpty())) {
                            records.add(ArrayList(currentRecord))
                        }
                        currentRecord.clear()
                    }
                    else -> {
                        currentField.append(c)
                    }
                }
            }
            prevChar = c
        }

        // Add trailing field and record if present
        if (currentField.isNotEmpty() || currentRecord.isNotEmpty()) {
            currentRecord.add(currentField.toString())
            if (currentRecord.isNotEmpty() && !(currentRecord.size == 1 && currentRecord[0].isEmpty())) {
                records.add(ArrayList(currentRecord))
            }
        }

        return records
    }
}
