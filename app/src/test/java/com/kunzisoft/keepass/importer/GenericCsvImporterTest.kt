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

import com.kunzisoft.keepass.importer.parsers.GenericCsvImporter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets

class GenericCsvImporterTest {

    @Test
    fun parseGenericCsvWithQuotedFields() {
        val csv = """
        "Title","Username","Password","URL","Notes","TOTP","Group"
        "AWS Console","admin@company.com","StrongP@ss123!","https://aws.amazon.com","Note with, comma and
        line break","JBSWY3DPEHPK3PXP","Cloud/Infrastructure"
        "Personal Blog","blogger","mypassword","https://blog.example.com","Simple note","","Personal"
        """.trimIndent()

        val importer = GenericCsvImporter()
        val result = importer.parse(ByteArrayInputStream(csv.toByteArray(StandardCharsets.UTF_8)))

        assertEquals(2, result.totalEntriesCount)
        assertEquals(1, result.totpEntriesCount)
        assertEquals(2, result.groups.size)

        val awsGroup = result.groups.firstOrNull { it.name == "Cloud/Infrastructure" }
        assertNotNull(awsGroup)
        assertEquals(1, awsGroup!!.entries.size)

        val awsEntry = awsGroup.entries[0]
        assertEquals("AWS Console", awsEntry.title)
        assertEquals("admin@company.com", awsEntry.username)
        assertEquals("StrongP@ss123!", String(awsEntry.password))
        assertEquals("https://aws.amazon.com", awsEntry.url)
        assertTrue(awsEntry.notes.contains("comma and"))
        assertTrue(awsEntry.notes.contains("line break"))
        assertEquals("JBSWY3DPEHPK3PXP", awsEntry.totpUriOrSecret)

        val personalGroup = result.groups.firstOrNull { it.name == "Personal" }
        assertNotNull(personalGroup)
        assertEquals(1, personalGroup!!.entries.size)
        assertEquals("Personal Blog", personalGroup.entries[0].title)
    }

    @Test
    fun testFuzzyHeaderMatching() {
        val csv = """
        Account,Email,Secret,Web
        "Dropbox","user@dropbox.com","p@ssword!","dropbox.com"
        """.trimIndent()

        val importer = GenericCsvImporter()
        val result = importer.parse(ByteArrayInputStream(csv.toByteArray(StandardCharsets.UTF_8)))

        assertEquals(1, result.totalEntriesCount)
        val entry = result.rootEntries[0]
        assertEquals("Dropbox", entry.title)
        assertEquals("user@dropbox.com", entry.username)
        assertEquals("p@ssword!", String(entry.password))
        assertEquals("dropbox.com", entry.url)
    }
}
