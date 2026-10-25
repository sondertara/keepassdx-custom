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

import com.kunzisoft.keepass.importer.parsers.BitwardenJsonImporter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets

class BitwardenJsonImporterTest {

    @Test
    fun parseBitwardenStandardJson() {
        val json = """
        {
          "encrypted": false,
          "folders": [
            {
              "id": "f-123",
              "name": "Social Networks"
            }
          ],
          "items": [
            {
              "id": "item-1",
              "organizationId": null,
              "folderId": "f-123",
              "type": 1,
              "name": "GitHub",
              "notes": "My developer account",
              "favorite": true,
              "login": {
                "uris": [
                  {
                    "match": null,
                    "uri": "https://github.com/login"
                  }
                ],
                "username": "octocat",
                "password": "super-secret-password",
                "totp": "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP"
              },
              "fields": [
                {
                  "name": "PIN",
                  "value": "9988",
                  "type": 1
                }
              ]
            },
            {
              "id": "item-2",
              "organizationId": null,
              "folderId": null,
              "type": 2,
              "name": "Server SSH Notes",
              "notes": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5..."
            }
          ]
        }
        """.trimIndent()

        val importer = BitwardenJsonImporter()
        val result = importer.parse(ByteArrayInputStream(json.toByteArray(StandardCharsets.UTF_8)))

        assertEquals(2, result.totalEntriesCount)
        assertEquals(1, result.totpEntriesCount)
        assertEquals(1, result.groups.size)
        assertEquals("Social Networks", result.groups[0].name)
        assertEquals(1, result.groups[0].entries.size)

        val gitHubEntry = result.groups[0].entries[0]
        assertEquals("GitHub", gitHubEntry.title)
        assertEquals("octocat", gitHubEntry.username)
        assertEquals("super-secret-password", String(gitHubEntry.password))
        assertEquals("https://github.com/login", gitHubEntry.url)
        assertEquals("otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP", gitHubEntry.totpUriOrSecret)
        assertTrue(gitHubEntry.tags.contains("Favorite"))
        assertEquals("9988", gitHubEntry.customFields["PIN"]?.first)

        assertEquals(1, result.rootEntries.size)
        val noteEntry = result.rootEntries[0]
        assertEquals("Server SSH Notes", noteEntry.title)
        assertTrue(noteEntry.notes.contains("ssh-ed25519"))
    }

    @Test
    fun testBitwardenWithNullTotpAndNullNotes() {
        val json = """
        {
          "encrypted": false,
          "folders": [],
          "items": [
            {
              "id": "item-plain",
              "organizationId": null,
              "folderId": null,
              "type": 1,
              "name": "Normal Website",
              "notes": null,
              "favorite": false,
              "login": {
                "uris": null,
                "username": "normal_user",
                "password": "normal_password",
                "totp": null
              }
            }
          ]
        }
        """.trimIndent()

        val importer = BitwardenJsonImporter()
        val result = importer.parse(ByteArrayInputStream(json.toByteArray(StandardCharsets.UTF_8)))

        assertEquals(1, result.totalEntriesCount)
        assertEquals(0, result.totpEntriesCount)
        assertEquals(1, result.rootEntries.size)

        val entry = result.rootEntries[0]
        assertEquals("Normal Website", entry.title)
        assertEquals("normal_user", entry.username)
        assertEquals("normal_password", String(entry.password))
        assertEquals("", entry.notes)
        org.junit.Assert.assertNull(entry.totpUriOrSecret)
        org.junit.Assert.assertFalse(entry.tags.contains("TOTP"))
    }
}
