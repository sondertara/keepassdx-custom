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
import com.kunzisoft.keepass.importer.parsers.ChromeCsvImporter
import com.kunzisoft.keepass.importer.parsers.GenericCsvImporter
import com.kunzisoft.keepass.importer.parsers.GoogleAuthMigrationImporter
import com.kunzisoft.keepass.importer.parsers.OnePasswordCsvImporter
import com.kunzisoft.keepass.importer.parsers.ProtonPassJsonImporter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ImporterFactoryTest {

    @Test
    fun testAllImportersRegistered() {
        val list = ImporterFactory.allImporters
        assertEquals(6, list.size)
        assertTrue(list.any { it is BitwardenJsonImporter })
        assertTrue(list.any { it is ProtonPassJsonImporter })
        assertTrue(list.any { it is OnePasswordCsvImporter })
        assertTrue(list.any { it is ChromeCsvImporter })
        assertTrue(list.any { it is GenericCsvImporter })
        assertTrue(list.any { it is GoogleAuthMigrationImporter })
    }

    @Test
    fun testDetectBitwarden() {
        val json = "{\"encrypted\":false,\"folders\":[],\"items\":[]}"
        val importer = ImporterFactory.detectImporter("bitwarden_export_2026.json", json)
        assertTrue(importer is BitwardenJsonImporter)
    }

    @Test
    fun testDetectProtonPass() {
        val json = "{\"vaults\":[{\"items\":[]}]}"
        val importer = ImporterFactory.detectImporter("proton_export.json", json)
        assertTrue(importer is ProtonPassJsonImporter)
    }

    @Test
    fun testDetectChromeCsv() {
        val csv = "name,url,username,password\nGoogle,https://google.com,user,pass"
        val importer = ImporterFactory.detectImporter("Chrome Passwords.csv", csv)
        assertTrue(importer is ChromeCsvImporter)
    }

    @Test
    fun testDetectGooglePasswordsCsvWithBomAndChineseFileName() {
        val csv = "\uFEFFname,url,username,password,note\nGoogle,https://google.com,user,pass,note"
        val importer = ImporterFactory.detectImporter("Google 密码.csv", csv)
        assertTrue(importer is ChromeCsvImporter)
    }

    @Test
    fun testDetectGooglePasswordsCsvWithChineseHeaders() {
        val csv = "名称,网址,用户名,密码,备注\nGoogle,https://google.com,user,pass,note"
        val importer = ImporterFactory.detectImporter("密码导出.csv", csv)
        assertTrue(importer is ChromeCsvImporter)
    }

    @Test
    fun testDetectOnePasswordCsv() {
        val csv = "Title,Type,Username,Password,Website,Notes\nDropbox,Login,user,pass,https://dropbox.com,note"
        val importer = ImporterFactory.detectImporter("1password.csv", csv)
        assertTrue(importer is OnePasswordCsvImporter)
    }

    @Test
    fun testDetectGoogleAuthMigration() {
        val text = "otpauth-migration://offline?data=xyz..."
        val importer = ImporterFactory.detectImporter("migration.txt", text)
        assertTrue(importer is GoogleAuthMigrationImporter)
    }
}
