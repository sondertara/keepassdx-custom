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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PasskeyInfoHelperTest {

    private fun createPasskey(
        pem: String,
        rp: String = "example.com",
        credId: String = "cred123",
        prf: String? = null
    ): Passkey {
        return Passkey(
            username = "alice",
            privateKeyPem = pem.toCharArray(),
            credentialId = credId,
            userHandle = "handle123",
            relyingParty = rp,
            backupEligibility = true,
            backupState = true,
            prfSecret = prf?.toCharArray()
        )
    }

    @Test
    fun testNormalizeRelyingParty() {
        assertEquals("github.com", PasskeyInfoHelper.normalizeRelyingParty("https://github.com/login"))
        assertEquals("google.com", PasskeyInfoHelper.normalizeRelyingParty("https://google.com"))
        assertEquals("localhost", PasskeyInfoHelper.normalizeRelyingParty("http://localhost:8080/auth"))
        assertEquals("account.proton.me", PasskeyInfoHelper.normalizeRelyingParty("account.proton.me"))
    }

    @Test
    fun testAlgorithmDetection() {
        val ecKey = createPasskey("-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEI...")
        assertEquals("ES256 (ECDSA P-256)", PasskeyInfoHelper.getAlgorithmName(ecKey))

        val rsaKey = createPasskey("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...")
        assertEquals("RS256 (RSA)", PasskeyInfoHelper.getAlgorithmName(rsaKey))

        val edKey = createPasskey("-----BEGIN ED25519 PRIVATE KEY-----\nMC4CAQAw...")
        assertEquals("EdDSA (Ed25519)", PasskeyInfoHelper.getAlgorithmName(edKey))
    }

    @Test
    fun testShortCredentialId() {
        val longId = "4A7B8C9D0E1F2A3B4C5D6E7F"
        assertEquals("4A7B8C9D...5D6E7F", PasskeyInfoHelper.getShortCredentialId(longId))

        val shortId = "shortId"
        assertEquals("shortId", PasskeyInfoHelper.getShortCredentialId(shortId))
    }

    @Test
    fun testPrfSupport() {
        val withPrf = createPasskey("EC", prf = "secret_prf_key")
        assertTrue(PasskeyInfoHelper.hasPrfSupport(withPrf))

        val withoutPrf = createPasskey("EC", prf = null)
        assertFalse(PasskeyInfoHelper.hasPrfSupport(withoutPrf))
    }
}
