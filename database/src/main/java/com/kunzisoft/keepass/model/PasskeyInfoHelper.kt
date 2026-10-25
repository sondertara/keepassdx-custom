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

import java.util.Locale

/**
 * Helper to extract, format, and present Passkey metadata in a user-friendly manner.
 */
object PasskeyInfoHelper {

    /**
     * Determine public/private key algorithm from PEM or default WebAuthn standards.
     */
    fun getAlgorithmName(passkey: Passkey): String {
        val pemString = String(passkey.privateKeyPem)
        return when {
            pemString.contains("EC PRIVATE KEY", ignoreCase = true) ||
            pemString.contains("secp256r1", ignoreCase = true) ||
            pemString.contains("prime256v1", ignoreCase = true) -> "ES256 (ECDSA P-256)"

            pemString.contains("RSA PRIVATE KEY", ignoreCase = true) -> "RS256 (RSA)"

            pemString.contains("ED25519", ignoreCase = true) -> "EdDSA (Ed25519)"

            else -> "ES256 (ECDSA P-256)"
        }
    }

    /**
     * Normalize relying party to a clean host name (e.g. "https://github.com/login" -> "github.com").
     */
    fun normalizeRelyingParty(rp: String): String {
        var clean = rp.trim()
        if (clean.startsWith("https://", ignoreCase = true)) {
            clean = clean.substring(8)
        } else if (clean.startsWith("http://", ignoreCase = true)) {
            clean = clean.substring(7)
        }
        val slashIdx = clean.indexOf('/')
        if (slashIdx != -1) {
            clean = clean.substring(0, slashIdx)
        }
        val colonIdx = clean.indexOf(':')
        if (colonIdx != -1) {
            clean = clean.substring(0, colonIdx)
        }
        return clean.ifEmpty { rp }
    }

    /**
     * Format a long credential ID string into a concise visual fingerprint (e.g. "4A7B...3E1F").
     */
    fun getShortCredentialId(credentialId: String): String {
        val clean = credentialId.trim()
        return if (clean.length > 16) {
            "${clean.substring(0, 8)}...${clean.substring(clean.length - 6)}"
        } else {
            clean
        }
    }

    /**
     * Check if PRF (Pseudo-Random Function, used for client-side encryption) extension is available.
     */
    fun hasPrfSupport(passkey: Passkey): Boolean {
        return passkey.prfSecret != null && passkey.prfSecret.isNotEmpty()
    }
}
