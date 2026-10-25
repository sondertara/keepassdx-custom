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
package com.kunzisoft.keepass.activities.dialogs

import android.app.Dialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.view.LayoutInflater
import android.widget.ImageButton
import android.widget.TextView
import android.widget.Toast
import androidx.fragment.app.DialogFragment
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.kunzisoft.keepass.R
import com.kunzisoft.keepass.model.Passkey
import com.kunzisoft.keepass.model.PasskeyInfoHelper
import com.kunzisoft.keepass.utils.getParcelableCompat

class PasskeyDetailsDialogFragment : DialogFragment() {

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        val passkey: Passkey? = arguments?.getParcelableCompat(ARG_PASSKEY)

        val context = requireContext()
        val inflater = LayoutInflater.from(context)
        val view = inflater.inflate(R.layout.dialog_passkey_details, null)

        if (passkey != null) {
            val txtRp = view.findViewById<TextView>(R.id.passkey_dialog_rp)
            val txtUsername = view.findViewById<TextView>(R.id.passkey_dialog_username)
            val txtAlgorithm = view.findViewById<TextView>(R.id.passkey_dialog_algorithm)
            val txtBackupStatus = view.findViewById<TextView>(R.id.passkey_dialog_backup_status)
            val txtCredentialId = view.findViewById<TextView>(R.id.passkey_dialog_credential_id)
            val btnCopy = view.findViewById<ImageButton>(R.id.btn_copy_credential_id)

            txtRp.text = PasskeyInfoHelper.normalizeRelyingParty(passkey.relyingParty)
            txtUsername.text = passkey.username.ifEmpty { "(No username)" }
            txtAlgorithm.text = PasskeyInfoHelper.getAlgorithmName(passkey)

            txtBackupStatus.text = if (passkey.backupEligibility == true) {
                if (passkey.backupState == true) {
                    getString(R.string.passkey_backup_synced)
                } else {
                    getString(R.string.passkey_backup_eligibility)
                }
            } else {
                getString(R.string.passkey_backup_single_device)
            }

            txtCredentialId.text = PasskeyInfoHelper.getShortCredentialId(passkey.credentialId)

            btnCopy.setOnClickListener {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val clip = ClipData.newPlainText("Credential ID", passkey.credentialId)
                clipboard.setPrimaryClip(clip)
                Toast.makeText(context, R.string.credential_id_copied, Toast.LENGTH_SHORT).show()
            }
        }

        return MaterialAlertDialogBuilder(context)
            .setView(view)
            .setPositiveButton(android.R.string.ok, null)
            .create()
    }

    companion object {
        const val TAG = "PasskeyDetailsDialog"
        private const val ARG_PASSKEY = "ARG_PASSKEY"

        fun newInstance(passkey: Passkey): PasskeyDetailsDialogFragment {
            return PasskeyDetailsDialogFragment().apply {
                arguments = Bundle().apply {
                    putParcelable(ARG_PASSKEY, passkey)
                }
            }
        }
    }
}
