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
package com.kunzisoft.keepass.importer.ui

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.util.Log
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.view.isVisible
import androidx.lifecycle.lifecycleScope
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.progressindicator.LinearProgressIndicator
import com.kunzisoft.keepass.R
import com.kunzisoft.keepass.activities.legacy.DatabaseLockActivity
import com.kunzisoft.keepass.database.ContextualDatabase
import com.kunzisoft.keepass.database.element.GroupId
import com.kunzisoft.keepass.importer.DatabaseBatchImporter
import com.kunzisoft.keepass.importer.ImporterFactory
import com.kunzisoft.keepass.importer.model.ImportBatchResult
import com.kunzisoft.keepass.importer.parsers.VaultImporter
import com.kunzisoft.keepass.utils.getParcelableExtraCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.io.InputStream

class ImportWizardActivity : DatabaseLockActivity() {

    private var currentParentGroupId: GroupId? = null
    private var selectedFileUri: Uri? = null
    private var selectedFileName: String? = null
    private var parsedBatchResult: ImportBatchResult? = null

    // Views
    private lateinit var toolbar: MaterialToolbar
    private lateinit var spinnerFormat: Spinner
    private lateinit var btnSelectFile: MaterialButton
    private lateinit var txtSelectedFileName: TextView
    private lateinit var cardPreview: MaterialCardView
    private lateinit var txtPreviewTotalEntries: TextView
    private lateinit var txtPreviewTotpEntries: TextView
    private lateinit var txtPreviewGroupsCount: TextView
    private lateinit var txtPreviewWarning: TextView
    private lateinit var radioGroupDestination: RadioGroup
    private lateinit var radioDestNewGroup: RadioButton
    private lateinit var progressImport: LinearProgressIndicator
    private lateinit var txtImportStatus: TextView
    private lateinit var btnStartImport: MaterialButton

    private val filePickerLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri != null) {
            handleSelectedFile(uri)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_import_wizard)

        currentParentGroupId = intent.getParcelableExtraCompat(EXTRA_PARENT_GROUP_ID)

        initViews()
        setupFormatSpinner()
    }

    private fun initViews() {
        toolbar = findViewById(R.id.toolbar)
        toolbar.setNavigationOnClickListener {
            finish()
        }

        spinnerFormat = findViewById(R.id.spinner_import_format)
        btnSelectFile = findViewById(R.id.btn_select_file)
        txtSelectedFileName = findViewById(R.id.txt_selected_file_name)
        cardPreview = findViewById(R.id.card_import_preview)
        txtPreviewTotalEntries = findViewById(R.id.txt_preview_total_entries)
        txtPreviewTotpEntries = findViewById(R.id.txt_preview_totp_entries)
        txtPreviewGroupsCount = findViewById(R.id.txt_preview_groups_count)
        txtPreviewWarning = findViewById(R.id.txt_preview_warning)
        radioGroupDestination = findViewById(R.id.radio_group_destination)
        radioDestNewGroup = findViewById(R.id.radio_dest_new_group)
        progressImport = findViewById(R.id.progress_import)
        txtImportStatus = findViewById(R.id.txt_import_status)
        btnStartImport = findViewById(R.id.btn_start_import)

        btnSelectFile.setOnClickListener {
            filePickerLauncher.launch(arrayOf("*/*"))
        }

        btnStartImport.setOnClickListener {
            executeImport()
        }
    }

    private fun setupFormatSpinner() {
        val formatList = mutableListOf(getString(R.string.import_source_auto))
        formatList.addAll(ImporterFactory.allImporters.map { it.displayName })

        val adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, formatList).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }
        spinnerFormat.adapter = adapter

        spinnerFormat.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                // If a file is already picked, re-parse with the newly selected parser
                selectedFileUri?.let { handleSelectedFile(it) }
            }

            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }
    }

    private fun handleSelectedFile(uri: Uri) {
        selectedFileUri = uri
        selectedFileName = queryFileName(uri) ?: uri.lastPathSegment ?: "unknown"
        txtSelectedFileName.text = selectedFileName

        parseFileInBackground(uri, selectedFileName ?: "")
    }

    private fun parseFileInBackground(uri: Uri, fileName: String) {
        showLoading(true, getString(R.string.import_parsing_in_progress))
        btnStartImport.isEnabled = false
        cardPreview.isVisible = false

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val fileBytes = contentResolver.openInputStream(uri)?.use { it.readBytes() }
                    ?: throw IllegalArgumentException("Cannot open file stream.")

                // Determine importer
                val selectedPos = withContext(Dispatchers.Main) { spinnerFormat.selectedItemPosition }
                val importer: VaultImporter = if (selectedPos == 0) {
                    // Auto-detect
                    val previewLength = minOf(fileBytes.size, 2048)
                    val preview = String(fileBytes, 0, previewLength)
                    ImporterFactory.detectImporter(fileName, preview)
                } else {
                    ImporterFactory.allImporters[selectedPos - 1]
                }

                val parseResult = importer.parse(ByteArrayInputStream(fileBytes))

                withContext(Dispatchers.Main) {
                    showLoading(false)
                    displayPreviewResult(parseResult)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error parsing file for import", e)
                withContext(Dispatchers.Main) {
                    showLoading(false)
                    Toast.makeText(
                        this@ImportWizardActivity,
                        getString(R.string.import_error, e.localizedMessage ?: "Unknown error"),
                        Toast.LENGTH_LONG
                    ).show()
                }
            }
        }
    }

    private fun displayPreviewResult(result: ImportBatchResult) {
        parsedBatchResult = result

        txtPreviewTotalEntries.text = getString(R.string.import_total_entries, result.totalEntriesCount)
        txtPreviewTotpEntries.text = getString(R.string.import_totp_entries, result.totpEntriesCount)
        txtPreviewGroupsCount.text = getString(R.string.import_folders_count, result.groups.size)

        if (result.warnings.isNotEmpty()) {
            txtPreviewWarning.text = result.warnings.joinToString("\n")
            txtPreviewWarning.isVisible = true
        } else {
            txtPreviewWarning.isVisible = false
        }

        cardPreview.isVisible = true
        btnStartImport.isEnabled = result.totalEntriesCount > 0
    }

    private fun executeImport() {
        val database = mDatabase ?: run {
            Toast.makeText(this, "Database not available", Toast.LENGTH_SHORT).show()
            return
        }

        val result = parsedBatchResult ?: return

        showLoading(true, getString(R.string.importing_in_progress))
        btnStartImport.isEnabled = false
        btnSelectFile.isEnabled = false

        val createDedicated = radioDestNewGroup.isChecked

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val summary = DatabaseBatchImporter.importBatch(
                    database = database,
                    targetParentGroupId = currentParentGroupId,
                    batchResult = result,
                    createDedicatedGroup = createDedicated
                )

                // Save changes to database
                saveDatabase()

                withContext(Dispatchers.Main) {
                    showLoading(false)
                    Toast.makeText(
                        this@ImportWizardActivity,
                        getString(R.string.import_success, summary.totalEntries, summary.totalGroups),
                        Toast.LENGTH_LONG
                    ).show()

                    setResult(Activity.RESULT_OK)
                    finish()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Batch import execution failed", e)
                withContext(Dispatchers.Main) {
                    showLoading(false)
                    btnStartImport.isEnabled = true
                    btnSelectFile.isEnabled = true
                    Toast.makeText(
                        this@ImportWizardActivity,
                        getString(R.string.import_error, e.localizedMessage ?: "Error during batch import"),
                        Toast.LENGTH_LONG
                    ).show()
                }
            }
        }
    }

    private fun showLoading(loading: Boolean, statusText: String? = null) {
        progressImport.isVisible = loading
        txtImportStatus.isVisible = loading
        txtImportStatus.text = statusText ?: ""
    }

    private fun queryFileName(uri: Uri): String? {
        var name: String? = null
        val cursor = contentResolver.query(uri, null, null, null, null)
        cursor?.use {
            if (it.moveToFirst()) {
                val nameIndex = it.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (nameIndex != -1) {
                    name = it.getString(nameIndex)
                }
            }
        }
        return name
    }

    override fun onDatabaseRetrieved(database: ContextualDatabase) {
        super.onDatabaseRetrieved(database)
    }

    companion object {
        private const val TAG = "ImportWizardActivity"
        const val EXTRA_PARENT_GROUP_ID = "EXTRA_PARENT_GROUP_ID"

        fun launch(context: Context, parentGroupId: GroupId? = null) {
            val intent = Intent(context, ImportWizardActivity::class.java).apply {
                if (parentGroupId != null) {
                    putExtra(EXTRA_PARENT_GROUP_ID, parentGroupId)
                }
            }
            context.startActivity(intent)
        }
    }
}
