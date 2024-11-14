package io.github.vvb2060.keyattestation.home

import android.app.admin.DevicePolicyManager
import android.content.ContentResolver
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import android.util.Log
import android.widget.Toast
import androidx.core.content.edit
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import io.github.vvb2060.keyattestation.AppApplication
import io.github.vvb2060.keyattestation.attestation.AttestationResult
import io.github.vvb2060.keyattestation.keystore.AttestationManager
import io.github.vvb2060.keyattestation.keystore.KeyStoreManager
import io.github.vvb2060.keyattestation.util.Resource
import rikka.shizuku.Shizuku

class HomeViewModel(pm: PackageManager, private val sp: SharedPreferences) : ViewModel() {

    private val attestationManager = AttestationManager()
    private val attestationResult = MutableLiveData<Resource<AttestationResult>>()

    val hasStrongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            pm.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
    var preferStrongBox = sp.getBoolean("prefer_strongbox", true)
        set(value) {
            field = value
            sp.edit { putBoolean("prefer_strongbox", value) }
        }

    val hasAttestKey = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
            pm.hasSystemFeature(PackageManager.FEATURE_KEYSTORE_APP_ATTEST_KEY)
    var preferAttestKey = sp.getBoolean("prefer_attest_key", true)
        set(value) {
            field = value
            sp.edit { putBoolean("prefer_attest_key", value) }
        }

    val hasDeviceIds = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            pm.hasSystemFeature("android.software.device_id_attestation")
    var preferIncludeProps = sp.getBoolean("prefer_include_props", true)
        set(value) {
            field = value
            sp.edit { putBoolean("prefer_include_props", value) }
        }

    var preferShizuku = false
        set(value) {
            field = value
            attestationManager.useRemoteKeyStore(value)
        }

    var preferIdAttestationSerial = sp.getBoolean("prefer_id_attestation_serial", true)
        set(value) {
            field = value
            sp.edit { putBoolean("prefer_id_attestation_serial", value) }
        }

    val hasIMEI = pm.hasSystemFeature(PackageManager.FEATURE_TELEPHONY_GSM)
    var preferIdAttestationIMEI = sp.getBoolean("prefer_id_attestation_IMEI", true)
        set(value) {
            field = value
            sp.edit { putBoolean("prefer_id_attestation_IMEI", value) }
        }

    val hasMEID = pm.hasSystemFeature(PackageManager.FEATURE_TELEPHONY_CDMA)
    var preferIdAttestationMEID = sp.getBoolean("prefer_id_attestation_MEID", true)
        set(value) {
            field = value
            sp.edit { putBoolean("prefer_id_attestation_MEID", value) }
        }

    val canIncludeUniqueId: Boolean
        get() {
            if (KeyStoreManager.getRemoteKeyStore() == null) return false
            val name = "android.permission.REQUEST_UNIQUE_ID_ATTESTATION"
            return Shizuku.checkRemotePermission(name) == PackageManager.PERMISSION_GRANTED
        }
    var preferIncludeUniqueId = sp.getBoolean("prefer_include_unique_id", true)
        set(value) {
            field = value
            sp.edit { putBoolean("prefer_include_unique_id", value) }
        }

    init {
        load()
    }

    fun hasCertificates() = attestationManager.hasCertificates()

    fun getAttestationResult(): LiveData<Resource<AttestationResult>> = attestationResult

    fun save(cr: ContentResolver, uri: Uri?) = AppApplication.executor.execute {
        if (uri == null || !attestationManager.hasCertificates()) return@execute
        var name = uri.toString()
        val projection = arrayOf(OpenableColumns.DISPLAY_NAME)
        cr.query(uri, projection, null, null, null)?.use { cursor ->
            val displayNameColumn = cursor.getColumnIndexOrThrow(OpenableColumns.DISPLAY_NAME)
            if (cursor.moveToFirst()) {
                name = cursor.getString(displayNameColumn)
            }
        }
        try {
            attestationManager.saveCerts(cr, uri)
            AppApplication.mainHandler.post {
                Toast.makeText(AppApplication.app, name, Toast.LENGTH_SHORT).show()
            }
        } catch (e: Exception) {
            Log.e(AppApplication.TAG, "saveCerts: ", e)
        }
    }

    fun load(cr: ContentResolver, uri: Uri?) = AppApplication.executor.execute {
        if (uri == null) return@execute
        attestationResult.postValue(Resource.loading(null))
        val result = attestationManager.loadCerts(cr, uri)
        attestationResult.postValue(result)
    }

    fun load(reset: Boolean = false) = AppApplication.executor.execute {
        attestationResult.postValue(Resource.loading(null))

        val useAttestKey = hasAttestKey && preferAttestKey
        val useStrongBox = hasStrongBox && preferStrongBox
        val includeProps = hasDeviceIds && preferIncludeProps && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
        var uniqueIdIncluded = false
        var idFlags = 0
        if (preferShizuku) {
            uniqueIdIncluded = canIncludeUniqueId && preferIncludeUniqueId
            if (hasDeviceIds) {
                if (preferIdAttestationSerial) idFlags = DevicePolicyManager.ID_TYPE_SERIAL
                if (hasIMEI && preferIdAttestationIMEI) idFlags = idFlags or DevicePolicyManager.ID_TYPE_IMEI
                if (hasMEID && preferIdAttestationMEID) idFlags = idFlags or DevicePolicyManager.ID_TYPE_MEID
            }
        }

        val result = attestationManager.attest(reset, useAttestKey, useStrongBox,
                includeProps, uniqueIdIncluded, idFlags)
        attestationResult.postValue(result)
    }
}
