package io.github.vvb2060.keyattestation.home

import android.app.admin.DevicePolicyManager
import android.content.ContentResolver
import android.content.Context
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import android.util.Log
import androidx.core.content.edit
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelProvider.AndroidViewModelFactory.Companion.APPLICATION_KEY
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import io.github.vvb2060.keyattestation.AppApplication
import io.github.vvb2060.keyattestation.keystore.KeyStoreManager
import io.github.vvb2060.keyattestation.repository.AttestationRepository
import io.github.vvb2060.keyattestation.repository.BaseData
import io.github.vvb2060.keyattestation.util.Resource
import rikka.shizuku.Shizuku

class HomeViewModel(
        pm: PackageManager,
        private val cr: ContentResolver,
        private val sp: SharedPreferences,
) : ViewModel() {
    companion object {
        val Factory: ViewModelProvider.Factory = viewModelFactory {
            initializer {
                val app = this[APPLICATION_KEY]!!
                val sp = app.getSharedPreferences("settings", Context.MODE_PRIVATE)
                HomeViewModel(app.packageManager, app.contentResolver, sp)
            }
        }
    }

    private val attestationRepository = AttestationRepository()
    private val attestationData = MutableLiveData<Resource<BaseData>>()

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
            attestationRepository.useRemoteKeyStore(value)
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

    val canCheckRkp: Boolean
        get() {
            if (KeyStoreManager.getRemoteKeyStore() == null) return false
            return attestationRepository.canRkp(false)
        }

    init {
        load()
    }

    fun hasCertificates() = attestationRepository.hasCertificates()

    fun getAttestationData(): LiveData<Resource<BaseData>> = attestationData

    fun save(uri: Uri?) = AppApplication.executor.execute {
        if (uri == null || !attestationRepository.hasCertificates()) return@execute

        var name = uri.toString()
        val projection = arrayOf(OpenableColumns.DISPLAY_NAME)
        cr.query(uri, projection, null, null, null)?.use { cursor ->
            val displayNameColumn = cursor.getColumnIndexOrThrow(OpenableColumns.DISPLAY_NAME)
            if (cursor.moveToFirst()) {
                name = cursor.getString(displayNameColumn)
            }
        }

        try {
            cr.openOutputStream(uri).use {
                attestationRepository.saveCerts(it)
            }
            AppApplication.toast(name)
        } catch (e: Exception) {
            Log.e(AppApplication.TAG, "save: ", e)
            AppApplication.toast(e.message)
        }
    }

    fun load(uri: Uri?) = AppApplication.executor.execute {
        if (uri == null) return@execute

        attestationData.postValue(Resource.loading(null))

        val result = cr.openFileDescriptor(uri, "r").use {
            attestationRepository.loadCerts(it)
        }

        attestationData.postValue(result)
    }

    fun load(reset: Boolean = false) = AppApplication.executor.execute {
        attestationData.postValue(Resource.loading(null))

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

        val result = attestationRepository.attest(reset, useAttestKey, useStrongBox,
                includeProps, uniqueIdIncluded, idFlags)

        attestationData.postValue(result)
    }

    fun import(uri: Uri?) = AppApplication.executor.execute {
        if (uri == null || !hasAttestKey) return@execute

        val useStrongBox = hasStrongBox && preferStrongBox
        try {
            cr.openFileDescriptor(uri, "r").use {
                attestationRepository.importKeyBox(useStrongBox, it)
            }
            load()
        } catch (e: Exception) {
            Log.e(AppApplication.TAG, "import: ", e)
            AppApplication.toast(e.message)
        }
    }

    fun rkp(newHostname: String? = null) = AppApplication.executor.execute {
        if (!canCheckRkp && !preferShizuku) return@execute

        attestationData.postValue(Resource.loading(null))

        val useStrongBox = hasStrongBox && preferStrongBox && attestationRepository.canRkp(true)
        attestationRepository.setHostname(newHostname)
        val result = attestationRepository.checkRkp(useStrongBox)

        attestationData.postValue(result)
    }
}
