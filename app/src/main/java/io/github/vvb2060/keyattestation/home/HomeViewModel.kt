package io.github.vvb2060.keyattestation.home

import android.app.admin.DevicePolicyManager
import android.content.ContentResolver
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import android.security.KeyStoreException
import android.security.KeyStoreException.ERROR_ATTESTATION_KEYS_UNAVAILABLE
import android.security.KeyStoreException.ERROR_ID_ATTESTATION_FAILURE
import android.security.keystore.DeviceIdAttestationException
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import android.widget.Toast
import androidx.core.content.edit
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import io.github.vvb2060.keyattestation.AppApplication
import io.github.vvb2060.keyattestation.attestation.AttestationResult
import io.github.vvb2060.keyattestation.attestation.CertificateInfo.parseCertificateChain
import io.github.vvb2060.keyattestation.keystore.AndroidKeyStore
import io.github.vvb2060.keyattestation.keystore.IAndroidKeyStore
import io.github.vvb2060.keyattestation.keystore.KeyStoreManager
import io.github.vvb2060.keyattestation.lang.AttestationException
import io.github.vvb2060.keyattestation.lang.AttestationException.Companion.CODE_CANT_PARSE_CERT
import io.github.vvb2060.keyattestation.lang.AttestationException.Companion.CODE_DEVICEIDS_UNAVAILABLE
import io.github.vvb2060.keyattestation.lang.AttestationException.Companion.CODE_OUT_OF_KEYS
import io.github.vvb2060.keyattestation.lang.AttestationException.Companion.CODE_OUT_OF_KEYS_TRANSIENT
import io.github.vvb2060.keyattestation.lang.AttestationException.Companion.CODE_STRONGBOX_UNAVAILABLE
import io.github.vvb2060.keyattestation.lang.AttestationException.Companion.CODE_UNAVAILABLE
import io.github.vvb2060.keyattestation.lang.AttestationException.Companion.CODE_UNAVAILABLE_TRANSIENT
import io.github.vvb2060.keyattestation.lang.AttestationException.Companion.CODE_UNKNOWN
import io.github.vvb2060.keyattestation.util.Resource
import rikka.shizuku.Shizuku
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.ObjectInputStream
import java.security.ProviderException
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

class HomeViewModel(pm: PackageManager, private val sp: SharedPreferences) : ViewModel() {

    private val localKeyStore = AndroidKeyStore()
    private var keyStore: IAndroidKeyStore = localKeyStore
    private val certificateFactory = CertificateFactory.getInstance("X.509")

    val attestationResult = MutableLiveData<Resource<AttestationResult>>()
    var currentCerts: List<X509Certificate>? = null

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
            keyStore = if (value) KeyStoreManager.getRemoteKeyStore() else localKeyStore
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

    private fun generateKey(alias: String, attestKeyAlias: String?,
                            useStrongBox: Boolean, includeProps: Boolean,
                            uniqueIdIncluded: Boolean, idAttestationFlags: Int) {
        val e = keyStore.generateKeyPair(alias, attestKeyAlias, useStrongBox, includeProps,
                uniqueIdIncluded, idAttestationFlags)
        if (e != null) {
            ObjectInputStream(ByteArrayInputStream(e)).use {
                val exception = it.readObject() as Exception
                throw exception
            }
        }
    }

    private fun attestDeviceIds(idAttestationFlags: Int, certs: ArrayList<Certificate>) {
        val data = keyStore.attestDeviceIds(idAttestationFlags)
        val s = ByteArrayInputStream(data)
        if (s.read() == 1) {
            certs.addAll(certificateFactory.generateCertificates(s))
        } else {
            ObjectInputStream(s).use {
                val exception = it.readObject() as Exception
                throw ProviderException(exception)
            }
        }
    }

    @Throws(AttestationException::class)
    private fun doAttestation(useAttestKey: Boolean, useStrongBox: Boolean,
                              includeProps: Boolean, uniqueIdIncluded: Boolean,
                              idAttestationFlags: Int): AttestationResult {
        val certs = ArrayList<Certificate>()
        val alias = if (useStrongBox) "${AppApplication.TAG}_strongbox" else AppApplication.TAG
        val attestKeyAlias = if (useAttestKey) "${alias}_persistent" else null
        try {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S && idAttestationFlags != 0) {
                attestDeviceIds(idAttestationFlags, certs)
            } else {
                if (useAttestKey && !keyStore.containsAlias(attestKeyAlias)) {
                    generateKey(attestKeyAlias!!, attestKeyAlias, useStrongBox,
                            includeProps, uniqueIdIncluded, idAttestationFlags)
                }
                generateKey(alias, attestKeyAlias, useStrongBox,
                        includeProps, uniqueIdIncluded, idAttestationFlags)
                val certChain = keyStore.getCertificateChain(alias)
                        ?: throw CertificateException("Unable to get certificate chain")
                val buffer = ByteArrayInputStream(certChain)
                certs.addAll(certificateFactory.generateCertificates(buffer))
                if (useAttestKey) {
                    val persistChain = keyStore.getCertificateChain(attestKeyAlias)
                            ?: throw CertificateException("Unable to get certificate chain")
                    val buf = ByteArrayInputStream(persistChain)
                    certs.addAll(certificateFactory.generateCertificates(buf))
                }
            }
        } catch (e: ProviderException) {
            val cause = e.cause
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && e is StrongBoxUnavailableException) {
                throw AttestationException(CODE_STRONGBOX_UNAVAILABLE, e)
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && cause is KeyStoreException) {
                when (cause.numericErrorCode) {
                    ERROR_ID_ATTESTATION_FAILURE ->
                        throw AttestationException(CODE_DEVICEIDS_UNAVAILABLE, e)
                    ERROR_ATTESTATION_KEYS_UNAVAILABLE -> if (cause.isTransientFailure) {
                        throw AttestationException(CODE_OUT_OF_KEYS_TRANSIENT, e)
                    } else {
                        throw AttestationException(CODE_OUT_OF_KEYS, e)
                    }
                    else -> if (cause.isTransientFailure) {
                        throw AttestationException(CODE_UNAVAILABLE_TRANSIENT, e)
                    } else {
                        throw AttestationException(CODE_UNAVAILABLE, e)
                    }
                }
            } else if (cause?.message?.contains("device ids") == true) {
                throw AttestationException(CODE_DEVICEIDS_UNAVAILABLE, e)
            } else if (cause is DeviceIdAttestationException) {
                throw AttestationException(CODE_DEVICEIDS_UNAVAILABLE, e)
            } else {
                throw AttestationException(CODE_UNAVAILABLE, e)
            }
        } catch (e: Exception) {
            throw AttestationException(CODE_UNKNOWN, e)
        }
        @Suppress("UNCHECKED_CAST")
        currentCerts = certs as ArrayList<X509Certificate>
        return parseCertificateChain(certs)
    }

    fun save(cr: ContentResolver, uri: Uri?) = AppApplication.executor.execute {
        val certs = currentCerts
        if (uri == null || certs == null) return@execute
        var name = uri.toString()
        val projection = arrayOf(OpenableColumns.DISPLAY_NAME)
        cr.query(uri, projection, null, null, null)?.use { cursor ->
            val displayNameColumn = cursor.getColumnIndexOrThrow(OpenableColumns.DISPLAY_NAME)
            if (cursor.moveToFirst()) {
                name = cursor.getString(displayNameColumn)
            }
        }
        try {
            cr.openOutputStream(uri)?.use {
                it.write(certificateFactory.generateCertPath(certs).getEncoded("PKCS7"))
            } ?: throw IOException("openOutputStream $uri failed")
            AppApplication.mainHandler.post {
                Toast.makeText(AppApplication.app, name, Toast.LENGTH_SHORT).show()
            }
        } catch (e: Exception) {
            Log.e(AppApplication.TAG, "saveCerts: ", e)
        }
    }

    fun load(cr: ContentResolver, uri: Uri?) = AppApplication.executor.execute {
        if (uri == null) return@execute
        currentCerts = null
        attestationResult.postValue(Resource.loading(null))

        val result = try {
            val certPath = try {
                cr.openInputStream(uri).use {
                    certificateFactory.generateCertPath(it, "PKCS7")
                }
            } catch (_: CertificateException) {
                cr.openInputStream(uri).use {
                    certificateFactory.generateCertPath(it)
                }
            }
            Resource.success(parseCertificateChain(certPath))
        } catch (e: Throwable) {
            val cause = if (e is AttestationException) e.cause else e
            Log.w(AppApplication.TAG, "Load attestation error.", cause)

            when (e) {
                is AttestationException -> Resource.error(e, null)
                is CertificateException -> Resource.error(AttestationException(CODE_CANT_PARSE_CERT, e), null)
                else -> Resource.error(AttestationException(CODE_UNKNOWN, e), null)
            }
        }

        attestationResult.postValue(result)
    }

    fun load(reset: Boolean = false) = AppApplication.executor.execute {
        currentCerts = null
        attestationResult.postValue(Resource.loading(null))

        val useAttestKey = hasAttestKey && preferAttestKey
        val useStrongBox = hasStrongBox && preferStrongBox
        val includeProps = hasDeviceIds && preferIncludeProps && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
        var uniqueIdIncluded = false
        var flags = 0
        if (preferShizuku) {
            uniqueIdIncluded = canIncludeUniqueId && preferIncludeUniqueId
            if (hasDeviceIds) {
                if (preferIdAttestationSerial) flags = DevicePolicyManager.ID_TYPE_SERIAL
                if (hasIMEI && preferIdAttestationIMEI) flags = flags or DevicePolicyManager.ID_TYPE_IMEI
                if (hasMEID && preferIdAttestationMEID) flags = flags or DevicePolicyManager.ID_TYPE_MEID
            }
        }

        val result = try {
            if (reset) keyStore.deleteAllEntry()
            val attestationResult = doAttestation(useAttestKey, useStrongBox, includeProps,
                    uniqueIdIncluded, flags)
            Resource.success(attestationResult)
        } catch (e: Throwable) {
            val cause = if (e is AttestationException) e.cause else e
            Log.w(AppApplication.TAG, "Do attestation error.", cause)

            when (e) {
                is AttestationException -> Resource.error(e, null)
                else -> Resource.error(AttestationException(CODE_UNKNOWN, e), null)
            }
        }

        attestationResult.postValue(result)
    }
}
