package io.github.vvb2060.keyattestation.home

import android.content.ContentResolver
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import android.security.KeyStoreException
import android.security.KeyStoreException.ERROR_ATTESTATION_KEYS_UNAVAILABLE
import android.security.KeyStoreException.ERROR_ID_ATTESTATION_FAILURE
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import android.widget.Toast
import androidx.core.content.edit
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import com.samsung.android.security.keystore.AttestParameterSpec
import com.samsung.android.security.keystore.AttestationUtils
import io.github.vvb2060.keyattestation.AppApplication
import io.github.vvb2060.keyattestation.attestation.AttestationResult
import io.github.vvb2060.keyattestation.attestation.CertificateInfo.parseCertificateChain
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
import io.github.vvb2060.keyattestation.util.SamsungUtils
import java.io.BufferedInputStream
import java.io.ByteArrayInputStream
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.ProviderException
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.CertificateParsingException
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date
import javax.security.auth.x500.X500Principal

class HomeViewModel(pm: PackageManager, private val sp: SharedPreferences) : ViewModel() {

    val attestationResult = MutableLiveData<Resource<AttestationResult>>()
    var currentCerts: List<X509Certificate>? = null

    val hasSAK = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q &&
            SamsungUtils.isSecAttestationSupported()
    var preferSAK = sp.getBoolean("prefer_sak", hasSAK)
        set(value) {
            field = value
            sp.edit { putBoolean("prefer_sak", value) }
        }

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

    val hasDeviceIds = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
            pm.hasSystemFeature("android.software.device_id_attestation")
    var preferIncludeProps = sp.getBoolean("prefer_including_props", true)
        set(value) {
            field = value
            sp.edit { putBoolean("prefer_including_props", value) }
        }

    var preferShowAll = sp.getBoolean("prefer_show_all", false)
        set(value) {
            field = value
            sp.edit { putBoolean("prefer_show_all", value) }
        }

    init {
        load()
    }

    @Throws(GeneralSecurityException::class)
    private fun generateKey(alias: String,
                            useSAK: Boolean,
                            useStrongBox: Boolean,
                            includeProps: Boolean,
                            attestKeyAlias: String?) {
        val now = Date()
        val attestKey = alias == attestKeyAlias
        val purposes = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && attestKey) {
            KeyProperties.PURPOSE_ATTEST_KEY
        } else {
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        }
        val builder = KeyGenParameterSpec.Builder(alias, purposes)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setKeyValidityStart(now)
                .setAttestationChallenge(now.toString().toByteArray())
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && useStrongBox) {
            builder.setIsStrongBoxBacked(true)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            if (includeProps) {
                builder.setDevicePropertiesAttestationIncluded(true)
            }
            if (attestKeyAlias != null && !attestKey) {
                builder.setAttestKeyAlias(attestKeyAlias)
            }
            if (attestKey) {
                builder.setCertificateSubject(X500Principal("CN=App Attest Key"))
            }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && useSAK) {
            val spec = AttestParameterSpec.Builder(alias, now.toString().toByteArray())
                .setAlgorithm(KeyProperties.KEY_ALGORITHM_EC)
                .setKeyGenParameterSpec(builder.build())
                .setVerifiableIntegrity(true)
                .setPackageName(AppApplication.app.packageName)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && includeProps) {
                spec.setDevicePropertiesAttestationIncluded(true)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && attestKey) {
                spec.setCertificateSubject(X500Principal("CN=App Attest Key"))
            }
            AttestationUtils().generateKeyPair(spec.build())
        } else {
            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            keyPairGenerator.initialize(builder.build())
            keyPairGenerator.generateKeyPair()
        }
    }

    @Throws(AttestationException::class)
    private fun doAttestation(useSAK: Boolean,
                              useStrongBox: Boolean,
                              includeProps: Boolean,
                              useAttestKey: Boolean): AttestationResult {
        val certs: List<Certificate>
        val alias = AppApplication.TAG
        val attestKeyAlias = if (useAttestKey) "${alias}_persistent" else null
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            if (useAttestKey && !keyStore.containsAlias(attestKeyAlias)) {
                generateKey(attestKeyAlias!!, useSAK, useStrongBox, includeProps, attestKeyAlias)
            }
            generateKey(alias, useSAK, useStrongBox, includeProps, attestKeyAlias)
            val chainAlias = if (useAttestKey) attestKeyAlias else alias
            val certificates = keyStore.getCertificateChain(chainAlias)
                    ?: throw CertificateException("Unable to get certificate chain")
            certs = ArrayList()
            val cf = CertificateFactory.getInstance("X.509")
            if (useAttestKey) {
                val certificate = keyStore.getCertificate(alias)
                        ?: throw CertificateException("Unable to get certificate")
                val buf = ByteArrayInputStream(certificate.encoded)
                certs.add(cf.generateCertificate(buf))
            }
            for (i in certificates.indices) {
                val buf = ByteArrayInputStream(certificates[i].encoded)
                certs.add(cf.generateCertificate(buf))
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
            } else {
                throw AttestationException(CODE_UNAVAILABLE, e)
            }
        } catch (e: Exception) {
            throw AttestationException(CODE_UNKNOWN, e)
        }
        @Suppress("UNCHECKED_CAST")
        currentCerts = certs as List<X509Certificate>
        return parseCertificateChain(certs)
    }

    fun save(cr: ContentResolver, uri: Uri?, encoding: String) = AppApplication.executor.execute {
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
            val cf = CertificateFactory.getInstance("X.509")
            cr.openOutputStream(uri)?.use {
                it.write(cf.generateCertPath(certs).getEncoded(encoding))
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
            val cf = CertificateFactory.getInstance("X.509")
            val certPath = BufferedInputStream(cr.openInputStream(uri)).use {
                try {
                    it.mark(8192)
                    cf.generateCertPath(it, "PkiPath")
                } catch (_: CertificateException) {
                    it.reset()
                    cf.generateCertPath(it, "PKCS7")
                }
            }
            if (certPath.certificates.isEmpty()) {
                throw CertificateParsingException("No certificate found")
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

    fun load() = AppApplication.executor.execute {
        currentCerts = null
        attestationResult.postValue(Resource.loading(null))

        val useSAK = hasSAK && preferSAK
        val useStrongBox = hasStrongBox && preferStrongBox
        val includeProps = hasDeviceIds && preferIncludeProps
        val useAttestKey = hasAttestKey && preferAttestKey && !useSAK
        val result = try {
            val attestationResult = doAttestation(useSAK, useStrongBox, includeProps, useAttestKey)
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
