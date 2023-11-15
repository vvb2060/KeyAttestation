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
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date
import javax.security.auth.x500.X500Principal

class HomeViewModel(pm: PackageManager, private val sp: SharedPreferences) : ViewModel() {

    private val keyStore = KeyStore.getInstance("AndroidKeyStore")
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

    val hasDeviceIds = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
            pm.hasSystemFeature("android.software.device_id_attestation")
    var preferIncludeProps = sp.getBoolean("prefer_including_props", true)
        set(value) {
            field = value
            sp.edit { putBoolean("prefer_including_props", value) }
        }

    init {
        keyStore.load(null)
        load()
    }

    @Throws(GeneralSecurityException::class)
    private fun generateKey(alias: String,
                            useStrongBox: Boolean,
                            includeProps: Boolean,
                            attestKeyAlias: String?) {
        val now = Date()
        val attestKey = alias == attestKeyAlias
        val purposes = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && attestKey) {
            KeyProperties.PURPOSE_ATTEST_KEY
        } else {
            KeyProperties.PURPOSE_SIGN
        }
        val builder = KeyGenParameterSpec.Builder(alias, purposes)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setCertificateNotBefore(now)
                .setAttestationChallenge(now.toString().toByteArray())
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && useStrongBox) {
            builder.setIsStrongBoxBacked(true)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            if (includeProps) {
                builder.setDevicePropertiesAttestationIncluded(true)
            }
            if (attestKey) {
                builder.setCertificateSubject(X500Principal("CN=App Attest Key"))
            } else {
                builder.setAttestKeyAlias(attestKeyAlias)
            }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && SamsungUtils.isSecAttestationSupported()) {
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
    private fun doAttestation(useStrongBox: Boolean,
                              includeProps: Boolean,
                              useAttestKey: Boolean): AttestationResult {
        val certs = ArrayList<Certificate>()
        val alias = if (useStrongBox) "${AppApplication.TAG}_strongbox" else AppApplication.TAG
        val attestKeyAlias = if (useAttestKey) "${alias}_persistent" else null
        try {
            if (useAttestKey && !keyStore.containsAlias(attestKeyAlias)) {
                generateKey(attestKeyAlias!!, useStrongBox, includeProps, attestKeyAlias)
            }
            generateKey(alias, useStrongBox, includeProps, attestKeyAlias)

            val certChain = keyStore.getCertificateChain(alias)
                    ?: throw CertificateException("Unable to get certificate chain")
            for (cert in certChain) {
                val buf = ByteArrayInputStream(cert.encoded)
                certs.add(certificateFactory.generateCertificate(buf))
            }
            if (useAttestKey) {
                val persistChain = keyStore.getCertificateChain(attestKeyAlias)
                        ?: throw CertificateException("Unable to get certificate chain")
                for (cert in persistChain) {
                    val buf = ByteArrayInputStream(cert.encoded)
                    certs.add(certificateFactory.generateCertificate(buf))
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
        if (reset) {
            for (alias in keyStore.aliases()) {
                keyStore.deleteEntry(alias)
            }
        }

        val useStrongBox = hasStrongBox && preferStrongBox
        val includeProps = hasDeviceIds && preferIncludeProps
        val useAttestKey = hasAttestKey && preferAttestKey
        val result = try {
            val attestationResult = doAttestation(useStrongBox, includeProps, useAttestKey)
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
