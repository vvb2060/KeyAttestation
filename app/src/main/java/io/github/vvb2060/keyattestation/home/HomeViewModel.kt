package io.github.vvb2060.keyattestation.home

import android.content.ContentResolver
import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import android.widget.Toast
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import io.github.vvb2060.keyattestation.AppApplication
import io.github.vvb2060.keyattestation.BuildConfig
import io.github.vvb2060.keyattestation.attestation.Attestation
import io.github.vvb2060.keyattestation.attestation.AttestationResult
import io.github.vvb2060.keyattestation.attestation.VerifyCertificateChain
import io.github.vvb2060.keyattestation.lang.AttestationException
import io.github.vvb2060.keyattestation.lang.AttestationException.Companion.CODE_CANT_PARSE_CERT
import io.github.vvb2060.keyattestation.lang.AttestationException.Companion.CODE_CERT_NOT_TRUSTED
import io.github.vvb2060.keyattestation.lang.AttestationException.Companion.CODE_DEVICEIDS_UNAVAILABLE
import io.github.vvb2060.keyattestation.lang.AttestationException.Companion.CODE_NOT_SUPPORT
import io.github.vvb2060.keyattestation.lang.AttestationException.Companion.CODE_STRONGBOX_UNAVAILABLE
import io.github.vvb2060.keyattestation.lang.AttestationException.Companion.CODE_UNKNOWN
import io.github.vvb2060.keyattestation.util.Resource
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.ByteArrayInputStream
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.ProviderException
import java.security.Security
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.CertificateParsingException
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date

class HomeViewModel(pm: PackageManager) : ViewModel() {

    val attestationResult = MutableLiveData<Resource<AttestationResult>>()
    var currentCerts: List<X509Certificate>? = null

    val hasStrongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            pm.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
    var preferStrongBox = true

    val hasDeviceIds = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
            pm.hasSystemFeature("android.software.device_id_attestation")
    var preferIncludeProps = true

    var showSkipVerify = false
    var preferSkipVerify = false

    @Throws(GeneralSecurityException::class)
    private fun generateKey(alias: String, useStrongBox: Boolean, includeProps: Boolean) {
        val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        val now = Date()
        val originationEnd = Date(now.time + 1000000)
        val consumptionEnd = Date(now.time + 2000000)
        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setKeyValidityStart(now)
                .setKeyValidityForOriginationEnd(originationEnd)
                .setKeyValidityForConsumptionEnd(consumptionEnd)
                .setAttestationChallenge(now.toString().toByteArray())
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && includeProps) {
            builder.setDevicePropertiesAttestationIncluded(true)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && useStrongBox) {
            builder.setIsStrongBoxBacked(true)
        }
        builder.setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256)
        keyPairGenerator.initialize(builder.build())
        keyPairGenerator.generateKeyPair()
    }

    @Throws(AttestationException::class)
    private fun parseCertificateChain(certs: List<X509Certificate>): AttestationResult {
        var attestation: Attestation? = null
        var exception: AttestationException? = null
        var isGoogleRootCertificate = VerifyCertificateChain.FAILED
        try {
            isGoogleRootCertificate = VerifyCertificateChain.verifyCertificateChain(certs)
        } catch (e: GeneralSecurityException) {
            if (!preferSkipVerify) throw AttestationException(CODE_CERT_NOT_TRUSTED, e)
        }
        // Find first attestation record
        // Never use certs[0], as certificate chain can have arbitrary certificates appended
        for (i in certs.indices.reversed()) {
            try {
                attestation = Attestation.loadFromCertificate(certs[i])
                break
            } catch (e: CertificateParsingException) {
                exception = AttestationException(CODE_CANT_PARSE_CERT, e)
            }
        }
        if (attestation == null) {
            throw exception!!
        }
        return AttestationResult(attestation, isGoogleRootCertificate)
    }

    @Throws(AttestationException::class)
    private fun doAttestation(alias: String, useStrongBox: Boolean, includeProps: Boolean
    ): AttestationResult {
        val certs: List<Certificate>
        try {
            generateKey(alias, useStrongBox, includeProps)
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            val certificates = keyStore.getCertificateChain(alias)
            certs = ArrayList(certificates.size)
            val cf = CertificateFactory.getInstance("X.509")
            for (i in certificates.indices) {
                val buf = ByteArrayInputStream(certificates[i].encoded)
                certs.add(cf.generateCertificate(buf))
            }
        } catch (e: ProviderException) {
            if (Build.VERSION.SDK_INT >= 28 && e is StrongBoxUnavailableException) {
                throw AttestationException(CODE_STRONGBOX_UNAVAILABLE, e)
            } else if (e.cause?.message?.contains("device ids") == true) {
                // The device does not support device ids attestation
                throw AttestationException(CODE_DEVICEIDS_UNAVAILABLE, e)
            } else {
                // The device does not support key attestation
                throw AttestationException(CODE_NOT_SUPPORT, e)
            }
        } catch (e: Exception) {
            // Unable to get certificate chain
            throw AttestationException(CODE_NOT_SUPPORT, e)
        }
        @Suppress("UNCHECKED_CAST")
        this.currentCerts = certs as List<X509Certificate>
        return parseCertificateChain(certs)
    }

    fun save(cr: ContentResolver, uri: Uri?) = viewModelScope.launch(Dispatchers.IO) {
        val certs = currentCerts
        if (uri == null || certs == null) return@launch
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
                it.write(cf.generateCertPath(certs).encoded)
            } ?: throw IOException("openOutputStream $uri failed")
            withContext(Dispatchers.Main) {
                Toast.makeText(AppApplication.App, name, Toast.LENGTH_SHORT).show()
            }
        } catch (e: Exception) {
            Log.e(AppApplication.TAG, "saveCerts: ", e)
        }
    }

    fun load(cr: ContentResolver, uri: Uri?) = viewModelScope.launch(Dispatchers.IO) {
        if (uri == null) return@launch
        this@HomeViewModel.currentCerts = null
        attestationResult.postValue(Resource.loading(null))

        val result = try {
            val cf = CertificateFactory.getInstance("X.509")
            cr.openInputStream(uri).use {
                @Suppress("UNCHECKED_CAST")
                val certs = cf.generateCertPath(it).certificates as List<X509Certificate>
                if (certs.isEmpty()) throw CertificateParsingException("No certificate found")
                val attestationResult = parseCertificateChain(certs)
                Resource.success(attestationResult)
            }
        } catch (e: Throwable) {
            val cause = if (e is AttestationException) e.cause!! else e
            Log.w(AppApplication.TAG, "Load attestation error.", cause)

            when (e) {
                is AttestationException -> Resource.error(e, null)
                is CertificateException -> Resource.error(AttestationException(CODE_CANT_PARSE_CERT, e), null)
                else -> Resource.error(AttestationException(CODE_UNKNOWN, e), null)
            }
        }

        attestationResult.postValue(result)
    }

    fun load() = viewModelScope.launch(Dispatchers.IO) {
        attestationResult.postValue(Resource.loading(null))

        val useStrongBox = hasStrongBox && preferStrongBox
        val includeProps = hasDeviceIds && preferIncludeProps
        val result = try {
            val alias = "Key_${useStrongBox}_$includeProps"
            val attestationResult = doAttestation(alias, useStrongBox, includeProps)
            Resource.success(attestationResult)
        } catch (e: Throwable) {
            val cause = if (e is AttestationException) e.cause!! else e
            Log.w(AppApplication.TAG, "Do attestation error.", cause)

            when (e) {
                is AttestationException -> Resource.error(e, null)
                else -> Resource.error(AttestationException(CODE_UNKNOWN, e), null)
            }
        }

        attestationResult.postValue(result)
    }

    fun install(context: Context) = viewModelScope.launch(Dispatchers.IO) {
        if (BuildConfig.DEBUG) {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
            return@launch
        }
        runCatching {
            val gms = context.createPackageContext("com.google.android.gms",
                    Context.CONTEXT_INCLUDE_CODE or Context.CONTEXT_IGNORE_SECURITY)
            gms.classLoader
                    .loadClass("com.google.android.gms.common.security.ProviderInstallerImpl")
                    .getMethod("insertProvider", Context::class.java)
                    .invoke(null, gms)
        }
    }
}
