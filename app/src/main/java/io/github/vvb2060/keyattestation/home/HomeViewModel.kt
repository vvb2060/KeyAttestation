package io.github.vvb2060.keyattestation.home

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import io.github.vvb2060.keyattestation.AppApplication
import io.github.vvb2060.keyattestation.attestation.Attestation
import io.github.vvb2060.keyattestation.attestation.AttestationResult
import io.github.vvb2060.keyattestation.attestation.VerifyCertificateChain
import io.github.vvb2060.keyattestation.lang.AttestationException
import io.github.vvb2060.keyattestation.util.Resource
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.GeneralSecurityException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.ProviderException
import java.security.cert.CertificateParsingException
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.*

class HomeViewModel(context: Context) : ViewModel() {

    val attestationResult = MutableLiveData<Resource<AttestationResult>>()

    val hasStrongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
    var preferStrongBox = true

    val hasDeviceIds = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
            context.packageManager.hasSystemFeature("android.software.device_id_attestation")
    var preferIncludeProps = true

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
        if (Build.VERSION.SDK_INT >= 28 && useStrongBox) {
            builder.setIsStrongBoxBacked(true)
        }
        builder.setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256)
        keyPairGenerator.initialize(builder.build())
        keyPairGenerator.generateKeyPair()
    }

    @Throws(AttestationException::class)
    private fun doAttestation(alias: String, useStrongBox: Boolean, includeProps: Boolean
    ): AttestationResult {
        val certs: Array<X509Certificate?>?
        val attestation: Attestation
        val isGoogleRootCertificate: Boolean
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            generateKey(alias, useStrongBox, includeProps)
            val certificates = keyStore.getCertificateChain(alias)
            certs = arrayOfNulls(certificates.size)
            for (i in certs.indices) certs[i] = certificates[i] as X509Certificate
        } catch (e: ProviderException) {
            if (Build.VERSION.SDK_INT >= 28 && e is StrongBoxUnavailableException) {
                throw AttestationException(AttestationException.CODE_STRONGBOX_UNAVAILABLE, e)
            } else if (e.cause?.message?.contains("device ids") == true) {
                // The device does not support device ids attestation
                throw AttestationException(AttestationException.CODE_DEVICEIDS_UNAVAILABLE, e)
            } else {
                // The device does not support key attestation
                throw AttestationException(AttestationException.CODE_NOT_SUPPORT, e)
            }
        } catch (e: Exception) {
            // Unable to get certificate
            throw AttestationException(AttestationException.CODE_NOT_SUPPORT, e)
        }
        try {
            isGoogleRootCertificate = VerifyCertificateChain.verifyCertificateChain(certs)
        } catch (e: GeneralSecurityException) {
            // Certificate is not trusted
            throw AttestationException(AttestationException.CODE_CERT_NOT_TRUSTED, e)
        }
        try {
            attestation = Attestation.loadFromCertificate(certs[0])
        } catch (e: CertificateParsingException) {
            // Unable to parse attestation record
            throw AttestationException(AttestationException.CODE_CANT_PARSE_ATTESTATION_RECORD, e)
        }

        return AttestationResult(useStrongBox, attestation, isGoogleRootCertificate)
    }

    fun load() = viewModelScope.launch {
        attestationResult.value = Resource.loading(null)

        withContext(Dispatchers.IO) {
            val useStrongBox = hasStrongBox && preferStrongBox
            val includeProps = hasDeviceIds && preferIncludeProps
            val result = try {
                val alias = "Key_${useStrongBox}_$includeProps"
                val attestationResult = doAttestation(alias, useStrongBox, includeProps)
                Resource.success(attestationResult)
            } catch (e: Throwable) {
                val cause = if (e is AttestationException) e.cause!! else e
                Log.w(AppApplication.TAG, "Do attestation error.", cause)

                if (e is AttestationException) {
                    Resource.error(e, null)
                } else {
                    Resource.error(AttestationException(AttestationException.CODE_UNKNOWN, e), null)
                }
            }

            attestationResult.postValue(result)
        }
    }
}
