package io.github.vvb2060.keyattestation.home

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.lifecycle.MediatorLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import io.github.vvb2060.keyattestation.R
import io.github.vvb2060.keyattestation.attestation.Attestation
import io.github.vvb2060.keyattestation.attestation.AttestationResult
import io.github.vvb2060.keyattestation.attestation.VerifyCertificateChain
import io.github.vvb2060.keyattestation.lang.AttestationException
import io.github.vvb2060.keyattestation.util.Resource
import kotlinx.coroutines.CancellationException
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

class HomeViewModel : ViewModel() {

    companion object {

        private const val ALIAS = "Key1"
        private const val ORIGINATION_TIME_OFFSET = 1000000
        private const val CONSUMPTION_TIME_OFFSET = 2000000
    }

    val attestationResult = MediatorLiveData<Resource<AttestationResult>>()

    @Throws(GeneralSecurityException::class)
    private fun generateKey(alias: String, useStrongBox: Boolean) {
        val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        val now = Date()
        val originationEnd = Date(now.time + ORIGINATION_TIME_OFFSET)
        val consumptionEnd = Date(now.time + CONSUMPTION_TIME_OFFSET)
        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setKeyValidityStart(now)
                .setKeyValidityForOriginationEnd(originationEnd)
                .setKeyValidityForConsumptionEnd(consumptionEnd)
                .setAttestationChallenge("key attestation test".toByteArray())
        if (Build.VERSION.SDK_INT >= 28 && useStrongBox) {
            builder.setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256)
            builder.setIsStrongBoxBacked(true)
        } else {
            builder.setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
        }
        keyPairGenerator.initialize(builder.build())
        keyPairGenerator.generateKeyPair()
    }

    private suspend fun doAttestation(context: Context, useStrongBox: Boolean, strongBoxUnavailable: Boolean): AttestationResult {
        val certs: Array<X509Certificate?>?
        val attestation: Attestation
        val isGoogleRootCertificate: Boolean
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            generateKey(ALIAS, useStrongBox && !strongBoxUnavailable)
            val certificates = keyStore.getCertificateChain(ALIAS)
            certs = arrayOfNulls(certificates.size)
            for (i in certs.indices) certs[i] = certificates[i] as X509Certificate
        } catch (e: ProviderException) {
            if (Build.VERSION.SDK_INT >= 28 && e is StrongBoxUnavailableException) {
                return doAttestation(context, useStrongBox, strongBoxUnavailable)
            } else {
                // The device does not support key attestation
                throw AttestationException(AttestationException.CODE_NOT_SUPPORT, e)
            }
        } catch (e: Exception) {
            // Unable to get certificate
            // throw AttestationException(AttestationException.CODE_CANT_GET_CERT, e)
            throw AttestationException(AttestationException.CODE_NOT_SUPPORT, e)
        }
        try {
            isGoogleRootCertificate = VerifyCertificateChain.verifyCertificateChain(certs, context.resources.openRawResource(R.raw.status))
        } catch (e: Exception) {
            // Certificate is not trusted
            throw AttestationException(AttestationException.CODE_CERT_NOT_TRUSTED, e)
        }
        try {
            attestation = Attestation(certs[0])
        } catch (e: CertificateParsingException) {
            // Unable to parse attestation record
            throw AttestationException(AttestationException.CODE_CANT_PARSE_ATTESTATION_RECORD, e)
        }
        return AttestationResult(attestation, isGoogleRootCertificate, strongBoxUnavailable)
    }

    fun invalidateAttestation(context: Context, preferStrongBox: Boolean) = viewModelScope.launch {
        try {
            withContext(Dispatchers.IO) {
                Resource.success(doAttestation(context, preferStrongBox, false))
            }
        } catch (e: CancellationException) {
            null
        } catch (e: AttestationException) {
            Resource.error(e, null)
        } catch (e: Throwable) {
            Resource.error(AttestationException(AttestationException.CODE_UNKNOWN, e), null)
        }?.let {
            attestationResult.postValue(it)
        }
    }
}