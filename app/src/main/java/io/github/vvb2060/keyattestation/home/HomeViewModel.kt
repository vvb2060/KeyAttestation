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

    private suspend fun doAttestation(context: Context, useStrongBox: Boolean) = withContext(Dispatchers.IO) {
        val certs: Array<X509Certificate?>?
        val attestation: Attestation
        val isGoogleRootCertificate: Boolean
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            generateKey(ALIAS, useStrongBox)
            val certificates = keyStore.getCertificateChain(ALIAS)
            certs = arrayOfNulls(certificates.size)
            for (i in certs.indices) certs[i] = certificates[i] as X509Certificate
        } catch (e: ProviderException) {
            if (Build.VERSION.SDK_INT >= 28 && e is StrongBoxUnavailableException) {
                throw AttestationException("Strong box key attestation error.", e)
            } else {
                throw AttestationException("The device does not support key attestation.", e)
            }
        } catch (e: Exception) {
            throw AttestationException("Unable to get certificate.", e)
        }
        try {
            isGoogleRootCertificate = VerifyCertificateChain.verifyCertificateChain(certs, context.resources.openRawResource(R.raw.status))
        } catch (e: Exception) {
            throw AttestationException("Certificate is not trusted.", e)
        }
        try {
            attestation = Attestation(certs[0])
        } catch (e: CertificateParsingException) {
            throw AttestationException("Unable to parse attestation record.", e)
        }
        AttestationResult(attestation, isGoogleRootCertificate)
    }

    fun invalidateAttestation(context: Context, useStrongBox: Boolean) = viewModelScope.launch {
        try {
            attestationResult.postValue(Resource.success(doAttestation(context, useStrongBox)))
        } catch (e: CancellationException) {

        } catch (e: AttestationException) {
            attestationResult.postValue(Resource.error(e, null))
        } catch (e: Throwable) {
            attestationResult.postValue(Resource.error(AttestationException("unknown", e), null))
        }
    }
}