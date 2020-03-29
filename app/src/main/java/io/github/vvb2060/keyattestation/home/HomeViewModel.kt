package io.github.vvb2060.keyattestation.home

import android.content.Context
import android.content.pm.PackageManager
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

        private const val ORIGINATION_TIME_OFFSET = 1000000
        private const val CONSUMPTION_TIME_OFFSET = 2000000
    }

    val attestationResult = MediatorLiveData<Resource<AttestationResult>>()

    var preferStrongBox = true

    val hasStrongBox = MediatorLiveData<Boolean>()

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

    private fun doAttestation(context: Context, alias: String, useStrongBox: Boolean): AttestationResult {
        val certs: Array<X509Certificate?>?
        val attestation: Attestation
        val isGoogleRootCertificate: Boolean
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            generateKey(alias, useStrongBox)
            val certificates = keyStore.getCertificateChain(alias)
            certs = arrayOfNulls(certificates.size)
            for (i in certs.indices) certs[i] = certificates[i] as X509Certificate
        } catch (e: ProviderException) {
            if (Build.VERSION.SDK_INT >= 28 && e is StrongBoxUnavailableException) {
                throw AttestationException(AttestationException.CODE_STRONGBOX_UNAVAILABLE, e)
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
        return AttestationResult(useStrongBox, attestation, isGoogleRootCertificate)
    }

    private suspend fun loadHasStrongBox(context: Context): Boolean {
        try {
            withContext(Dispatchers.IO) {
                hasStrongBox.postValue(Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                        context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE))
            }
        } catch (e: CancellationException) {
            return false
        } catch (e: Throwable) {
            hasStrongBox.postValue(false)
        }
        return true
    }

    fun invalidateAttestation(context: Context) = viewModelScope.launch {
        attestationResult.postValue(Resource.loading(null))

        if (hasStrongBox.value == null) {
            if (!loadHasStrongBox(context)) {
                return@launch
            }
        }

        try {
            withContext(Dispatchers.IO) {
                val useStrongBox = hasStrongBox.value!! && preferStrongBox
                val alias = if (useStrongBox) "Key2" else "Key1"
                Resource.success(doAttestation(context, alias, useStrongBox))
            }
        } catch (e: CancellationException) {
            return@launch
        } catch (e: AttestationException) {
            Resource.error(e, null)
        } catch (e: Throwable) {
            Resource.error(AttestationException(AttestationException.CODE_UNKNOWN, e), null)
        }.let {
            attestationResult.postValue(it)
        }
    }
}