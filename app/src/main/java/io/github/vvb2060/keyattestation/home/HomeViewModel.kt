package io.github.vvb2060.keyattestation.home

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import io.github.vvb2060.keyattestation.R
import io.github.vvb2060.keyattestation.attestation.Attestation
import io.github.vvb2060.keyattestation.attestation.AttestationResult
import io.github.vvb2060.keyattestation.attestation.RootOfTrust
import io.github.vvb2060.keyattestation.attestation.VerifyCertificateChain
import io.github.vvb2060.keyattestation.lang.AttestationException
import io.github.vvb2060.keyattestation.util.Resource
import io.github.vvb2060.keyattestation.util.Status
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

    companion object {

        private const val ORIGINATION_TIME_OFFSET = 1000000
        private const val CONSUMPTION_TIME_OFFSET = 2000000
        private val ALIAS = arrayOf("Key1", "Key2")
    }

    private val _attestationResults = MutableLiveData<Array<Resource<AttestationResult>>>()

    val attestationResults = _attestationResults as LiveData<Array<Resource<AttestationResult>>>

    private val _hasStrongBox = MutableLiveData<Boolean>()

    val hasStrongBox = _hasStrongBox as LiveData<Boolean>

    var preferStrongBox = true

    private val _hasDeviceIds = MutableLiveData<Boolean>()

    val hasDeviceIds = _hasDeviceIds as LiveData<Boolean>

    var preferIncludeProps = true

    init {
        load(context)
    }

    @Throws(GeneralSecurityException::class)
    private fun generateKey(alias: String, useStrongBox: Boolean, incloudProps: Boolean) {
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
        )
        val now = Date()
        val originationEnd = Date(now.time + ORIGINATION_TIME_OFFSET)
        val consumptionEnd = Date(now.time + CONSUMPTION_TIME_OFFSET)
        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setKeyValidityStart(now)
            .setKeyValidityForOriginationEnd(originationEnd)
            .setKeyValidityForConsumptionEnd(consumptionEnd)
            .setAttestationChallenge(now.toString().toByteArray())
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && incloudProps) {
            builder.setDevicePropertiesAttestationIncluded(true)
        }
        if (Build.VERSION.SDK_INT >= 28 && useStrongBox) {
            builder.setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256)
            builder.setIsStrongBoxBacked(true)
        } else {
            builder.setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
        }
        keyPairGenerator.initialize(builder.build())
        keyPairGenerator.generateKeyPair()
    }

    private fun doAttestation(
        context: Context,
        alias: String,
        useStrongBox: Boolean,
        incloudProps: Boolean
    ): AttestationResult {
        val certs: Array<X509Certificate?>?
        val attestation: Attestation
        val isGoogleRootCertificate: Boolean
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            generateKey(alias, useStrongBox, incloudProps)
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
            // throw AttestationException(AttestationException.CODE_CANT_GET_CERT, e)
            throw AttestationException(AttestationException.CODE_NOT_SUPPORT, e)
        }
        try {
            isGoogleRootCertificate =
                VerifyCertificateChain.verifyCertificateChain(certs, context.resources.openRawResource(R.raw.status))
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

    private fun load(context: Context) = viewModelScope.launch {
        val results = arrayOf<Resource<AttestationResult>>(Resource.loading(null), Resource.loading(null))

        _attestationResults.postValue(results)

        withContext(Dispatchers.IO) {
            val hasStrongBox = try {
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                        context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
            } catch (e: Throwable) {
                false
            }

            _hasStrongBox.postValue(hasStrongBox)

            val hasDeviceIds = try {
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
                        context.packageManager.hasSystemFeature("android.software.device_id_attestation")
            } catch (e: Throwable) {
                false
            }

            _hasDeviceIds.postValue(hasDeviceIds)

            for (i in 0..1) {
                val useStrongBox = i == 1
                if (useStrongBox && !hasStrongBox) continue
                results[i] = try {
                    val alias = "Key_$useStrongBox"
                    val attestationResult = doAttestation(context, alias, useStrongBox, true)
                    Resource.success(attestationResult)
                } catch (e: Throwable) {
                    val cause = if (e is AttestationException) e.cause!! else e
                            Log.d("KeyAttestation", "Do attestation error.", cause)

                    if (useStrongBox) {
                        preferStrongBox = false
                    }

                    if (e is AttestationException) {
                        Resource.error(e, null)
                    } else {
                        Resource.error(AttestationException(AttestationException.CODE_UNKNOWN, e), null)
                    }
                }
            }
            _attestationResults.postValue(results)
        }
    }
}
