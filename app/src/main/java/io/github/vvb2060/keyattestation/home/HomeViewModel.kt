package io.github.vvb2060.keyattestation.home

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.google.firebase.analytics.FirebaseAnalytics
import com.google.firebase.crashlytics.FirebaseCrashlytics
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

    init {
        load(context)
    }

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

        } catch (e: Throwable) {
            _hasStrongBox.postValue(false)
        }
        return true
    }

    private fun logSuccess(firebaseAnalytics: FirebaseAnalytics, attestationResult: AttestationResult, hasStrongBox: Boolean) {
        try {
            firebaseAnalytics.apply {
                setUserProperty("doAttestation", if (hasStrongBox && !attestationResult.isStrongBox) "Fallback" else "Done")
                setUserProperty("isGoogleRootCertificate", attestationResult.isGoogleRootCertificate.toString())
                setUserProperty("attestationVersion", attestationResult.attestation.attestationVersion.toString())
                setUserProperty("attestationSecurityLevel", attestationResult.attestation.attestationSecurityLevel
                        .let { Attestation.securityLevelToString(it) })
                setUserProperty("isDeviceLocked", attestationResult.attestation.teeEnforced?.rootOfTrust?.isDeviceLocked
                        ?.toString() ?: "NULL")
                setUserProperty("verifiedBootState", attestationResult.attestation.teeEnforced?.rootOfTrust?.verifiedBootState
                        ?.let { RootOfTrust.verifiedBootStateToString(it) } ?: "NULL")
            }
        } catch (e: Throwable) {
        }
    }

    private fun logFailure(firebaseAnalytics: FirebaseAnalytics, e: Throwable) {
        try {
            firebaseAnalytics.apply {
                if (e is AttestationException) {
                    setUserProperty("doAttestation", when (e.code) {
                        AttestationException.CODE_NOT_SUPPORT -> "Not support"
                        AttestationException.CODE_CERT_NOT_TRUSTED -> "Unable get cert"
                        AttestationException.CODE_CANT_PARSE_ATTESTATION_RECORD -> "Parse error"
                        AttestationException.CODE_STRONGBOX_UNAVAILABLE -> "Fallback"
                        else -> "Unknown"
                    })
                } else {
                    setUserProperty("doAttestation", "Unknown")
                }
                setUserProperty("isGoogleRootCertificate", "NULL")
                setUserProperty("attestationVersion", "NULL")
                setUserProperty("attestationSecurityLevel", "NULL")
                setUserProperty("isDeviceLocked", "NULL")
                setUserProperty("verifiedBootState", "NULL")
            }
        } catch (e: Throwable) {
        }
    }

    private fun load(context: Context) = viewModelScope.launch {
        val results = arrayOf<Resource<AttestationResult>>(Resource.loading(null), Resource.loading(null))

        _attestationResults.postValue(results)

        val hasStrongBox = withContext(Dispatchers.IO) {
            try {
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                        context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
            } catch (e: Throwable) {
                false
            }
        }

        _hasStrongBox.value = hasStrongBox

        withContext(Dispatchers.IO) {
            val firebaseAnalytics = FirebaseAnalytics.getInstance(context)
            val firebaseCrashlytics = FirebaseCrashlytics.getInstance()

            for (i in 0..1) {
                val useStrongBox = i == 1
                if (useStrongBox && !hasStrongBox) continue
                results[i] = try {
                    val attestationResult = doAttestation(context, ALIAS[i], useStrongBox)
                    Resource.success(attestationResult)
                } catch (e: Throwable) {
                    val cause = if (e is AttestationException) e.cause!! else e
                    cause.also {
                        firebaseCrashlytics.apply {
                            setCustomKey("useStrongBox", useStrongBox)
                            recordException(it)
                        }
                    }

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

            val strongBoxResult = results[1]
            val result = results[0]
            when {
                strongBoxResult.status == Status.SUCCESS -> {
                    // StrongBox succeed
                    logSuccess(firebaseAnalytics, strongBoxResult.data!!, hasStrongBox)
                }
                result.status == Status.SUCCESS -> {
                    // normal succeed
                    logSuccess(firebaseAnalytics, result.data!!, hasStrongBox)
                }
                else -> {
                    // all failed
                    logFailure(firebaseAnalytics, result.error as AttestationException)
                }
            }
        }
    }
}