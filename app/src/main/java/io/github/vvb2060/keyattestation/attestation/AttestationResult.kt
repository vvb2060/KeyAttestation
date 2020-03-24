package io.github.vvb2060.keyattestation.attestation

data class AttestationResult(val attestation: Attestation, val isGoogleRootCertificate: Boolean)