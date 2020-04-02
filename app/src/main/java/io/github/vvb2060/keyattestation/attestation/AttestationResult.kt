package io.github.vvb2060.keyattestation.attestation

data class AttestationResult(val isStrongBox: Boolean, val attestation: Attestation, val isGoogleRootCertificate: Boolean)

