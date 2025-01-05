/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.hardware.security.keymint;

/**
 * NOTE: ProtectedData has been removed as of version 3, but is kept around for backwards
 * compatibility reasons. For versions 1 and 2:
 *
 * ProtectedData contains the encrypted BCC and the ephemeral MAC key used to
 * authenticate the keysToSign (see keysToSignMac output argument of
 * IRemotelyProvisionedComponent.generateCertificateRequest).
 *
 * @hide
 */
parcelable ProtectedData {
    /**
     * ProtectedData is a COSE_Encrypt structure, encrypted with an AES key that is agreed upon
     * using Elliptic-curve Diffie-Hellman. The contents of the structure are specified by the
     * following CDDL [RFC8610].
     *
     * Notes:
     *   - None of the CBOR in ProtectedData uses CBOR tags. If an implementation includes
     *     tags, parsers may reject the data.
     *
     *     ProtectedData = [               ; COSE_Encrypt
     *         protected: bstr .cbor {
     *             1 : 3                   ; Algorithm : AES-GCM 256
     *         },
     *         unprotected: {
     *             5 : bstr .size 12       ; IV
     *         },
     *         ciphertext: bstr,           ; AES-GCM-256(K, .cbor ProtectedDataPayload)
     *                                     ; Where the encryption key 'K' is derived as follows:
     *                                     ; ikm = ECDH(EEK_pub, Ephemeral_priv)
     *                                     ; salt = null
     *                                     ; info = .cbor Context (see below)
     *                                     ; K = HKDF-SHA-256(ikm, salt, info)
     *                                     ; AAD for the encryption is a CBOR-serialized
     *                                     ; Enc_structure (RFC 8152 s5.3) with empty external_aad.
     *         recipients : [
     *             [                       ; COSE_Recipient
     *                 protected : bstr .cbor {
     *                     1 : -25         ; Algorithm : ECDH-ES + HKDF-256
     *                 },
     *                 unprotected : {
     *                     -1 : PubKeyX25519 / PubKeyEcdhP256  ; Ephemeral_pub
     *                     4 : bstr,       ; KID : EEK ID
     *                 },
     *                 ciphertext : nil
     *             ]
     *         ]
     *     ]
     *
     *     ; The COSE_KDF_Context that is used to derive the ProtectedData encryption key with
     *     ; HKDF. See details on use in ProtectedData comments above. The public key data
     *     ; included in the other field of PartyUInfo / PartyVInfo is encoded as:
     *     ;  - a raw 32-byte public key for X25519
     *     ;  - raw coordinate data (x || y) for P-256
     *     Context = [
     *         AlgorithmID : 3             ; AES-GCM 256
     *         PartyUInfo : [
     *             identity : bstr "client"
     *             nonce : bstr .size 0,
     *             other : bstr            ; Ephemeral_pub
     *         ],
     *         PartyVInfo : [
     *             identity : bstr "server",
     *             nonce : bstr .size 0,
     *             other : bstr            ; EEK pubkey
     *         ],
     *         SuppPubInfo : [
     *             256,                    ; Output key length
     *             protected : bstr .size 0
     *         ]
     *     ]
     *
     *     ; The data that is encrypted and included in ProtectedData ciphertext (see above).
     *     ProtectedDataPayload [
     *         SignedMac,
     *         Bcc,
     *         ? AdditionalDKSignatures,
     *     ]
     *
     *     ; AdditionalDKSignatures allows the platform to provide additional certifications
     *     ; for the DK_pub. For example, this could be provided by the hardware vendor, who
     *     ; certifies all of their devices. The SignerName is a free-form string describing
     *     ; who generated the signature.
     *     AdditionalDKSignatures = {
     *         + SignerName => DKCertChain
     *     }
     *
     *     ; SignerName is a string identifier that indicates both the signing authority as
     *     ; well as the format of the DKCertChain
     *     SignerName = tstr
     *
     *     DKCertChain = [
     *         2* X509Certificate       ; Root -> ... -> Leaf. "Root" is the vendor self-signed
     *                                  ; cert, "Leaf" contains DK_pub. There may also be
     *                                  ; intermediate certificates between Root and Leaf.
     *     ]
     *
     *     ; A bstr containing a DER-encoded X.509 certificate (RSA, NIST P-curve, or edDSA)
     *     X509Certificate = bstr
     *
     *     ; The SignedMac, which authenticates the MAC key that is used to authenticate the
     *     ; keysToSign.
     *     SignedMac = [                                ; COSE_Sign1
     *         bstr .cbor {                             ; Protected params
     *             1 : AlgorithmEdDSA / AlgorithmES256, ; Algorithm
     *         },
     *         {},                                      ; Unprotected params
     *         bstr .size 32,                           ; Payload: MAC key
     *         bstr ; PureEd25519(KM_priv, bstr .cbor SignedMac_structure) /
     *              ; ECDSA(KM_priv, bstr .cbor SignedMac_structure)
     *     ]
     *
     *     SignedMac_structure = [                      ;  COSE Sig_structure
     *         "Signature1",
     *         bstr .cbor {                             ; Protected params
     *             1 : AlgorithmEdDSA / AlgorithmES256, ; Algorithm
     *         },
     *         bstr .cbor SignedMacAad,
     *         bstr .size 32                            ; MAC key
     *     ]
     *
     *     SignedMacAad = [
     *         challenge : bstr .size (16..64),   ; Size between 16 - 64
     *                                            ; bytes inclusive
     *         VerifiedDeviceInfo,
     *         tag: bstr                 ; This is the tag from COSE_Mac0 of
     *                                   ; KeysToSign, to tie the key set to
     *                                   ; the signature.
     *     ]
     *
     *     VerifiedDeviceInfo = DeviceInfo  ; See DeviceInfo.aidl
     *
     *     ; The BCC is the boot certificate chain, containing measurements about the device
     *     ; boot chain. The BCC generally follows the Open Profile for DICE specification at
     *     ; https:;pigweed.googlesource.com/open-dice/+/HEAD/docs/specification.md.
     *     ;
     *     ; The first entry in the Bcc is the DK_pub, encoded as a COSE_key. All entries after
     *     ; the first describe a link in the boot chain (e.g. bootloaders: BL1, BL2, ... BLN).
     *     ; Note that there is no BccEntry for DK_pub, only a "bare" COSE_key.
     *     Bcc = [
     *         PubKeyEd25519 / PubKeyECDSA256, ; DK_pub
     *         + BccEntry,                     ; Root -> leaf (KM_pub)
     *     ]
     *
     *     ; This is the signed payload for each entry in the Bcc. Note that the "Configuration
     *     ; Input Values" described by the Open Profile are not used here. Instead, the Bcc
     *     ; defines its own configuration values for the Configuration Descriptor field. See
     *     ; the Open Profile for DICE for more details on the fields. All hashes are SHA256.
     *     BccPayload = {                               ; CWT [RFC8392]
     *         1 : tstr,                                ; Issuer
     *         2 : tstr,                                ; Subject
     *         -4670552 : bstr .cbor PubKeyEd25519 /
     *                    bstr .cbor PubKeyECDSA256,    ; Subject Public Key
     *         -4670553 : bstr                          ; Key Usage
     *
     *         ; NOTE: All of the following fields may be omitted for a "Degenerate BCC", as
     *         ;       described by IRemotelyProvisionedComponent.aidl.
     *         -4670545 : bstr,                         ; Code Hash
     *         ? -4670546 : bstr,                       ; Code Descriptor
     *         ? -4670547 : bstr,                       ; Configuration Hash
     *         -4670548 : bstr .cbor {                  ; Configuration Descriptor
     *             ? -70002 : tstr,                         ; Component name
     *             ? -70003 : int,                          ; Firmware version
     *             ? -70004 : null,                         ; Resettable
     *         },
     *         -4670549 : bstr,                         ; Authority Hash
     *         ? -4670550 : bstr,                       ; Authority Descriptor
     *         -4670551 : bstr,                         ; Mode
     *     }
     *
     *     ; Each entry in the Bcc is a BccPayload signed by the key from the previous entry
     *     ; in the Bcc array.
     *     BccEntry = [                                  ; COSE_Sign1 (untagged)
     *         protected : bstr .cbor {
     *             1 : AlgorithmEdDSA / AlgorithmES256,  ; Algorithm
     *         },
     *         unprotected: {},
     *         payload: bstr .cbor BccPayload,
     *         signature: bstr ; PureEd25519(SigningKey, bstr .cbor BccEntryInput) /
     *                         ; ECDSA(SigningKey, bstr .cbor BccEntryInput)
     *         ; See RFC 8032 for details of how to encode the signature value for Ed25519.
     *     ]
     *
     *     BccEntryInput = [
     *         context: "Signature1",
     *         protected: bstr .cbor {
     *             1 : AlgorithmEdDSA / AlgorithmES256,  ; Algorithm
     *         },
     *         external_aad: bstr .size 0,
     *         payload: bstr .cbor BccPayload
     *     ]
     *
     *     ; The following section defines some types that are reused throughout the above
     *     ; data structures.
     *     PubKeyX25519 = {                 ; COSE_Key
     *          1 : 1,                      ; Key type : Octet Key Pair
     *         -1 : 4,                      ; Curve : X25519
     *         -2 : bstr                    ; Sender X25519 public key, little-endian
     *     }
     *
     *     PubKeyEd25519 = {                ; COSE_Key
     *         1 : 1,                       ; Key type : octet key pair
     *         3 : AlgorithmEdDSA,          ; Algorithm : EdDSA
     *         -1 : 6,                      ; Curve : Ed25519
     *         -2 : bstr                    ; X coordinate, little-endian
     *     }
     *
     *     PubKeyEcdhP256 = {               ; COSE_Key
     *          1 : 2,                      ; Key type : EC2
     *          -1 : 1,                     ; Curve : P256
     *          -2 : bstr                   ; Sender X coordinate, big-endian
     *          -3 : bstr                   ; Sender Y coordinate, big-endian
     *     }
     *
     *     PubKeyECDSA256 = {               ; COSE_Key
     *         1 : 2,                       ; Key type : EC2
     *         3 : AlgorithmES256,          ; Algorithm : ECDSA w/ SHA-256
     *         -1 : 1,                      ; Curve: P256
     *         -2 : bstr,                   ; X coordinate, big-endian
     *         -3 : bstr                    ; Y coordinate, big-endian
     *     }
     *
     *     AlgorithmES256 = -7
     *     AlgorithmEdDSA = -8
     */
    byte[] protectedData;
}
