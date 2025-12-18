// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The module for `KEY_RELEASE_REQUEST` request type that supports preparing
//! runtime claims, which is a part of the request, and parsing the response, which
//! can be either in JSON or JSON web token (JWT) format defined by Azure Key Vault (AKV).

use crate::igvm_attest::Error as CommonError;
use crate::igvm_attest::parse_response_header;
use crate::jwt::JwtError;
use crate::jwt::JwtHelper;
use openhcl_attestation_protocol::igvm_attest::akv;
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum KeyReleaseError {
    #[error("the response payload size is too small to parse")]
    PayloadSizeTooSmall,
    #[error("failed to parse AKV JWT (API version > 7.2)")]
    ParseAkvJwt(#[source] JwtError),
    #[error("error occurs during AKV JWT signature verification")]
    VerifyAkvJwtSignature(#[source] JwtError),
    #[error("failed to verify AKV JWT signature")]
    VerifyAkvJwtSignatureFailed,
    #[error("failed to get wrapped key from AKV JWT body")]
    GetWrappedKeyFromAkvJwtBody(#[source] serde_json::Error),
    #[error("error in parsing response header")]
    ParseHeader(#[source] CommonError),
    #[error("invalid response header version: {0}")]
    InvalidResponseVersion(u32),
}

/// Parse a `KEY_RELEASE_REQUEST` response and return a raw wrapped key blob.
///
/// Returns `Ok(Vec<u8>)` on successfully extracting a wrapped key blob from `response`,
/// otherwise return an error.
pub fn parse_response(
    response: &[u8],
    rsa_modulus_size: usize,
) -> Result<Vec<u8>, KeyReleaseError> {
    use openhcl_attestation_protocol::igvm_attest::get::IgvmAttestCommonResponseHeader;
    use openhcl_attestation_protocol::igvm_attest::get::IgvmAttestKeyReleaseResponseHeader;
    use openhcl_attestation_protocol::igvm_attest::get::IgvmAttestResponseVersion;

    // Minimum acceptable payload would look like {"ciphertext":"base64URL wrapped key"}
    const AES_IC_SIZE: usize = 8;
    const CIPHER_TEXT_KEY: &str = r#"{"ciphertext":""}"#;

    let header = parse_response_header(response).map_err(KeyReleaseError::ParseHeader)?;

    // Extract payload as per header version
    let header_size = match header.version {
        IgvmAttestResponseVersion::VERSION_1 => size_of::<IgvmAttestCommonResponseHeader>(),
        IgvmAttestResponseVersion::VERSION_2 => size_of::<IgvmAttestKeyReleaseResponseHeader>(),
        invalid_version => return Err(KeyReleaseError::InvalidResponseVersion(invalid_version.0)),
    };
    let payload = &response[header_size..header.data_size as usize];
    let wrapped_key_size = rsa_modulus_size + rsa_modulus_size + AES_IC_SIZE;
    let wrapped_key_base64_url_size = wrapped_key_size / 3 * 4;
    let minimum_payload_size = CIPHER_TEXT_KEY.len() + wrapped_key_base64_url_size - 1;

    if payload.len() < minimum_payload_size {
        Err(KeyReleaseError::PayloadSizeTooSmall)?
    }
    let data_utf8 = String::from_utf8_lossy(payload);
    let wrapped_key = match serde_json::from_str::<akv::AkvKeyReleaseKeyBlob>(&data_utf8) {
        Ok(blob) => {
            // JSON format (API version 7.2)
            blob.ciphertext
        }
        Err(_) => {
            // JWT format (API version > 7.2)
            let result = JwtHelper::<akv::AkvKeyReleaseJwtBody>::from(payload)
                .map_err(KeyReleaseError::ParseAkvJwt)?;

            // Validate the JWT signature (if exist)
            if !result.jwt.signature.is_empty() {
                if !result
                    .verify_signature()
                    .map_err(KeyReleaseError::VerifyAkvJwtSignature)?
                {
                    Err(KeyReleaseError::VerifyAkvJwtSignatureFailed)?
                }
            }
            get_wrapped_key_blob(result)?
        }
    };

    Ok(wrapped_key)
}

fn get_wrapped_key_blob(
    jwt: JwtHelper<akv::AkvKeyReleaseJwtBody>,
) -> Result<Vec<u8>, KeyReleaseError> {
    let key_hsm = jwt.jwt.body.response.key.key.key_hsm;
    let key_hsm = String::from_utf8_lossy(&key_hsm);
    let key_hsm: akv::AkvKeyReleaseKeyBlob =
        serde_json::from_str(&key_hsm).map_err(KeyReleaseError::GetWrappedKeyFromAkvJwtBody)?;

    Ok(key_hsm.ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::Engine;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::pkey::Private;
    use openssl::rsa::Padding;
    use openssl::x509::X509;
    use openssl::x509::X509Name;

    const CIPHERTEXT: &str = "test";

    /// Generate a self-signed X.509 certificate for testing.
    fn generate_x509(private: &PKey<Private>) -> X509 {
        let mut x509 = X509::builder().unwrap();

        // Generate a public key from the private key and set it as the public key of the certificate
        let public = private.public_key_to_pem().unwrap();
        let public = PKey::public_key_from_pem(&public).unwrap();
        x509.set_pubkey(&public).unwrap();

        x509.set_version(2).unwrap();
        x509.set_serial_number(
            &openssl::bn::BigNum::from_u32(1)
                .unwrap()
                .to_asn1_integer()
                .unwrap(),
        )
        .unwrap();
        x509.set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        x509.set_not_after(&openssl::asn1::Asn1Time::days_from_now(365).unwrap())
            .unwrap();

        let mut name = X509Name::builder().unwrap();
        name.append_entry_by_text("C", "US").unwrap();
        name.append_entry_by_text("ST", "Washington").unwrap();
        name.append_entry_by_text("L", "Redmond").unwrap();
        name.append_entry_by_text("O", "Example INC").unwrap();
        name.append_entry_by_text("CN", "example.com").unwrap();
        let name = name.build();
        x509.set_subject_name(&name).unwrap();
        x509.set_issuer_name(&name).unwrap();

        x509.sign(private, MessageDigest::sha256()).unwrap();

        x509.build()
    }

    /// Generate an X.509 certificate chain for testing.
    /// The chain consists of three certificates: cert, intermediate, and root.
    /// All certs are signed by the same private key and have the same subject and issuer.
    fn generate_x5c(private: &PKey<Private>) -> Vec<String> {
        let cert = generate_x509(private);
        let intermediate = generate_x509(private);
        let root = generate_x509(private);

        let base64_cert = base64::engine::general_purpose::STANDARD.encode(cert.to_der().unwrap());
        let base64_intermediate =
            base64::engine::general_purpose::STANDARD.encode(intermediate.to_der().unwrap());
        let base64_root = base64::engine::general_purpose::STANDARD.encode(root.to_der().unwrap());

        vec![base64_cert, base64_intermediate, base64_root]
    }

    /// Generate the base64 encoded components of a JWT.
    fn generate_base64_encoded_jwt_components(private: &PKey<Private>) -> (String, String, String) {
        let header = akv::AkvKeyReleaseJwtHeader {
            alg: "RS256".to_string(),
            x5c: generate_x5c(private),
        };
        // Header is a base64-url encoded JSON object
        let base64_header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_string(&header).unwrap());

        let key_hsm = akv::AkvKeyReleaseKeyBlob {
            ciphertext: CIPHERTEXT.as_bytes().to_vec(),
        };

        let body = akv::AkvKeyReleaseJwtBody {
            response: akv::AkvKeyReleaseResponse {
                key: akv::AkvKeyReleaseKeyObject {
                    key: akv::AkvJwk {
                        key_hsm: serde_json::to_string(&key_hsm).unwrap().as_bytes().to_vec(),
                    },
                },
            },
        };
        // Body is a base64-url encoded JSON object
        let base64_body = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_string(&body).unwrap().as_bytes());

        // The signature is generated by signing the concatenation of base64_header and base64_body
        let message = format!("{}.{}", base64_header, base64_body);
        let mut signer = openssl::sign::Signer::new(MessageDigest::sha256(), private).unwrap();
        signer.set_rsa_padding(Padding::PKCS1).unwrap();
        signer.update(message.as_bytes()).unwrap();
        let signature = signer.sign_to_vec().unwrap();
        let base64_signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature);

        (base64_header, base64_body, base64_signature)
    }

    #[test]
    fn get_wrapped_key_from_jwt() {
        let rsa_key = openssl::rsa::Rsa::generate(2048).unwrap();
        let private = PKey::from_rsa(rsa_key).unwrap();

        let (header, body, signature) = generate_base64_encoded_jwt_components(&private);

        let jwt = format!("{}.{}.{}", header, body, signature);
        let jwt = JwtHelper::<akv::AkvKeyReleaseJwtBody>::from(jwt.as_bytes()).unwrap();

        let wrapped_key = get_wrapped_key_blob(jwt).unwrap();
        assert_eq!(wrapped_key, CIPHERTEXT.as_bytes());
    }

    #[test]
    fn fail_to_parse_empty_response() {
        let response = parse_response(&[], 256);
        assert!(response.is_err());
        assert_eq!(
            response.unwrap_err().to_string(),
            KeyReleaseError::ParseHeader(CommonError::ResponseSizeTooSmall { response_size: 0 })
                .to_string()
        );
    }
}
