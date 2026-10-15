use cms::{
    builder::{SignedDataBuilder, SignerInfoBuilder},
    cert::CertificateChoices,
    cert::IssuerAndSerialNumber,
    content_info::ContentInfo,
    signed_data::{EncapsulatedContentInfo, SignerIdentifier},
};
use const_oid::{
    ObjectIdentifier,
    db::{rfc4519, rfc5911, rfc5912},
};
use der::{
    Any, Decode, DecodePem, Encode, EncodePem, Sequence,
    asn1::{OctetString, SequenceOf, SetOfVec, Utf8StringRef},
    pem::LineEnding,
};
use p256::{
    ecdsa::{DerSignature, SigningKey},
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::{io, path::Path, time::Duration};
use x509_cert::{
    Certificate,
    attr::{Attribute, AttributeTypeAndValue},
    builder::{Builder, CertificateBuilder, Profile},
    name::{Name, RdnSequence, RelativeDistinguishedName},
    serial_number::SerialNumber,
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
    time::Validity,
};

use crate::infrastructure::signing::{
    ensure_private_directory, restrict_private_key, signing_directory, write_private_file,
    write_public_file,
};

const KEY_FILE: &str = "pdf_signing.key";
const CERT_FILE: &str = "pdf_signing.crt";
const DEFAULT_COMMON_NAME: &str = "BitsPlayer Examiner";
const ORGANIZATION: &str = "BitsPlayer";
const CERT_VALIDITY: Duration = Duration::from_secs(10 * 365 * 24 * 60 * 60);
const ID_AA_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");

pub struct PdfSigningIdentity {
    pub key: SigningKey,
    pub cert_der: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SignerDetails {
    pub common_name: String,
    pub subject: String,
    pub certificate_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct EssCertIdV2 {
    cert_hash: OctetString,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct SigningCertificateV2 {
    certs: SequenceOf<EssCertIdV2, 1>,
}

impl PdfSigningIdentity {
    pub fn load_or_create(examiner: Option<&str>) -> io::Result<Self> {
        Self::load_or_create_in(signing_directory()?, examiner)
    }

    pub fn load_or_create_in(
        directory: impl AsRef<Path>,
        examiner: Option<&str>,
    ) -> io::Result<Self> {
        let directory = directory.as_ref();
        ensure_private_directory(directory)?;

        let key_path = directory.join(KEY_FILE);
        let cert_path = directory.join(CERT_FILE);

        let key = if key_path.exists() {
            restrict_private_key(&key_path)?;
            let pem = std::fs::read_to_string(&key_path)?;
            SigningKey::from_pkcs8_pem(&pem).map_err(io::Error::other)?
        } else {
            let key = SigningKey::random(&mut OsRng);
            let pem = key.to_pkcs8_pem(LineEnding::LF).map_err(io::Error::other)?;
            write_private_file(&key_path, pem.trim_end())?;
            key
        };

        if cert_path.exists() {
            let pem = std::fs::read_to_string(&cert_path)?;
            let certificate = Certificate::from_pem(&pem).map_err(io::Error::other)?;
            return Ok(Self {
                key,
                cert_der: certificate.to_der().map_err(io::Error::other)?,
            });
        }

        let certificate = build_certificate(&key, examiner)?;
        let pem = certificate
            .to_pem(LineEnding::LF)
            .map_err(io::Error::other)?;
        write_public_file(&cert_path, pem.trim_end())?;

        Ok(Self {
            key,
            cert_der: certificate.to_der().map_err(io::Error::other)?,
        })
    }

    pub fn signer_details(&self) -> io::Result<SignerDetails> {
        let certificate = Certificate::from_der(&self.cert_der).map_err(io::Error::other)?;
        let subject = &certificate.tbs_certificate.subject;
        Ok(SignerDetails {
            common_name: common_name(subject)?,
            subject: subject.to_string(),
            certificate_sha256: hex::encode(Sha256::digest(&self.cert_der)),
        })
    }

    pub fn cms_signature(&self, message_digest: &[u8]) -> io::Result<Vec<u8>> {
        let certificate = Certificate::from_der(&self.cert_der).map_err(io::Error::other)?;
        let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: certificate.tbs_certificate.issuer.clone(),
            serial_number: certificate.tbs_certificate.serial_number.clone(),
        });
        let digest_algorithm = AlgorithmIdentifierOwned {
            oid: rfc5912::ID_SHA_256,
            parameters: None,
        };
        let content = EncapsulatedContentInfo {
            econtent_type: rfc5911::ID_DATA,
            econtent: None,
        };

        let mut signer = SignerInfoBuilder::new(
            &self.key,
            sid,
            digest_algorithm.clone(),
            &content,
            Some(message_digest),
        )
        .map_err(cms_error)?;
        signer
            .add_signed_attribute(signing_certificate_attribute(&self.cert_der)?)
            .map_err(cms_error)?;

        let mut signed = SignedDataBuilder::new(&content);
        signed
            .add_digest_algorithm(digest_algorithm)
            .map_err(cms_error)?;
        signed
            .add_certificate(CertificateChoices::Certificate(certificate))
            .map_err(cms_error)?;
        signed
            .add_signer_info::<SigningKey, DerSignature>(signer)
            .map_err(cms_error)?;

        let content_info: ContentInfo = signed.build().map_err(cms_error)?;
        content_info.to_der().map_err(io::Error::other)
    }
}

fn cms_error(error: cms::builder::Error) -> io::Error {
    io::Error::other(format!("{error:?}"))
}

fn build_certificate(key: &SigningKey, examiner: Option<&str>) -> io::Result<Certificate> {
    let common_name = examiner
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or(DEFAULT_COMMON_NAME);
    let subject = distinguished_name(common_name)?;

    let mut serial = [0u8; 16];
    OsRng.fill_bytes(&mut serial);
    serial[0] = (serial[0] & 0x7f) | 0x40;
    let serial_number = SerialNumber::new(&serial).map_err(io::Error::other)?;

    let validity = Validity::from_now(CERT_VALIDITY).map_err(io::Error::other)?;
    let spki = SubjectPublicKeyInfoOwned::from_key(key.verifying_key().clone())
        .map_err(io::Error::other)?;
    let profile = Profile::Leaf {
        issuer: subject.clone(),
        enable_key_agreement: false,
        enable_key_encipherment: false,
    };

    CertificateBuilder::new(profile, serial_number, validity, subject, spki, key)
        .map_err(io::Error::other)?
        .build::<DerSignature>()
        .map_err(io::Error::other)
}

fn distinguished_name(common_name: &str) -> io::Result<Name> {
    let common_name_rdn = name_attribute(rfc4519::COMMON_NAME, common_name)?;
    let organization_rdn = name_attribute(rfc4519::ORGANIZATION_NAME, ORGANIZATION)?;
    Ok(RdnSequence(vec![common_name_rdn, organization_rdn]))
}

fn name_attribute(oid: ObjectIdentifier, value: &str) -> io::Result<RelativeDistinguishedName> {
    let utf8 = Utf8StringRef::new(value).map_err(io::Error::other)?;
    let attribute = AttributeTypeAndValue {
        oid,
        value: Any::encode_from(&utf8).map_err(io::Error::other)?,
    };
    let values = SetOfVec::try_from(vec![attribute]).map_err(io::Error::other)?;
    Ok(RelativeDistinguishedName(values))
}

fn common_name(subject: &Name) -> io::Result<String> {
    for rdn in &subject.0 {
        for attribute in rdn.0.iter() {
            if attribute.oid == rfc4519::COMMON_NAME {
                let value: Utf8StringRef<'_> =
                    attribute.value.decode_as().map_err(io::Error::other)?;
                return Ok(value.as_str().to_string());
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "PDF signing certificate has no common name",
    ))
}

fn signing_certificate_attribute(cert_der: &[u8]) -> io::Result<Attribute> {
    let cert_hash =
        OctetString::new(Sha256::digest(cert_der).to_vec()).map_err(io::Error::other)?;
    let mut certs = SequenceOf::new();
    certs
        .add(EssCertIdV2 { cert_hash })
        .map_err(io::Error::other)?;
    let value = SigningCertificateV2 { certs };

    let encoded = Any::encode_from(&value).map_err(io::Error::other)?;
    let values = SetOfVec::try_from(vec![encoded]).map_err(io::Error::other)?;
    Ok(Attribute {
        oid: ID_AA_SIGNING_CERTIFICATE_V2,
        values,
    })
}
