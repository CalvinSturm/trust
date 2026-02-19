use std::fs::{self, File};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use c2pa::{create_signer, settings, Builder, SigningAlg};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};

const TINY_JPEG_B64: &str = "/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEAAkGBxAQEBAQEA8PEA8QDw8PEA8PDw8PEA8PFREWFhURFRUYHSggGBolGxUVITEhJSkrLi4uFx8zODMsNygtLisBCgoKDg0OFQ8PFSsdFR0tKy0rKy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tK//AABEIAAEAAQMBIgACEQEDEQH/xAAXAAEBAQEAAAAAAAAAAAAAAAABAAID/8QAFhEBAQEAAAAAAAAAAAAAAAAAABEB/9oADAMBAAIQAxAAAAH2r//EABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAQUCcf/EABQRAQAAAAAAAAAAAAAAAAAAACD/2gAIAQMBAT8BP//EABQRAQAAAAAAAAAAAAAAAAAAACD/2gAIAQIBAT8BP//Z";

pub fn make_unsigned_and_signed_assets(root: &Path) -> (PathBuf, PathBuf) {
    let unsigned = root.join("unsigned.jpg");
    let signed = root.join("signed.jpg");

    let jpg = BASE64_STANDARD
        .decode(TINY_JPEG_B64)
        .expect("decode tiny jpeg");
    fs::write(&unsigned, jpg).expect("write unsigned test image");

    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("generate ca key");
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "trust-stack test root");
    let mut ca_params = CertificateParams::new(vec!["trust-stack.test".to_string()])
        .expect("create ca cert params");
    ca_params.distinguished_name = ca_dn;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign ca cert");

    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("generate leaf key");
    let mut leaf_dn = DistinguishedName::new();
    leaf_dn.push(DnType::CommonName, "trust-stack test signer");
    let mut leaf_params = CertificateParams::new(vec!["trust-stack.local".to_string()])
        .expect("create leaf cert params");
    leaf_params.distinguished_name = leaf_dn;
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.use_authority_key_identifier_extension = true;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::EmailProtection];
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .expect("sign leaf cert");
    let cert_chain_pem = format!("{}\n{}", leaf_cert.pem(), ca_cert.pem());

    let signer = create_signer::from_keys(
        cert_chain_pem.as_bytes(),
        leaf_key.serialize_pem().as_bytes(),
        SigningAlg::Es256,
        None,
    )
    .expect("create c2pa signer");

    let manifest = serde_json::json!({
        "claim_generator_info": [
            {
                "name": "trust-stack-tests",
                "version": "0.1.0"
            }
        ],
        "title": "test-asset"
    })
    .to_string();
    let mut builder = Builder::from_json(&manifest).expect("build manifest");
    settings::reset_default_settings().expect("reset c2pa settings");
    settings::load_settings_from_str(
        r#"{"verify":{"verify_after_sign":false,"verify_trust":false,"remote_manifest_fetch":false}}"#,
        "json",
    )
    .expect("apply test c2pa settings");
    builder
        .sign(
            signer.as_ref(),
            "image/jpeg",
            &mut File::open(&unsigned).expect("open unsigned"),
            &mut File::create(&signed).expect("create signed"),
        )
        .expect("sign image");
    settings::reset_default_settings().expect("reset c2pa settings");

    (unsigned, signed)
}
