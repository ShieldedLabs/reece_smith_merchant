
pub fn do_all_the_things() {
    use secrecy::ExposeSecret;

    let temp_dir = tempfile::tempdir().unwrap();

    // let mut wdb = zcash_client_sqlite::WalletDb::for_path(temp_dir.path().join("wallet.db"), zcash_protocol::consensus::Network::MainNetwork, zcash_client_sqlite::util::SystemClock, rand_core::OsRng).unwrap();
    let cdb = zcash_client_sqlite::BlockDb::for_path(temp_dir.path().join("cache.db")).unwrap();

    // First run only: create/upgrade the schemas.
    zcash_client_sqlite::chain::init::init_cache_database(&cdb).unwrap();
    // zcash_client_sqlite::wallet::init::init_wallet_db(&mut wdb, None).unwrap();

    // get seed from seed phrase and passphrase
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let bip39_passphrase = ""; // optional
    let mnemonic = bip39::Mnemonic::parse(phrase).unwrap();
    let seed64 = mnemonic.to_seed(bip39_passphrase);
    // assumes passphrase "TREZOR"
    // assert_eq!(&Vec::<u8>::from_hex("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04").unwrap(), &seed64);
    let seed = secrecy::SecretVec::new(seed64[..32].to_vec());

    // 2. Derive Unified Spending Key (USK) from seed
    let account_id = zip32::AccountId::try_from(0).unwrap();
    let usk = zcash_client_backend::keys::UnifiedSpendingKey::from_seed(&zcash_protocol::consensus::MAIN_NETWORK, seed.expose_secret(), account_id).unwrap();

    // 3. Derive Unified Full Viewing Key (UFVK)
    let ufvk: zcash_client_backend::keys::UnifiedFullViewingKey = usk.to_unified_full_viewing_key();
    let uivk: zcash_client_backend::keys::UnifiedIncomingViewingKey = ufvk.to_unified_incoming_viewing_key();
    // Derive the account’s UFVK and default Unified Address (UA).
    // TODO: we want to generate these on a dev PC and transfer to the lower-privileged server
    // ALT: we can do specific handling for Sapling/Orchard incoming view keys without going through a full key
    let ua: zcash_client_backend::address::UnifiedAddress = uivk.default_address(zcash_client_backend::keys::UnifiedAddressRequest::SHIELDED).unwrap().0;
    println!("Receive at: {}", ua.encode(&zcash_protocol::consensus::Network::MainNetwork));

    for _ in 0..3 {
        get_entire_mempool(uivk.clone());
    }
    // ------------------------------------------------------------------------------- //

}


// Define a C-compatible struct with #[repr(C)]
#[repr(C)]
pub struct Vector2 {
    pub x: f32,
    pub y: f32,
}

#[repr(C)]
pub enum MyEnum {
    ThingA,
    ThingB,
}

// Define a C-compatible function with extern "C" and #[no_mangle]
#[unsafe(no_mangle)]
pub extern "C" fn vector2_magnitude(vector: *const Vector2, kind: MyEnum) -> f32 {
    // Safety: Ensure the pointer is valid in real code
    unsafe {
        if vector.is_null() {
            return 0.0;
        }
        let v = &*vector;
        (v.x * v.x + v.y * v.y).sqrt()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        do_all_the_things();
    }
}


// ============================================================================
//                               NEW CODE BELOW
// ============================================================================

use std::time::Instant;
use std::{error::Error, time::Duration};
use tokio::runtime::Builder;
use tonic::transport::Channel;

// Generated client types from lightwalletd's proto
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
use zcash_client_backend::proto::service::Exclude;

use std::sync::Arc;
use tonic::transport::{ClientTlsConfig, Endpoint};
use rustls::{ClientConfig, RootCertStore};

use rustls::client::danger::{ServerCertVerifier, ServerCertVerified, HandshakeSignatureValid};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::{DigitallySignedStruct, SignatureScheme, Error as TlsError, CertificateError, DistinguishedName};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tonic_rustls::channel::Endpoint as RustlsEndpoint;
use rustls::crypto::CryptoProvider;
use rustls::crypto::ring;

#[derive(Debug)]
struct ExactDerVerifier {
    pinned_der: &'static [u8],
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for ExactDerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        // pin exact leaf DER
        if end_entity.as_ref() == self.pinned_der {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::InvalidCertificate(CertificateError::UnknownIssuer))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}
/// Connect to lightwalletd and stream mempool `CompactTx` items.
/// Replace trial-decrypt stubs with your Sapling/Orchard routines.
fn get_entire_mempool(
    uivk: zcash_client_backend::keys::UnifiedIncomingViewingKey,
) {
    let rt = Builder::new_current_thread()
        .enable_time()
        .enable_io()
        .build()
        .expect("build tokio rt");
    rt.block_on(async move {

/*
# grab only the first (leaf) cert as PEM
openssl s_client -connect na.zec.rocks:443 -servername na.zec.rocks -showcerts </dev/null \
| awk 'BEGIN{p=0}/BEGIN CERT/{p=1}/END CERT/{print; exit} p{print}' > na.zec.rocks-leaf.pem

# convert to DER for a clean byte compare
openssl x509 -in na.zec.rocks-leaf.pem -outform DER -out na.zec.rocks-leaf.der
*/

        let start_time = Instant::now();
        // Embed the exact leaf certificate you captured
        static PINNED_LEAF_DER: &[u8] = include_bytes!("../eu.zec.rocks-leaf.der");

        let _ = CryptoProvider::install_default(ring::default_provider());

        let algs = CryptoProvider::get_default()
            .expect("CryptoProvider not installed")
            .signature_verification_algorithms;

        let verifier = Arc::new(ExactDerVerifier { pinned_der: PINNED_LEAF_DER, algs });

        let mut cfg = ClientConfig::builder()
            .dangerous() // allows custom verifier
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

        // gRPC over HTTP/2 needs ALPN "h2"
        cfg.alpn_protocols.push(b"h2".to_vec());
        
        let channel = RustlsEndpoint::from_static("https://eu.zec.rocks:443")
            .tls_config(cfg).unwrap()  // <- your rustls::ClientConfig from above
            .connect()
            .await.unwrap();

        let mut client = CompactTxStreamerClient::new(channel);

        println!("Time 1: {} ms", start_time.elapsed().as_millis());
        for _ in 0..4 {
            let start_time = Instant::now();
            let mut stream = client
                .get_mempool_tx(Exclude { txid: Vec::new() })
                .await.unwrap()
                .into_inner();

            while let Some(ct) = stream.message().await.unwrap() {
            }
            println!("Time 2: {} ms", start_time.elapsed().as_millis());
        }
    });
}

// Re-export the prost/tonic-generated module if needed by your build setup.
// If your build uses `walletrpc` crate directly, this `mod` is not necessary.
// mod walletrpc { tonic::include_proto!("cash.z.wallet.sdk.rpc"); }