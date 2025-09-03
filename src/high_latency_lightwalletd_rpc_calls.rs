
/*
# grab only the first (leaf) cert as PEM
openssl s_client -connect na.zec.rocks:443 -servername na.zec.rocks -showcerts </dev/null \
| awk 'BEGIN{p=0}/BEGIN CERT/{p=1}/END CERT/{print; exit} p{print}' > na.zec.rocks-leaf.pem

# convert to DER for a clean byte compare
openssl x509 -in na.zec.rocks-leaf.pem -outform DER -out na.zec.rocks-leaf.der
*/


fn run_this_async_future<F: Future>(future: F) -> F::Output {
    Builder::new_current_thread()
        .enable_time()
        .enable_io()
        .build()
        .expect("build tokio rt")
        .block_on(future)
}

async fn get_verifier(algs: WebPkiSupportedAlgorithms, uri: &ConnectURIAndCertificateBlob, on_fail: u32) -> Option<CompactTxStreamerClient<tonic_rustls::Channel>> { unsafe {
    let verifier = Arc::new(ExactDerVerifier {
        certificate_blob: &*slice_from_raw_parts(uri.certificate_blob_ptr, uri.certificate_blob_len),
        algs,
    });

    let mut cfg = ClientConfig::builder()
        .dangerous() // allows custom verifier
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    // gRPC over HTTP/2 needs ALPN "h2"
    cfg.alpn_protocols.push(b"h2".to_vec());

    let v = uhh(RustlsEndpoint::from_shared(&*slice_from_raw_parts(uri.https_uri_string_ptr, uri.https_uri_string_len)), on_fail).ok()?;
    let v = uhh(v.tls_config(cfg), on_fail).ok()?;
    let channel = uhh(v.connect().await, on_fail).ok()?;
    Some(CompactTxStreamerClient::new(channel))
}}

async fn connect_to_server_and_produce_client_object(uris: &[ConnectURIAndCertificateBlob], on_fail: u32) -> Option<CompactTxStreamerClient<tonic_rustls::Channel>> {
    let _ = CryptoProvider::install_default(ring::default_provider());

    let algs = CryptoProvider::get_default().map(|x| x.signature_verification_algorithms)?;

    for uri_i in 0..uris.len() {
        let on_fail = ((uri_i == uris.len()-1) as u32 * on_fail) | uhh::LOG;
        if let Some(verifier) = get_verifier(algs, &uris[uri_i], on_fail).await {
            return Some(verifier);
        }
    }
    None
}


use super::*;
use std::ptr::slice_from_raw_parts;
use tokio::runtime::Builder;
use zcash_client_backend::proto::service::{
    BlockId,
    Exclude,
    compact_tx_streamer_client::CompactTxStreamerClient,
};
use std::sync::Arc;
use rustls::{ClientConfig};
use rustls::client::danger::{ServerCertVerifier, ServerCertVerified, HandshakeSignatureValid};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::{DigitallySignedStruct, SignatureScheme, Error as TlsError, CertificateError};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tonic_rustls::channel::Endpoint as RustlsEndpoint;
use rustls::crypto::CryptoProvider;
use rustls::crypto::ring;

use crate::{ConnectURIAndCertificateBlob, LightwalletdEndpointArray, uhh};

#[derive(Debug)]
struct ExactDerVerifier {
    // called a 'der'
    certificate_blob: &'static [u8],
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
        if end_entity.as_ref() == self.certificate_blob {
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

// TODO: presumably we want to exclude all the transactions we've already seen
pub fn simple_get_mempool_tx(uris: LightwalletdEndpointArray, on_fail: u32) -> Option<Vec<CompactTx>> {
    run_this_async_future(async move {
        let mut client = connect_to_server_and_produce_client_object(uris.into(), on_fail).await?;
        let tx_stream = uhh(client.get_mempool_tx(Exclude { txid: Vec::new() }).await, on_fail).ok()?;
        let mut grpc_stream = tx_stream.into_inner();

        let mut txs = Vec::new();
        loop {
            if let Ok(msg) = grpc_stream.message().await {
                if let Some(tx) = msg {
                    txs.push(tx);
                } else {
                    return Some(txs);
                }
            } else {
                return None;
            }
        }
    })
}

pub fn simple_get_block(uris: LightwalletdEndpointArray, height: u64, on_fail: u32) -> Option<CompactBlock> {
    run_this_async_future(async move {
        let mut client = connect_to_server_and_produce_client_object(uris.into(), on_fail).await?;
        let block_res = uhh(client.get_block(BlockId { height, hash: Vec::new() }).await, on_fail).ok()?;
        Some(block_res.into_inner())
    })
}
