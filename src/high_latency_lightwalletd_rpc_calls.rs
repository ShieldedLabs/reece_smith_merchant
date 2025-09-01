
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

async fn connect_to_server_and_produce_client_object(uris: &[ConnectURIAndCertificateBlob]) -> CompactTxStreamerClient<tonic_rustls::Channel> { unsafe {
    if let Some(got) = try_connect_to_server_and_produce_client_object(&uris[0..uris.len()-1]).await { return got; }
    let uri = uris.last().unwrap();
    {
        let _ = CryptoProvider::install_default(ring::default_provider());

        let algs = CryptoProvider::get_default()
            .expect("CryptoProvider not installed")
            .signature_verification_algorithms;

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
        
        let channel = RustlsEndpoint::from_shared(
            &*slice_from_raw_parts(uri.https_uri_string_ptr, uri.https_uri_string_len)
            )
            .unwrap()
            .tls_config(cfg)
            .unwrap()  // <- your rustls::ClientConfig from above
            .connect()
            .await
            .unwrap();

        return CompactTxStreamerClient::new(channel);
    }
}}

async fn try_connect_to_server_and_produce_client_object(uris: &[ConnectURIAndCertificateBlob]) -> Option<CompactTxStreamerClient<tonic_rustls::Channel>> { unsafe {
    let _ = CryptoProvider::install_default(ring::default_provider());
    
    let algs = CryptoProvider::get_default().map(|x| x.signature_verification_algorithms)?;

    for uri in uris {
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
    
        if let Ok(v) = RustlsEndpoint::from_shared(&*slice_from_raw_parts(uri.https_uri_string_ptr, uri.https_uri_string_len)) {
            if let Ok(v) = v.tls_config(cfg) {
                if let Ok(channel) = v.connect().await {
                    return Some(CompactTxStreamerClient::new(channel));
                }
            }
        }
    }
    return None;
}}


use std::ptr::slice_from_raw_parts;
use std::time::Instant;
use std::{error::Error, time::Duration};
use tokio::runtime::Builder;
use tonic::transport::Channel;
use zcash_client_backend::proto::compact_formats::CompactTx;
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

use crate::{ConnectURIAndCertificateBlob, LightwalletdEndpointArray};

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

pub fn simple_get_mempool_tx(uris: LightwalletdEndpointArray) -> Vec<CompactTx> {
    run_this_async_future(async move {
        let mut stream = connect_to_server_and_produce_client_object(uris.into())
            .await
            .get_mempool_tx(Exclude { txid: Vec::new() })
            .await
            .unwrap()
            .into_inner();
        
        let mut buf = Vec::new();
        loop {
            if let Some(m) = stream.message().await.unwrap() {
                buf.push(m);
            } else {
                return buf;
            }
        }
    })
}
pub fn simple_try_get_mempool_tx(uris: LightwalletdEndpointArray) -> Option<Vec<CompactTx>> {
    run_this_async_future(async move {
        if let Ok(v) = connect_to_server_and_produce_client_object(uris.into()).await
                            .get_mempool_tx(Exclude { txid: Vec::new() }).await {
            let mut stream = v.into_inner();
            
            let mut buf = Vec::new();
            loop {
                if let Ok(v) = stream.message().await {
                    if let Some(m) = v {
                        buf.push(m);
                    } else {
                        return Some(buf);
                    }
                } else {
                    return None;
                }
            }
        } else {
            None
        }
    })
}
