// Copyright 2026 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use log::debug;
use pingora_error::{Error, ErrorType::*, OrErr, Result};
use std::net::IpAddr;
use std::sync::{Arc, Once};

use crate::connectors::tls::replace_leftmost_underscore;
use crate::connectors::ConnectorOptions;
use crate::protocols::tls::client::handshake;
use crate::protocols::tls::SslStream;
use crate::protocols::IO;
use crate::tls::ext::{
    add_host, clear_error_stack, ssl_add_chain_cert, ssl_set_groups_list,
    ssl_set_renegotiate_mode_freely, ssl_set_verify_cert_store, ssl_use_certificate,
    ssl_use_private_key, ssl_use_second_key_share,
};
use crate::tls::ssl::{SslConnector, SslFiletype, SslMethod, SslVerifyMode, SslVersion};
use crate::tls::x509::store::X509StoreBuilder;
use crate::upstreams::peer::{Peer, ALPN};

pub type TlsConnector = SslConnector;

const CIPHER_LIST: &str = "AES-128-GCM-SHA256\
    :AES-256-GCM-SHA384\
    :CHACHA20-POLY1305-SHA256\
    :ECDHE-ECDSA-AES128-GCM-SHA256\
    :ECDHE-ECDSA-AES256-GCM-SHA384\
    :ECDHE-RSA-AES128-GCM-SHA256\
    :ECDHE-RSA-AES256-GCM-SHA384\
    :ECDHE-RSA-AES128-SHA\
    :ECDHE-RSA-AES256-SHA384\
    :AES128-GCM-SHA256\
    :AES256-GCM-SHA384\
    :AES128-SHA\
    :AES256-SHA\
    :DES-CBC3-SHA";

/**
 * Enabled signature algorithms for signing/verification (ECDSA).
 * As of 4/10/2023, the only addition to boringssl's defaults is ECDSA_SECP521R1_SHA512.
 *
 * N.B. BoringSSL 5.x uses case-sensitive parsing for signature algorithm names,
 * so these must be in lowercase wire format.
 */
const SIGALG_LIST: &str = "ecdsa_secp256r1_sha256\
    :rsa_pss_rsae_sha256\
    :rsa_pkcs1_sha256\
    :ecdsa_secp384r1_sha384\
    :rsa_pss_rsae_sha384\
    :rsa_pkcs1_sha384\
    :rsa_pss_rsae_sha512\
    :rsa_pkcs1_sha512\
    :rsa_pkcs1_sha1\
    :ecdsa_secp521r1_sha512";

/**
 * Enabled curves for ECDHE (signature key exchange).
 * As of 4/10/2023, the only addition to boringssl's defaults is SECP521R1.
 *
 * N.B. The ordering of these curves is important. The boringssl library will select the first one
 * as a guess when negotiating a handshake with a server using TLSv1.3. We should opt for curves
 * that are both computationally cheaper and more supported.
 */
#[cfg(feature = "boringssl")]
const BORINGSSL_CURVES_LIST: &str = "X25519:P-256:P-384:P-521";

static INIT_CA_ENV: Once = Once::new();
fn init_ssl_cert_env_vars() {
    // this sets env vars to pick up the root certs
    // it is universal across openssl and boringssl
    // safety: although impossible to prove safe we assume it's safe since the call is
    // wrapped in a call_once and it's unlikely other threads are reading these vars
    INIT_CA_ENV.call_once(|| unsafe { openssl_probe::init_openssl_env_vars() });
}

#[derive(Clone)]
pub struct Connector {
    pub(crate) ctx: Arc<SslConnector>, // Arc to support clone
}

impl Connector {
    pub fn new(options: Option<ConnectorOptions>) -> Self {
        let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
        // TODO: make these conf
        // Set supported ciphers.
        builder.set_cipher_list(CIPHER_LIST).unwrap();
        // Set supported signature algorithms and ECDH (key exchange) curves.
        builder.set_sigalgs_list(SIGALG_LIST).unwrap();
        #[cfg(feature = "boringssl")]
        builder.set_curves_list(BORINGSSL_CURVES_LIST).unwrap();
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        builder
            .set_min_proto_version(Some(SslVersion::TLS1))
            .unwrap();
        if let Some(conf) = options.as_ref() {
            if let Some(ca_file_path) = conf.ca_file.as_ref() {
                builder.set_ca_file(ca_file_path).unwrap();
            } else {
                init_ssl_cert_env_vars();
                // load from default system wide trust location. (the name is misleading)
                builder.set_default_verify_paths().unwrap();
            }
            if let Some((cert, key)) = conf.cert_key_file.as_ref() {
                builder.set_certificate_chain_file(cert).unwrap();

                builder.set_private_key_file(key, SslFiletype::PEM).unwrap();
            }
            if conf.debug_ssl_keylog {
                // write TLS keys to file specified by SSLKEYLOGFILE if it exists
                if let Some(keylog) = std::env::var_os("SSLKEYLOGFILE").and_then(|path| {
                    std::fs::OpenOptions::new()
                        .append(true)
                        .create(true)
                        .open(path)
                        .ok()
                }) {
                    use std::io::Write;
                    builder.set_keylog_callback(move |_, line| {
                        let _ = writeln!(&keylog, "{}", line);
                    });
                }
            }
        } else {
            init_ssl_cert_env_vars();
            builder.set_default_verify_paths().unwrap();
        }

        Connector {
            ctx: Arc::new(builder.build()),
        }
    }
}

/// The IP address `sni` spells, if any. RFC 6066 forbids IP literals in SNI; the TLS
/// library already leaves the extension out for them.
fn sni_ip_literal(sni: &str) -> Option<IpAddr> {
    let bare = sni
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(sni);
    bare.parse().ok()
}

pub(crate) async fn connect<T, P>(
    stream: T,
    peer: &P,
    alpn_override: Option<ALPN>,
    tls_ctx: &SslConnector,
) -> Result<SslStream<T>>
where
    T: IO,
    P: Peer + Send + Sync,
{
    let mut ssl_conf = tls_ctx.configure().unwrap();

    ssl_set_renegotiate_mode_freely(&mut ssl_conf);

    // Set up CA/verify cert store
    // TODO: store X509Store in the peer directly
    if let Some(ca_list) = peer.get_ca() {
        let mut store_builder = X509StoreBuilder::new().unwrap();
        for ca in &***ca_list {
            store_builder.add_cert(ca.clone()).unwrap();
        }
        ssl_set_verify_cert_store(&mut ssl_conf, &store_builder.build())
            .or_err(InternalError, "failed to load cert store")?;
    }

    // Set up client cert/key
    if let Some(key_pair) = peer.get_client_cert_key() {
        debug!("setting client cert and key");
        ssl_use_certificate(&mut ssl_conf, key_pair.leaf())
            .or_err(InternalError, "invalid client cert")?;
        ssl_use_private_key(&mut ssl_conf, key_pair.key())
            .or_err(InternalError, "invalid client key")?;

        let intermediates = key_pair.intermediates();
        if !intermediates.is_empty() {
            debug!("adding intermediate certificates for mTLS chain");
            for int in intermediates {
                ssl_add_chain_cert(&mut ssl_conf, int)
                    .or_err(InternalError, "invalid intermediate client cert")?;
            }
        }
    }

    if let Some(curve) = peer.get_peer_options().and_then(|o| o.curves.as_deref()) {
        ssl_set_groups_list(&mut ssl_conf, curve).or_err(InternalError, "invalid curves")?;
    }

    // second_keyshare is default true
    if !peer.get_peer_options().is_none_or(|o| o.second_keyshare) {
        ssl_use_second_key_share(&mut ssl_conf, false);
    }

    // disable verification if sni does not exist
    // XXX: verify on empty string cause null string seg fault
    if peer.sni().is_empty() {
        ssl_conf.set_use_server_name_indication(false);
        /* NOTE: technically we can still verify who signs the cert but turn it off to be
        consistent with nginx's behavior */
        ssl_conf.set_verify(SslVerifyMode::NONE);
    } else if peer.verify_cert() {
        if peer.verify_hostname() {
            let verify_param = ssl_conf.param_mut();
            if let Some(ip) = sni_ip_literal(peer.sni()) {
                // An IP literal is checked against IP SANs; add_host only matches DNS names.
                verify_param
                    .set_ip(ip)
                    .or_err(InternalError, "failed to set ip")?;
            } else {
                add_host(verify_param, peer.sni()).or_err(InternalError, "failed to add host")?;
                // if sni had underscores in leftmost label replace and add
                if let Some(sni_s) = replace_leftmost_underscore(peer.sni()) {
                    add_host(verify_param, sni_s.as_ref()).unwrap();
                }
            }
            if let Some(alt_cn) = peer.alternative_cn() {
                if !alt_cn.is_empty() {
                    add_host(verify_param, alt_cn).unwrap();
                    // if alt_cn had underscores in leftmost label replace and add
                    if let Some(alt_cn_s) = replace_leftmost_underscore(alt_cn) {
                        add_host(verify_param, alt_cn_s.as_ref()).unwrap();
                    }
                }
            }
        }
        ssl_conf.set_verify(SslVerifyMode::PEER);
    } else {
        ssl_conf.set_verify(SslVerifyMode::NONE);
    }

    /*
       We always set set_verify_hostname(false) here because:
        - verify case.)  otherwise ssl.connect calls X509_VERIFY_PARAM_set1_host
                         which overrides the names added by add_host. Verify is
                         essentially on as long as the names are added.
        - off case.)    the non verify hostname case should have it disabled
    */
    ssl_conf.set_verify_hostname(false);

    if let Some(alpn) = alpn_override.as_ref().or(peer.get_alpn()) {
        ssl_conf.set_alpn_protos(alpn.to_wire_preference()).unwrap();
    }

    clear_error_stack();

    let complete_hook = peer
        .get_peer_options()
        .and_then(|o| o.upstream_tls_handshake_complete_hook.clone());
    let connect_future = handshake(ssl_conf, peer.sni(), stream, complete_hook);

    match peer.connection_timeout() {
        Some(t) => match pingora_timeout::timeout(t, connect_future).await {
            Ok(res) => res,
            Err(_) => Error::e_explain(
                ConnectTimedout,
                format!("connecting to server {}, timeout {:?}", peer, t),
            ),
        },
        None => connect_future.await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::l4::stream::Stream;
    use crate::tls::pkey::{PKey, Private};
    use crate::tls::ssl::{NameType, SslAcceptor};
    use crate::tls::x509::X509;
    use crate::upstreams::peer::HttpPeer;
    use std::sync::Mutex;

    /// Self-signed fixtures (tests/certs/ip_literal), each trusting only itself.
    fn fixture(name: &str) -> (X509, PKey<Private>) {
        let (crt, key) = match name {
            "ip_san" => (
                &include_bytes!("../../../../tests/certs/ip_literal/ip_san.crt")[..],
                &include_bytes!("../../../../tests/certs/ip_literal/ip_san.key")[..],
            ),
            "ip_and_dns_san" => (
                &include_bytes!("../../../../tests/certs/ip_literal/ip_and_dns_san.crt")[..],
                &include_bytes!("../../../../tests/certs/ip_literal/ip_and_dns_san.key")[..],
            ),
            "dns_only" => (
                &include_bytes!("../../../../tests/certs/ip_literal/dns_only.crt")[..],
                &include_bytes!("../../../../tests/certs/ip_literal/dns_only.key")[..],
            ),
            "other_ip" => (
                &include_bytes!("../../../../tests/certs/ip_literal/other_ip.crt")[..],
                &include_bytes!("../../../../tests/certs/ip_literal/other_ip.key")[..],
            ),
            "dns_backend" => (
                &include_bytes!("../../../../tests/certs/ip_literal/dns_backend.crt")[..],
                &include_bytes!("../../../../tests/certs/ip_literal/dns_backend.key")[..],
            ),
            _ => unreachable!(),
        };
        (
            X509::from_pem(crt).unwrap(),
            PKey::private_key_from_pem(key).unwrap(),
        )
    }

    /// Serves one TLS handshake; returns the port and the SNI the server saw.
    fn serve_once(cert: &X509, key: &PKey<Private>) -> (u16, Arc<Mutex<Option<String>>>) {
        let seen = Arc::new(Mutex::new(None));
        let seen_cb = seen.clone();
        let mut acc = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        acc.set_certificate(cert).unwrap();
        acc.set_private_key(key).unwrap();
        acc.set_servername_callback(move |ssl, _| {
            *seen_cb.lock().unwrap() = ssl.servername(NameType::HOST_NAME).map(str::to_string);
            Ok(())
        });
        let acc = acc.build();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((s, _)) = listener.accept() {
                if let Ok(mut s) = acc.accept(s) {
                    let _ = std::io::Write::write_all(&mut s, b"x");
                }
            }
        });
        (port, seen)
    }

    /// Connects to a server presenting `cert`, with `sni` as the peer name.
    async fn try_connect(cert: &X509, key: &PKey<Private>, sni: &str) -> (bool, Option<String>) {
        let (port, seen) = serve_once(cert, key);
        let mut peer = HttpPeer::new(format!("127.0.0.1:{port}"), true, sni.to_string());
        peer.options.ca = Some(Arc::new(vec![cert.clone()].into_boxed_slice()));
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let connector = Connector::new(None);
        let ok = connect(Stream::from(tcp), &peer, None, &connector.ctx)
            .await
            .is_ok();
        let sni_seen = seen.lock().unwrap().clone();
        (ok, sni_seen)
    }

    #[tokio::test]
    async fn ip_sni_matches_ip_san() {
        let (cert, key) = fixture("ip_san");
        let (ok, sni) = try_connect(&cert, &key, "127.0.0.1").await;
        assert!(ok, "IP SAN must verify an IP-literal upstream");
        assert_eq!(sni, None, "no SNI for an IP literal");
    }

    #[tokio::test]
    async fn ip_sni_matches_ip_san_with_dns_san_too() {
        let (cert, key) = fixture("ip_and_dns_san");
        let (ok, _) = try_connect(&cert, &key, "127.0.0.1").await;
        assert!(ok);
    }

    #[tokio::test]
    async fn ip_sni_rejects_dns_only_cert() {
        let (cert, key) = fixture("dns_only");
        let (ok, sni) = try_connect(&cert, &key, "127.0.0.1").await;
        assert!(!ok, "a DNS SAN must not satisfy an IP-literal upstream");
        assert_eq!(sni, None);
    }

    #[tokio::test]
    async fn ip_sni_rejects_wrong_ip() {
        let (cert, key) = fixture("other_ip");
        let (ok, _) = try_connect(&cert, &key, "127.0.0.1").await;
        assert!(!ok);
    }

    #[tokio::test]
    async fn dns_sni_still_sent_and_checked() {
        let (cert, key) = fixture("dns_backend");
        let (ok, sni) = try_connect(&cert, &key, "backend.internal").await;
        assert!(ok);
        assert_eq!(sni.as_deref(), Some("backend.internal"));

        let (ok, _) = try_connect(&cert, &key, "other.internal").await;
        assert!(!ok);
    }
}
