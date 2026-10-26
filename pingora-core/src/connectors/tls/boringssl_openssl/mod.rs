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

/// The IP address `sni` spells, if any, with or without brackets. RFC 6066 forbids IP
/// literals in SNI, so the caller turns the extension off for them: the TLS library only
/// skips it for the unbracketed forms.
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

    let sni_ip = sni_ip_literal(peer.sni()).map(|ip| ip.to_canonical());
    if sni_ip.is_some() {
        ssl_conf.set_use_server_name_indication(false);
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
            let has_alt_cn = peer.alternative_cn().is_some_and(|a| !a.is_empty());
            // OpenSSL checks the IP and the host list independently, so set_ip together
            // with alt_cn would demand both. With alt_cn the host list (IP string plus
            // alt_cn) is kept and IP SANs are not matched.
            if let (Some(ip), false) = (sni_ip, has_alt_cn) {
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
            "ip_san_v6" => (
                &include_bytes!("../../../../tests/certs/ip_literal/ip_san_v6.crt")[..],
                &include_bytes!("../../../../tests/certs/ip_literal/ip_san_v6.key")[..],
            ),
            _ => unreachable!(),
        };
        (
            X509::from_pem(crt).unwrap(),
            PKey::private_key_from_pem(key).unwrap(),
        )
    }

    /// Serves one TLS handshake on `bind`; returns the port and what the servername
    /// callback saw: `None` if it never ran, `Some(None)` if it ran without an SNI.
    #[allow(clippy::type_complexity)]
    fn serve_once(
        bind: &str,
        cert: &X509,
        key: &PKey<Private>,
    ) -> Option<(u16, Arc<Mutex<Option<Option<String>>>>)> {
        let seen = Arc::new(Mutex::new(None));
        let seen_cb = seen.clone();
        let mut acc = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        acc.set_certificate(cert).unwrap();
        acc.set_private_key(key).unwrap();
        acc.set_servername_callback(move |ssl, _| {
            *seen_cb.lock().unwrap() =
                Some(ssl.servername(NameType::HOST_NAME).map(str::to_string));
            Ok(())
        });
        let acc = acc.build();
        let listener = std::net::TcpListener::bind(bind).ok()?;
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((s, _)) = listener.accept() {
                if let Ok(mut s) = acc.accept(s) {
                    let _ = std::io::Write::write_all(&mut s, b"x");
                }
            }
        });
        Some((port, seen))
    }

    struct Outcome {
        err: Option<String>,
        /// The X509 verify error the client's verify callback saw.
        verify_err: Option<String>,
        /// `None`: the servername callback never ran.
        sni_seen: Option<Option<String>>,
    }

    impl Outcome {
        fn ok(&self) -> bool {
            self.err.is_none()
        }
        /// Asserts the server's callback ran and saw no SNI extension.
        fn assert_no_sni(&self) {
            assert_eq!(
                self.sni_seen,
                Some(None),
                "callback must run and see no SNI"
            );
        }
    }

    /// Connects to a server presenting `cert`, with `sni` as the peer name.
    async fn try_connect(
        cert: &X509,
        key: &PKey<Private>,
        sni: &str,
        tweak: impl FnOnce(&mut HttpPeer),
    ) -> Outcome {
        try_connect_on("127.0.0.1", cert, key, sni, tweak)
            .await
            .unwrap()
    }

    async fn try_connect_on(
        host: &str,
        cert: &X509,
        key: &PKey<Private>,
        sni: &str,
        tweak: impl FnOnce(&mut HttpPeer),
    ) -> Option<Outcome> {
        let (port, seen) = serve_once(&format!("{host}:0"), cert, key)?;
        let addr = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let mut peer = HttpPeer::new(addr, true, sni.to_string());
        peer.options.ca = Some(Arc::new(vec![cert.clone()].into_boxed_slice()));
        tweak(&mut peer);
        let tcp = tokio::net::TcpStream::connect((host, port)).await.unwrap();
        let verify_err = Arc::new(Mutex::new(None));
        let verify_err_cb = verify_err.clone();
        let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
        builder.set_verify_callback(SslVerifyMode::PEER, move |ok, ctx| {
            if !ok {
                verify_err_cb
                    .lock()
                    .unwrap()
                    .get_or_insert_with(|| verify_error_text(ctx));
            }
            ok
        });
        let ctx = builder.build();
        let res = connect(Stream::from(tcp), &peer, None, &ctx).await;
        let sni_seen = seen.lock().unwrap().clone();
        let verify_err = verify_err.lock().unwrap().clone();
        Some(Outcome {
            err: res.err().map(|e| e.to_string()),
            verify_err,
            sni_seen,
        })
    }

    #[cfg(not(feature = "boringssl"))]
    fn verify_error_text(ctx: &crate::tls::x509::X509StoreContextRef) -> String {
        ctx.error().error_string().to_string()
    }

    // boring's X509StoreContextRef has no error getter: the reason cannot be read there.
    #[cfg(feature = "boringssl")]
    fn verify_error_text(_: &crate::tls::x509::X509StoreContextRef) -> String {
        String::new()
    }

    fn assert_rejected(o: &Outcome, what: &str) {
        assert!(o.err.is_some(), "handshake must fail");
        if cfg!(not(feature = "boringssl")) {
            assert_eq!(o.verify_err.as_deref(), Some(what));
        }
    }

    #[test]
    fn sni_ip_literal_forms() {
        let ip = |s: &str| s.parse::<IpAddr>().ok();
        assert_eq!(sni_ip_literal("::1"), ip("::1"));
        assert_eq!(sni_ip_literal("[::1]"), ip("::1"));
        assert_eq!(sni_ip_literal("127.0.0.1"), ip("127.0.0.1"));
        assert_eq!(sni_ip_literal("[127.0.0.1]"), ip("127.0.0.1"));
        assert_eq!(sni_ip_literal("fe80::1%eth0"), None);
        assert_eq!(sni_ip_literal("host"), None);
        assert_eq!(sni_ip_literal("::ffff:10.0.0.5"), ip("::ffff:10.0.0.5"));
    }

    #[tokio::test]
    async fn ip_sni_matches_ip_san() {
        let (cert, key) = fixture("ip_san");
        let o = try_connect(&cert, &key, "127.0.0.1", |_| {}).await;
        assert!(
            o.ok(),
            "IP SAN must verify an IP-literal upstream: {:?}",
            o.err
        );
        o.assert_no_sni();
    }

    #[tokio::test]
    async fn ip_sni_matches_ip_san_with_dns_san_too() {
        let (cert, key) = fixture("ip_and_dns_san");
        let o = try_connect(&cert, &key, "127.0.0.1", |_| {}).await;
        assert!(o.ok(), "{:?}", o.err);
    }

    #[tokio::test]
    async fn ip_sni_rejects_dns_only_cert() {
        let (cert, key) = fixture("dns_only");
        let o = try_connect(&cert, &key, "127.0.0.1", |_| {}).await;
        assert_rejected(&o, "IP address mismatch");
        o.assert_no_sni();
    }

    #[tokio::test]
    async fn ip_sni_rejects_wrong_ip() {
        let (cert, key) = fixture("other_ip");
        let o = try_connect(&cert, &key, "127.0.0.1", |_| {}).await;
        assert_rejected(&o, "IP address mismatch");
    }

    #[tokio::test]
    async fn ip_sni_without_hostname_verification_accepts_other_ip() {
        let (cert, key) = fixture("other_ip");
        let o = try_connect(&cert, &key, "127.0.0.1", |p| {
            p.options.verify_hostname = false
        })
        .await;
        assert!(o.ok(), "{:?}", o.err);
        o.assert_no_sni();
    }

    // With alternative_cn the host list (IP string plus alt_cn) is used and IP SANs are
    // not consulted, so OpenSSL's independent IP check is not added on top of it.
    #[tokio::test]
    async fn ip_sni_with_alternative_cn_matches_dns_cert() {
        let (cert, key) = fixture("dns_backend");
        let o = try_connect(&cert, &key, "127.0.0.1", |p| {
            p.options.alternative_cn = Some("backend.internal".to_string())
        })
        .await;
        assert!(o.ok(), "{:?}", o.err);
        o.assert_no_sni();
    }

    #[tokio::test]
    async fn ip_sni_with_alternative_cn_ignores_ip_san() {
        let (cert, key) = fixture("ip_san");
        let o = try_connect(&cert, &key, "127.0.0.1", |p| {
            p.options.alternative_cn = Some("backend.internal".to_string())
        })
        .await;
        assert_rejected(&o, "hostname mismatch");
    }

    #[tokio::test]
    async fn bracketed_ipv6_sni_sends_no_sni_and_matches_ip_san() {
        let (cert, key) = fixture("ip_san_v6");
        let Some(o) = try_connect_on("::1", &cert, &key, "[::1]", |_| {}).await else {
            eprintln!("skipped: ::1 cannot be bound");
            return;
        };
        assert!(o.ok(), "{:?}", o.err);
        o.assert_no_sni();
    }

    #[tokio::test]
    async fn dns_sni_still_sent_and_checked() {
        let (cert, key) = fixture("dns_backend");
        let o = try_connect(&cert, &key, "backend.internal", |_| {}).await;
        assert!(o.ok(), "{:?}", o.err);
        assert_eq!(o.sni_seen, Some(Some("backend.internal".to_string())));

        let o = try_connect(&cert, &key, "other.internal", |_| {}).await;
        assert_rejected(&o, "hostname mismatch");
    }
}
