//! TLCP（GM/T 0024-2014）国密协议接入实现。
use std::net::IpAddr as StdIpAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio_tongsuo::SslStream;
use tongsuo::{
    ssl::{Ssl, SslContext, SslContextBuilder, SslFiletype, SslMethod, SslVerifyMode},
    x509::verify::X509CheckFlags,
};
use url::Host;

use crate::auth::{ConnectionTLSConfig, TlcpConfig};
use crate::errors::{Error, Result};

pub(crate) fn format_tongsuo_error(
    stage: &str,
    error: &(impl std::fmt::Display + std::fmt::Debug),
) -> String {
    format!("{stage}: {error}; debug: {error:?}")
}

/// 把 Tongsuo 的 SSL/握手错误展开成尽可能详尽的诊断字符串，
/// 包含错误码、I/O 错误、SSL 错误栈等，方便排查国密握手失败问题。
pub(crate) fn format_tongsuo_ssl_error(error: &tongsuo::ssl::Error) -> String {
    let mut parts = vec![format!("OpenSSL error code {}", error.code().as_raw())];
    parts.push(error.to_string());
    if let Some(io_error) = error.io_error() {
        parts.push(format!("io: {io_error}"));
    }
    if let Some(stack) = error.ssl_error() {
        let stack_message = stack.to_string();
        if !stack_message.is_empty() {
            parts.push(format!("stack: {stack_message}"));
        }
    }
    parts.push(format!("debug: {error:?}"));
    parts.join("; ")
}

/// TLCP 连接器：携带共享的 `SSL_CTX` 与目标主机，用于在每条 TCP 连接上
/// 派生独立的 `SSL` 对象并完成 NTLS 握手。
///
/// `SslContext` 内部即是 `SSL_CTX` 引用计数对象。再外包一层 `Arc`
/// 是为了让 `ConnectionInfo`/`PrepareOpts` 在跨连接 clone 时只复制
/// 指针而不是拷贝任何字节，让连接池中所有连接显式共用同一份配置。
#[derive(Clone)]
pub(crate) struct TlcpConnector {
    context: Arc<SslContext>,
    host: Host<Arc<str>>,
}

impl TlcpConnector {
    /// 在给定 TCP 连接上构造 NTLS `SslStream`，但**不**触发握手。
    /// 握手由 [`perform_handshake`] 完成，便于错误信息按阶段细分。
    fn wrap(&self, stream: TcpStream) -> Result<SslStream<TcpStream>> {
        let mut ssl = Ssl::new(self.context.as_ref())
            .map_err(|e| Error::SSLConnectionError(format_tongsuo_error("create TLCP SSL", &e)))?;
        ssl.set_connect_state();
        match &self.host {
            Host::Domain(domain) => {
                ssl.set_hostname(domain).map_err(|e| {
                    Error::SSLConnectionError(format_tongsuo_error("set TLCP SNI hostname", &e))
                })?;
                ssl.param_mut()
                    .set_hostflags(X509CheckFlags::NO_PARTIAL_WILDCARDS);
                ssl.param_mut().set_host(domain).map_err(|e| {
                    Error::SSLConnectionError(format_tongsuo_error(
                        "set TLCP verification host",
                        &e,
                    ))
                })?;
            }
            Host::Ipv4(ip) => {
                ssl.param_mut()
                    .set_ip(StdIpAddr::V4((*ip).into()))
                    .map_err(|e| {
                        Error::SSLConnectionError(format_tongsuo_error(
                            "set TLCP verification IPv4",
                            &e,
                        ))
                    })?;
            }
            Host::Ipv6(ip) => {
                ssl.param_mut()
                    .set_ip(StdIpAddr::V6((*ip).into()))
                    .map_err(|e| {
                        Error::SSLConnectionError(format_tongsuo_error(
                            "set TLCP verification IPv6",
                            &e,
                        ))
                    })?;
            }
        }
        SslStream::new(ssl, stream).map_err(|e| {
            Error::SSLConnectionError(format!(
                "TLCP stream initialization failed: {}",
                format_tongsuo_error("create TLCP SSL stream", &e)
            ))
        })
    }
}

impl std::fmt::Debug for TlcpConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlcpConnector")
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

/// 根据连接级 TLS 配置构建一个共享的 [`TlcpConnector`]。
///
/// 该函数取代了原 `ConnectionInfo::tlcp_connector`：把 SSL_CTX 的初始化、
/// 国密套件清单、CA 校验、客户端双证书加载等所有 Tongsuo 细节统一收纳，
/// 让 `connection.rs` 的调用点退化成一行 dispatch。
pub(crate) fn build_connector(
    host: Host<&str>,
    tls_config: &ConnectionTLSConfig,
) -> Result<TlcpConnector> {
    let tlcp = match tls_config {
        ConnectionTLSConfig::Tlcp(tlcp) => tlcp.clone(),
        _ => TlcpConfig::new(
            None::<&Path>,
            None::<&Path>,
            None::<&Path>,
            None::<&Path>,
            None::<&Path>,
        ),
    };

    let mut builder = SslContextBuilder::new(SslMethod::ntls_client()).map_err(|e| {
        Error::SSLConnectionError(format_tongsuo_error("create TLCP SSL context", &e))
    })?;
    builder.enable_ntls();
    // 仅保留 GM/T 0024-2014 标准命名的 TLCP 套件，移除 Tongsuo 早期版本的
    // `*-WITH-SM4-SM3` 别名（实测在新版本 Tongsuo 上别名已不再注册，
    // 留着会导致 `set_cipher_list` 报 "no cipher match"）。
    // 顺序：前向安全 (ECDHE) 优先，AEAD (GCM) 优先于 CBC。
    builder
        .set_cipher_list(
            "ECDHE-SM2-SM4-GCM-SM3:ECDHE-SM2-SM4-CBC-SM3:\
             ECC-SM2-SM4-GCM-SM3:ECC-SM2-SM4-CBC-SM3",
        )
        .map_err(|e| Error::SSLConnectionError(format_tongsuo_error("set TLCP cipher list", &e)))?;

    if tlcp.validation {
        let ca_cert = tlcp.ca_cert.as_ref().ok_or_else(|| {
            Error::SSLConnectionError("TLCP CA certificate is required".to_string())
        })?;
        builder.set_ca_file(ca_cert).map_err(|e| {
            Error::SSLConnectionError(format_tongsuo_error("load TLCP CA certificate", &e))
        })?;
        builder.set_verify(SslVerifyMode::PEER);
    } else {
        builder.set_verify(SslVerifyMode::NONE);
    }

    match (
        &tlcp.sign_cert,
        &tlcp.sign_key,
        &tlcp.enc_cert,
        &tlcp.enc_key,
    ) {
        (Some(sign_cert), Some(sign_key), Some(enc_cert), Some(enc_key)) => {
            builder
                .set_sign_certificate_file(sign_cert, SslFiletype::PEM)
                .map_err(|e| {
                    Error::SSLConnectionError(format_tongsuo_error(
                        "load TLCP client signing certificate",
                        &e,
                    ))
                })?;
            builder
                .set_sign_private_key_file(sign_key, SslFiletype::PEM)
                .map_err(|e| {
                    Error::SSLConnectionError(format_tongsuo_error(
                        "load TLCP client signing key",
                        &e,
                    ))
                })?;
            builder
                .set_enc_certificate_file(enc_cert, SslFiletype::PEM)
                .map_err(|e| {
                    Error::SSLConnectionError(format_tongsuo_error(
                        "load TLCP client encryption certificate",
                        &e,
                    ))
                })?;
            builder
                .set_enc_private_key_file(enc_key, SslFiletype::PEM)
                .map_err(|e| {
                    Error::SSLConnectionError(format_tongsuo_error(
                        "load TLCP client encryption key",
                        &e,
                    ))
                })?;
        }
        (None, None, None, None) => {}
        _ => {
            return Err(Error::SSLConnectionError(
                "TLCP mutual authentication requires sign cert/key and enc cert/key".to_string(),
            ));
        }
    }

    let host = match host {
        Host::Domain(domain) => Host::Domain(Arc::<str>::from(domain)),
        Host::Ipv4(ip) => Host::Ipv4(ip),
        Host::Ipv6(ip) => Host::Ipv6(ip),
    };

    Ok(TlcpConnector {
        context: Arc::new(builder.build()),
        host,
    })
}

/// 在给定 TCP 连接上完成 NTLS 握手并返回可读写的 `SslStream`。
///
/// 这是 `connection.rs::Connection::prepare` 调度 TLCP 时唯一的 await 点。
pub(crate) async fn perform_handshake(
    connector: &TlcpConnector,
    tcp: TcpStream,
) -> Result<SslStream<TcpStream>> {
    let mut stream = connector.wrap(tcp)?;
    Pin::new(&mut stream).connect().await.map_err(|e| {
        Error::SSLConnectionError(format!(
            "TLCP handshake failed: {}",
            format_tongsuo_ssl_error(&e)
        ))
    })?;
    Ok(stream)
}
