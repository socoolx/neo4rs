use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq, Clone)]
pub enum ConnectionTLSConfig {
    None,
    ClientCACertificate(ClientCertificate),
    NoSSLValidation,
    MutualTLS(MutualTLS),
    Tlcp(TlcpConfig),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientCertificate {
    pub(crate) cert_file: PathBuf,
}

impl ClientCertificate {
    pub fn new(path: impl AsRef<Path>) -> Self {
        ClientCertificate {
            cert_file: path.as_ref().to_path_buf(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MutualTLS {
    pub(crate) validation: bool,
    pub(crate) cert_file: Option<PathBuf>,
    pub(crate) client_cert: PathBuf,
    pub(crate) client_key: PathBuf,
}

impl MutualTLS {
    pub fn new(
        cert_file: Option<impl AsRef<Path>>,
        client_cert: impl AsRef<Path>,
        client_key: impl AsRef<Path>,
    ) -> Self {
        MutualTLS {
            validation: true,
            cert_file: cert_file.map(|p| p.as_ref().to_path_buf()),
            client_cert: client_cert.as_ref().to_path_buf(),
            client_key: client_key.as_ref().to_path_buf(),
        }
    }
    pub fn with_no_validation(&self) -> Self {
        Self {
            validation: false,
            ..self.clone()
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TlcpConfig {
    pub(crate) validation: bool,
    pub(crate) ca_cert: Option<PathBuf>,
    pub(crate) sign_cert: Option<PathBuf>,
    pub(crate) sign_key: Option<PathBuf>,
    pub(crate) enc_cert: Option<PathBuf>,
    pub(crate) enc_key: Option<PathBuf>,
}

impl TlcpConfig {
    pub fn new(
        ca_cert: Option<impl AsRef<Path>>,
        sign_cert: Option<impl AsRef<Path>>,
        sign_key: Option<impl AsRef<Path>>,
        enc_cert: Option<impl AsRef<Path>>,
        enc_key: Option<impl AsRef<Path>>,
    ) -> Self {
        TlcpConfig {
            validation: true,
            ca_cert: ca_cert.map(|p| p.as_ref().to_path_buf()),
            sign_cert: sign_cert.map(|p| p.as_ref().to_path_buf()),
            sign_key: sign_key.map(|p| p.as_ref().to_path_buf()),
            enc_cert: enc_cert.map(|p| p.as_ref().to_path_buf()),
            enc_key: enc_key.map(|p| p.as_ref().to_path_buf()),
        }
    }

    pub fn with_no_validation(&self) -> Self {
        Self {
            validation: false,
            ..self.clone()
        }
    }
}
