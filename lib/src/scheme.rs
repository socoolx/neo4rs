//! Bolt URI scheme 常量与解析工具。
//!
//! 该模块是 driver 与上层（如 `cypher-shell`）共享的唯一 scheme 真值表。
//! 任何新增/修改 URI scheme 都只在本文件维护，避免上下游各自硬编码导致
//! 行为漂移。

use crate::errors::{Error, Result};

/// 解析 URI scheme 后得到的语义信息。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemeInfo {
    /// scheme 字面量（小写，不含 `://`）
    pub scheme: &'static str,
    /// 是否启用客户端路由（cluster routing）
    pub routing: bool,
    /// 是否启用传输层加密
    pub encryption: bool,
    /// 是否校验服务端证书
    pub validation: bool,
    /// 是否使用 TLCP（国密）协议
    pub tlcp: bool,
}

/// driver / shell 共享的 scheme 真值表。
///
/// 顺序：未加密 → TLS → TLCP；单点 → cluster；neo4j 兼容。
pub const SCHEMES: &[SchemeInfo] = &[
    // bolt 单点
    SchemeInfo {
        scheme: "bolt",
        routing: false,
        encryption: false,
        validation: false,
        tlcp: false,
    },
    SchemeInfo {
        scheme: "bolt+s",
        routing: false,
        encryption: true,
        validation: true,
        tlcp: false,
    },
    SchemeInfo {
        scheme: "bolt+ssl",
        routing: false,
        encryption: true,
        validation: true,
        tlcp: false,
    },
    SchemeInfo {
        scheme: "bolt+ssc",
        routing: false,
        encryption: true,
        validation: false,
        tlcp: false,
    },
    SchemeInfo {
        scheme: "bolt+gms",
        routing: false,
        encryption: true,
        validation: true,
        tlcp: true,
    },
    SchemeInfo {
        scheme: "bolt+gmssl",
        routing: false,
        encryption: true,
        validation: true,
        tlcp: true,
    },
    SchemeInfo {
        scheme: "bolt+gmssc",
        routing: false,
        encryption: true,
        validation: false,
        tlcp: true,
    },
    // bolt cluster
    SchemeInfo {
        scheme: "bolt+cluster",
        routing: true,
        encryption: false,
        validation: false,
        tlcp: false,
    },
    SchemeInfo {
        scheme: "bolt+cluster+ssl",
        routing: true,
        encryption: true,
        validation: true,
        tlcp: false,
    },
    SchemeInfo {
        scheme: "bolt+cluster+ssc",
        routing: true,
        encryption: true,
        validation: false,
        tlcp: false,
    },
    SchemeInfo {
        scheme: "bolt+cluster+gmssl",
        routing: true,
        encryption: true,
        validation: true,
        tlcp: true,
    },
    SchemeInfo {
        scheme: "bolt+cluster+gmssc",
        routing: true,
        encryption: true,
        validation: false,
        tlcp: true,
    },
    // neo4j
    SchemeInfo {
        scheme: "neo4j",
        routing: true,
        encryption: false,
        validation: false,
        tlcp: false,
    },
    SchemeInfo {
        scheme: "neo4j+s",
        routing: true,
        encryption: true,
        validation: true,
        tlcp: false,
    },
    SchemeInfo {
        scheme: "neo4j+ssl",
        routing: true,
        encryption: true,
        validation: true,
        tlcp: false,
    },
    SchemeInfo {
        scheme: "neo4j+ssc",
        routing: true,
        encryption: true,
        validation: false,
        tlcp: false,
    },
];

/// 在静态表中查找 scheme，找不到返回 `None`。
///
/// 空字符串视为 `"bolt"`，与 `Url::parse` 在缺省 scheme 时的行为一致。
pub fn lookup(scheme: &str) -> Option<SchemeInfo> {
    let key = if scheme.is_empty() { "bolt" } else { scheme };
    SCHEMES.iter().find(|s| s.scheme == key).copied()
}

/// 解析 scheme，未识别时返回 [`Error::UnsupportedScheme`]。
pub fn parse(scheme: &str) -> Result<SchemeInfo> {
    lookup(scheme).ok_or_else(|| Error::UnsupportedScheme(scheme.to_owned()))
}

/// 是否是 cluster / routing 协议（用于 shell 触发路由表重连）。
pub fn is_cluster(scheme: &str) -> bool {
    lookup(scheme).map(|s| s.routing).unwrap_or(false)
}

/// 是否是 TLCP（国密）协议。
pub fn is_tlcp(scheme: &str) -> bool {
    lookup(scheme).map(|s| s.tlcp).unwrap_or(false)
}

/// 是否启用 TLS/TLCP 加密（不区分加密种类）。
pub fn is_encrypted(scheme: &str) -> bool {
    lookup(scheme).map(|s| s.encryption).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_known_schemes() {
        assert_eq!(lookup("bolt").unwrap().routing, false);
        assert_eq!(lookup("bolt+s").unwrap().validation, true);
        assert_eq!(lookup("bolt+ssc").unwrap().validation, false);
        assert_eq!(lookup("bolt+gmssl").unwrap().tlcp, true);
        assert_eq!(lookup("neo4j").unwrap().routing, true);
        let neo4j_s = lookup("neo4j+s").unwrap();
        let neo4j_ssl = lookup("neo4j+ssl").unwrap();
        assert_eq!(neo4j_ssl.routing, neo4j_s.routing);
        assert_eq!(neo4j_ssl.encryption, neo4j_s.encryption);
        assert_eq!(neo4j_ssl.validation, neo4j_s.validation);
        assert_eq!(neo4j_ssl.tlcp, neo4j_s.tlcp);
        assert_eq!(lookup("").unwrap().scheme, "bolt");
    }

    #[test]
    fn lookup_unknown_scheme() {
        assert!(lookup("http").is_none());
        assert!(parse("http").is_err());
    }

    #[test]
    fn helpers_consistent_with_table() {
        for s in SCHEMES {
            assert_eq!(is_cluster(s.scheme), s.routing);
            assert_eq!(is_tlcp(s.scheme), s.tlcp);
            assert_eq!(is_encrypted(s.scheme), s.encryption);
        }
    }
}
