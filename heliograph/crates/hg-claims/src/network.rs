use crate::consts;

/// H3 network binding (ADR-003 D4): the Cardano network magic, `u32` BE — a
/// protocol-native, self-describing identifier, not a config digest. A newtype
/// rather than a closed enum so a private/devnet magic round-trips without a
/// schema change; the verifier's pinned set — never the codec — is the
/// allowlist (R3 policy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkId(u32);

impl NetworkId {
    pub const MAINNET: NetworkId = NetworkId(consts::NET_MAGIC_MAINNET);
    pub const PREPROD: NetworkId = NetworkId(consts::NET_MAGIC_PREPROD);
    pub const PREVIEW: NetworkId = NetworkId(consts::NET_MAGIC_PREVIEW);

    pub const fn from_u32(raw: u32) -> Self {
        Self(raw)
    }

    pub const fn as_u32(self) -> u32 {
        self.0
    }

    pub const fn is_known(self) -> bool {
        matches!(
            self.0,
            consts::NET_MAGIC_MAINNET | consts::NET_MAGIC_PREPROD | consts::NET_MAGIC_PREVIEW
        )
    }
}
