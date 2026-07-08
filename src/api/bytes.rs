//! JSON wire format for binary blobs (ciphertext, keys, sealed boxes): all
//! standard base64, wrapped so DTOs can just use `B64` like any other field.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone)]
pub struct B64(pub Vec<u8>);

impl Serialize for B64 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for B64 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        STANDARD
            .decode(s.as_bytes())
            .map(B64)
            .map_err(serde::de::Error::custom)
    }
}

impl From<Vec<u8>> for B64 {
    fn from(v: Vec<u8>) -> Self {
        B64(v)
    }
}

impl From<B64> for Vec<u8> {
    fn from(b: B64) -> Self {
        b.0
    }
}

impl AsRef<[u8]> for B64 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
