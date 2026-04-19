// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Wire protocol for the mediator Unix domain socket.
//!
//! Messages are length-prefixed JSON frames:
//! `[4 bytes: u32 BE payload length][JSON payload]`

use bytes::{Buf, BufMut, BytesMut};
use serde::{Deserialize, Serialize};
use tokio_util::codec::{Decoder, Encoder};

/// Maximum frame size (16 MiB) to prevent memory exhaustion.
const MAX_FRAME_SIZE: u32 = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Request / Response envelopes
// ---------------------------------------------------------------------------

/// A request sent from an agent to the mediator daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// Unique request ID (UUID).
    pub id: String,
    /// Syscall method name.
    pub method: Method,
    /// Hex-encoded HMAC workflow token.
    pub workflow_token: String,
    /// Method-specific parameters.
    pub params: serde_json::Value,
}

/// Recognised mediator methods.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    PolicyPropose,
    ForkWithPolicy,
    RequestPort,
    Ps,
    Signal,
    RevokePolicy,
    PolicyList,
    PolicyGet,
}

/// A response returned by the mediator daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// Echoed request ID.
    pub id: String,
    /// `true` if the call succeeded.
    pub ok: bool,
    /// Present when `ok == true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Present when `ok == false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorPayload>,
}

/// Error detail in a failed response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPayload {
    pub code: String,
    pub message: String,
}

impl Response {
    /// Construct a success response.
    pub fn ok(id: String, result: serde_json::Value) -> Self {
        Self {
            id,
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    /// Construct an error response.
    pub fn err(id: String, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            id,
            ok: false,
            result: None,
            error: Some(ErrorPayload {
                code: code.into(),
                message: message.into(),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Length-prefixed JSON codec
// ---------------------------------------------------------------------------

/// A tokio codec that frames JSON messages with a 4-byte big-endian length
/// prefix.
#[derive(Debug, Default)]
pub struct LengthPrefixedJson;

impl Decoder for LengthPrefixedJson {
    type Item = serde_json::Value;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 4 {
            return Ok(None);
        }

        let len = u32::from_be_bytes([src[0], src[1], src[2], src[3]]);
        if len > MAX_FRAME_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("frame too large: {len} bytes"),
            ));
        }

        let total = 4 + len as usize;
        if src.len() < total {
            src.reserve(total - src.len());
            return Ok(None);
        }

        src.advance(4);
        let payload = src.split_to(len as usize);
        let value: serde_json::Value = serde_json::from_slice(&payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        Ok(Some(value))
    }
}

impl Encoder<serde_json::Value> for LengthPrefixedJson {
    type Error = std::io::Error;

    fn encode(&mut self, item: serde_json::Value, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let payload = serde_json::to_vec(&item)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let len = u32::try_from(payload.len()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "payload too large")
        })?;

        if len > MAX_FRAME_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "payload exceeds max frame size",
            ));
        }

        dst.reserve(4 + payload.len());
        dst.put_u32(len);
        dst.extend_from_slice(&payload);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip() {
        let req = Request {
            id: "req-1".into(),
            method: Method::Ps,
            workflow_token: "deadbeef".into(),
            params: serde_json::json!({}),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: Request = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.method, Method::Ps);
        assert_eq!(parsed.id, "req-1");
    }

    #[test]
    fn response_ok_round_trip() {
        let resp = Response::ok("r-1".into(), serde_json::json!({"port": 8080}));
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: Response = serde_json::from_str(&json).unwrap();
        assert!(parsed.ok);
        assert!(parsed.error.is_none());
        assert_eq!(parsed.result.unwrap()["port"], 8080);
    }

    #[test]
    fn response_err_round_trip() {
        let resp = Response::err("r-2".into(), "EPERM", "not allowed");
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: Response = serde_json::from_str(&json).unwrap();
        assert!(!parsed.ok);
        assert!(parsed.result.is_none());
        assert_eq!(parsed.error.unwrap().code, "EPERM");
    }

    #[test]
    fn codec_encode_decode() {
        let mut codec = LengthPrefixedJson;
        let value = serde_json::json!({"hello": "world"});

        let mut buf = BytesMut::new();
        codec.encode(value.clone(), &mut buf).unwrap();

        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn codec_partial_read() {
        let mut codec = LengthPrefixedJson;
        let value = serde_json::json!({"x": 1});

        let mut buf = BytesMut::new();
        codec.encode(value, &mut buf).unwrap();

        // Feed only 2 bytes — should return None.
        let mut partial = buf.split_to(2);
        assert!(codec.decode(&mut partial).unwrap().is_none());
    }

    #[test]
    fn method_serde() {
        let json = serde_json::to_string(&Method::ForkWithPolicy).unwrap();
        assert_eq!(json, "\"fork_with_policy\"");
        let parsed: Method = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, Method::ForkWithPolicy);
    }
}
