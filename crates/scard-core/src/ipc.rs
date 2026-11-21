//! Bounded binary IPC framing between `cred_provider.dll` (`LogonUI.exe`) and
//! `familiar-auth-helper.exe` over anonymous pipes.
//!
//! All frames are strictly bounded to `MAX_IPC_FRAME_LEN` (1024 bytes) and keep
//! PIN and password buffers inside `Zeroizing` containers.

#![forbid(unsafe_code)]

use crate::error::{AuthError, Result};
use std::io::{Read, Write};
use zeroize::Zeroizing;

pub const IPC_MAGIC: [u8; 4] = *b"FSH1";
pub const IPC_VERSION: u8 = 2;
pub const MAX_IPC_FRAME_LEN: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HelperIcon {
    None = 0,
    Warning = 1,
    Error = 2,
}

impl HelperIcon {
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::None),
            1 => Ok(Self::Warning),
            2 => Ok(Self::Error),
            _ => Err(AuthError::Ipc("invalid helper icon code".into())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HelperFailureReason {
    Generic = 0,
    /// Card PIN retry counter is exhausted (`SW=6983` / `63C0`); LogonUI should open PUK unblock fields.
    PinBlocked = 1,
    /// Host 60s safety cooldown before final (3rd) PIN attempt is active.
    CooldownActive = 2,
    /// Supplied PUK was rejected (`SW=63Cx`); stay in PUK unblock mode.
    PukIncorrect = 3,
    /// Card PUK retry counter is permanently exhausted.
    PukBlocked = 4,
}

impl HelperFailureReason {
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::Generic),
            1 => Ok(Self::PinBlocked),
            2 => Ok(Self::CooldownActive),
            3 => Ok(Self::PukIncorrect),
            4 => Ok(Self::PukBlocked),
            _ => Err(AuthError::Ipc("invalid helper failure reason".into())),
        }
    }
}

pub enum HelperOperation {
    Unlock {
        pin: Zeroizing<Vec<u8>>,
    },
    UnblockAndUnlock {
        puk: Zeroizing<Vec<u8>>,
        new_pin: Zeroizing<Vec<u8>>,
    },
}

pub struct HelperRequest {
    pub sid: String,
    pub username: String,
    pub computer: String,
    pub operation: HelperOperation,
}

pub enum HelperResponse {
    Success {
        password: Zeroizing<String>,
    },
    Failure {
        reason: HelperFailureReason,
        icon: HelperIcon,
        message: String,
    },
}

fn push_field(buf: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let len = u16::try_from(bytes.len())
        .map_err(|_| AuthError::Ipc("IPC field exceeds u16::MAX".into()))?;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bytes);
    Ok(())
}

fn read_field<'a>(data: &'a [u8], pos: &mut usize, max_len: usize) -> Result<&'a [u8]> {
    let header_end = pos
        .checked_add(2)
        .ok_or_else(|| AuthError::Ipc("IPC offset overflow".into()))?;
    if header_end > data.len() {
        return Err(AuthError::Ipc("truncated IPC field length".into()));
    }
    let len = u16::from_le_bytes([data[*pos], data[*pos + 1]]) as usize;
    if len > max_len {
        return Err(AuthError::Ipc("IPC field exceeds max length".into()));
    }
    let end = header_end
        .checked_add(len)
        .ok_or_else(|| AuthError::Ipc("IPC offset overflow".into()))?;
    if end > data.len() {
        return Err(AuthError::Ipc("truncated IPC field payload".into()));
    }
    *pos = end;
    Ok(&data[header_end..end])
}

impl HelperRequest {
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut payload = Zeroizing::new(Vec::with_capacity(224));
        payload.extend_from_slice(&IPC_MAGIC);
        payload.push(IPC_VERSION);
        push_field(&mut payload, self.sid.as_bytes())?;
        push_field(&mut payload, self.username.as_bytes())?;
        push_field(&mut payload, self.computer.as_bytes())?;
        match &self.operation {
            HelperOperation::Unlock { pin } => {
                payload.push(1u8);
                push_field(&mut payload, pin.as_slice())?;
            }
            HelperOperation::UnblockAndUnlock { puk, new_pin } => {
                payload.push(2u8);
                push_field(&mut payload, puk.as_slice())?;
                push_field(&mut payload, new_pin.as_slice())?;
            }
        }
        if payload.len() > MAX_IPC_FRAME_LEN {
            return Err(AuthError::Ipc(
                "encoded IPC request exceeds 1024 bytes".into(),
            ));
        }
        Ok(payload)
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 6 || data.len() > MAX_IPC_FRAME_LEN {
            return Err(AuthError::Ipc("invalid IPC request frame size".into()));
        }
        if data[..4] != IPC_MAGIC || data[4] != IPC_VERSION {
            return Err(AuthError::Ipc("bad IPC request magic or version".into()));
        }
        let mut pos = 5usize;
        let sid = std::str::from_utf8(read_field(data, &mut pos, 184)?)
            .map_err(|_| AuthError::Ipc("invalid UTF-8 in SID".into()))?
            .to_string();
        let username = std::str::from_utf8(read_field(data, &mut pos, 256)?)
            .map_err(|_| AuthError::Ipc("invalid UTF-8 in username".into()))?
            .to_string();
        let computer = std::str::from_utf8(read_field(data, &mut pos, 128)?)
            .map_err(|_| AuthError::Ipc("invalid UTF-8 in computer".into()))?
            .to_string();
        let op_tag = *data
            .get(pos)
            .ok_or_else(|| AuthError::Ipc("missing IPC operation tag".into()))?;
        pos += 1;
        let operation = match op_tag {
            1 => {
                let pin_slice = read_field(data, &mut pos, 16)?;
                HelperOperation::Unlock {
                    pin: Zeroizing::new(pin_slice.to_vec()),
                }
            }
            2 => {
                let puk_slice = read_field(data, &mut pos, 16)?;
                let new_pin_slice = read_field(data, &mut pos, 16)?;
                HelperOperation::UnblockAndUnlock {
                    puk: Zeroizing::new(puk_slice.to_vec()),
                    new_pin: Zeroizing::new(new_pin_slice.to_vec()),
                }
            }
            _ => return Err(AuthError::Ipc("unknown IPC operation tag".into())),
        };
        if pos != data.len() {
            return Err(AuthError::Ipc("trailing bytes in IPC request".into()));
        }
        Ok(Self {
            sid,
            username,
            computer,
            operation,
        })
    }
}

impl HelperResponse {
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut payload = Zeroizing::new(Vec::with_capacity(320));
        payload.extend_from_slice(&IPC_MAGIC);
        payload.push(IPC_VERSION);
        match self {
            HelperResponse::Success { password } => {
                payload.push(1u8);
                payload.push(HelperFailureReason::Generic as u8);
                payload.push(HelperIcon::None as u8);
                push_field(&mut payload, password.as_bytes())?;
            }
            HelperResponse::Failure {
                reason,
                icon,
                message,
            } => {
                payload.push(0u8);
                payload.push(*reason as u8);
                payload.push(*icon as u8);
                let truncated = if message.len() > 512 {
                    &message.as_bytes()[..512]
                } else {
                    message.as_bytes()
                };
                push_field(&mut payload, truncated)?;
            }
        }
        if payload.len() > MAX_IPC_FRAME_LEN {
            return Err(AuthError::Ipc(
                "encoded IPC response exceeds 1024 bytes".into(),
            ));
        }
        Ok(payload)
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 8 || data.len() > MAX_IPC_FRAME_LEN {
            return Err(AuthError::Ipc("invalid IPC response frame size".into()));
        }
        if data[..4] != IPC_MAGIC || data[4] != IPC_VERSION {
            return Err(AuthError::Ipc("bad IPC response magic or version".into()));
        }
        let tag = data[5];
        let reason = HelperFailureReason::from_u8(data[6])?;
        let icon = HelperIcon::from_u8(data[7])?;
        let mut pos = 8usize;
        let body = read_field(data, &mut pos, 512)?;
        if pos != data.len() {
            return Err(AuthError::Ipc("trailing bytes in IPC response".into()));
        }
        match tag {
            1 => {
                let mut owned = Zeroizing::new(Vec::with_capacity(body.len()));
                owned.extend_from_slice(body);
                let text = std::str::from_utf8(&owned)
                    .map_err(|_| AuthError::Ipc("invalid UTF-8 in decrypted password".into()))?
                    .to_string();
                Ok(HelperResponse::Success {
                    password: Zeroizing::new(text),
                })
            }
            0 => {
                let message = String::from_utf8_lossy(body).to_string();
                Ok(HelperResponse::Failure {
                    reason,
                    icon,
                    message,
                })
            }
            _ => Err(AuthError::Ipc("unknown IPC response status tag".into())),
        }
    }
}

/// Write a length-prefixed (`u16_le`) frame to `writer`.
pub fn write_framed<W: Write>(mut writer: W, frame: &[u8]) -> Result<()> {
    if frame.is_empty() || frame.len() > MAX_IPC_FRAME_LEN {
        return Err(AuthError::Ipc("IPC frame length out of bounds".into()));
    }
    let len = (frame.len() as u16).to_le_bytes();
    writer
        .write_all(&len)
        .and_then(|_| writer.write_all(frame))
        .and_then(|_| writer.flush())
        .map_err(|e| AuthError::Ipc(format!("pipe write failed: {e}")))
}

/// Read a length-prefixed (`u16_le`) frame from `reader` into a `Zeroizing` buffer.
pub fn read_framed<R: Read>(mut reader: R) -> Result<Zeroizing<Vec<u8>>> {
    let mut len_bytes = [0u8; 2];
    reader
        .read_exact(&mut len_bytes)
        .map_err(|e| AuthError::Ipc(format!("pipe header read failed: {e}")))?;
    let len = u16::from_le_bytes(len_bytes) as usize;
    if len == 0 || len > MAX_IPC_FRAME_LEN {
        return Err(AuthError::Ipc("pipe frame length out of bounds".into()));
    }
    let mut buf = Zeroizing::new(vec![0u8; len]);
    reader
        .read_exact(buf.as_mut_slice())
        .map_err(|e| AuthError::Ipc(format!("pipe body read failed: {e}")))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn request_and_response_roundtrip() {
        let req = HelperRequest {
            sid: "S-1-5-21-1000-2000-3000-1001".into(),
            username: "alice".into(),
            computer: "WORKSTATION".into(),
            operation: HelperOperation::Unlock {
                pin: Zeroizing::new(b"123456".to_vec()),
            },
        };
        let encoded = req.encode().unwrap();
        let mut wire = Vec::new();
        write_framed(&mut wire, &encoded).unwrap();

        let raw_read = read_framed(Cursor::new(&wire)).unwrap();
        let decoded = HelperRequest::decode(&raw_read).unwrap();
        assert_eq!(decoded.sid, req.sid);
        assert_eq!(decoded.username, req.username);
        match decoded.operation {
            HelperOperation::Unlock { pin } => assert_eq!(pin.as_slice(), b"123456"),
            HelperOperation::UnblockAndUnlock { .. } => panic!("expected Unlock"),
        }

        // UnblockAndUnlock roundtrip
        let unblock_req = HelperRequest {
            sid: "S-1-5-21-1000-2000-3000-1001".into(),
            username: "alice".into(),
            computer: "WORKSTATION".into(),
            operation: HelperOperation::UnblockAndUnlock {
                puk: Zeroizing::new(b"12345678".to_vec()),
                new_pin: Zeroizing::new(b"654321".to_vec()),
            },
        };
        let unblock_dec = HelperRequest::decode(&unblock_req.encode().unwrap()).unwrap();
        match unblock_dec.operation {
            HelperOperation::UnblockAndUnlock { puk, new_pin } => {
                assert_eq!(puk.as_slice(), b"12345678");
                assert_eq!(new_pin.as_slice(), b"654321");
            }
            HelperOperation::Unlock { .. } => panic!("expected UnblockAndUnlock"),
        }

        let resp = HelperResponse::Success {
            password: Zeroizing::new("ABCD-EFGH-2345".into()),
        };
        let resp_enc = resp.encode().unwrap();
        let mut resp_wire = Vec::new();
        write_framed(&mut resp_wire, &resp_enc).unwrap();
        let resp_raw = read_framed(Cursor::new(&resp_wire)).unwrap();
        match HelperResponse::decode(&resp_raw).unwrap() {
            HelperResponse::Success { password } => assert_eq!(password.as_str(), "ABCD-EFGH-2345"),
            HelperResponse::Failure { .. } => panic!("expected success"),
        }

        let blocked = HelperResponse::Failure {
            reason: HelperFailureReason::PinBlocked,
            icon: HelperIcon::Error,
            message: "blocked".into(),
        };
        match HelperResponse::decode(&blocked.encode().unwrap()).unwrap() {
            HelperResponse::Failure {
                reason,
                icon,
                message,
            } => {
                assert_eq!(reason, HelperFailureReason::PinBlocked);
                assert_eq!(icon, HelperIcon::Error);
                assert_eq!(message, "blocked");
            }
            HelperResponse::Success { .. } => panic!("expected failure"),
        }
    }
}
