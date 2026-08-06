//! Length-prefixed framing: 4-byte big-endian length + UTF-8 JSON payload.

use crate::error::{IpcError, IpcResult};
use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum accepted JSON-RPC frame size (16 MiB).
pub const MAX_FRAME_BYTES: u32 = 16 * 1024 * 1024;

/// Encode `payload` as a length-prefixed frame and write it to `writer`.
pub async fn write_frame<W>(writer: &mut W, payload: &[u8]) -> IpcResult<()>
where
    W: AsyncWrite + Unpin,
{
    let len = u32::try_from(payload.len()).map_err(|_| {
        IpcError::Framing(format!(
            "payload too large to frame: {} bytes",
            payload.len()
        ))
    })?;
    if len > MAX_FRAME_BYTES {
        return Err(IpcError::Framing(format!(
            "payload exceeds max frame size ({len} > {MAX_FRAME_BYTES})"
        )));
    }
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Read one length-prefixed frame from `reader`.
pub async fn read_frame<R>(reader: &mut R) -> IpcResult<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0_u8; 4];
    reader.read_exact(&mut len_buf).await.map_err(|err| {
        if err.kind() == std::io::ErrorKind::UnexpectedEof {
            IpcError::Disconnected("peer closed connection while reading frame length".into())
        } else {
            IpcError::Io(err)
        }
    })?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_BYTES {
        return Err(IpcError::Framing(format!(
            "frame length {len} exceeds max {MAX_FRAME_BYTES}"
        )));
    }
    let mut body = vec![0_u8; len as usize];
    if len > 0 {
        reader.read_exact(&mut body).await.map_err(|err| {
            if err.kind() == std::io::ErrorKind::UnexpectedEof {
                IpcError::Disconnected("peer closed connection while reading frame body".into())
            } else {
                IpcError::Io(err)
            }
        })?;
    }
    Ok(body)
}

/// Incremental decoder for buffered transports / tests.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buffer: BytesMut,
}

impl FrameDecoder {
    /// Create an empty decoder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::new(),
        }
    }

    /// Push bytes and return complete frames.
    pub fn push(&mut self, data: &[u8]) -> IpcResult<Vec<Vec<u8>>> {
        self.buffer.extend_from_slice(data);
        let mut out = Vec::new();
        loop {
            if self.buffer.len() < 4 {
                break;
            }
            let len = {
                let mut cursor = &self.buffer[..4];
                cursor.get_u32()
            };
            if len > MAX_FRAME_BYTES {
                return Err(IpcError::Framing(format!(
                    "frame length {len} exceeds max {MAX_FRAME_BYTES}"
                )));
            }
            let total = 4 + len as usize;
            if self.buffer.len() < total {
                break;
            }
            let _ = self.buffer.split_to(4);
            let body = self.buffer.split_to(len as usize).to_vec();
            out.push(body);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn roundtrip_frame() {
        let (mut a, mut b) = duplex(64);
        write_frame(&mut a, br#"{"ok":true}"#).await.unwrap();
        let body = read_frame(&mut b).await.unwrap();
        assert_eq!(body, br#"{"ok":true}"#);
    }

    #[test]
    fn decoder_handles_partial() {
        let mut dec = FrameDecoder::new();
        let payload = b"hi";
        let mut frame = Vec::new();
        frame.extend_from_slice(&2_u32.to_be_bytes());
        frame.extend_from_slice(payload);
        assert!(dec.push(&frame[..1]).unwrap().is_empty());
        let frames = dec.push(&frame[1..]).unwrap();
        assert_eq!(frames, vec![payload.to_vec()]);
    }
}
