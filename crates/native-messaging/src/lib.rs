use std::io::{Read, Write};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;

pub const DEFAULT_MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

pub fn write_frame(writer: &mut impl Write, value: &Value) -> Result<()> {
    let bytes = serde_json::to_vec(value).context("serialize native message json")?;
    let len = u32::try_from(bytes.len()).map_err(|_| anyhow!("frame too large"))?;
    writer
        .write_all(&len.to_le_bytes())
        .context("write frame length")?;
    writer.write_all(&bytes).context("write frame payload")?;
    writer.flush().context("flush frame")?;
    Ok(())
}

pub fn read_frame(reader: &mut impl Read, max_frame_bytes: usize) -> Result<Option<Value>> {
    let mut len_bytes = [0u8; 4];
    match reader.read_exact(&mut len_bytes) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e).context("read frame length"),
    }
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len == 0 {
        bail!("empty frame is not allowed");
    }
    if len > max_frame_bytes {
        bail!("frame exceeds max_frame_bytes");
    }
    let mut payload = vec![0u8; len];
    reader
        .read_exact(&mut payload)
        .context("read frame payload")?;
    let value: Value = serde_json::from_slice(&payload).context("parse frame json")?;
    Ok(Some(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_frame() {
        let mut buf = Vec::new();
        let msg = serde_json::json!({"id":"x","v":1});
        write_frame(&mut buf, &msg).unwrap();
        let mut rd = std::io::Cursor::new(buf);
        let decoded = read_frame(&mut rd, DEFAULT_MAX_FRAME_BYTES)
            .unwrap()
            .unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn rejects_oversized_frame() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(100u32).to_le_bytes());
        buf.extend_from_slice(&[b'a'; 100]);
        let mut rd = std::io::Cursor::new(buf);
        let err = read_frame(&mut rd, 50).unwrap_err().to_string();
        assert!(err.contains("max_frame_bytes"));
    }

    #[test]
    fn invalid_json_fails() {
        let mut buf = Vec::new();
        let payload = b"{bad json".to_vec();
        let len = payload.len() as u32;
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&payload);
        let mut rd = std::io::Cursor::new(buf);
        let err = read_frame(&mut rd, DEFAULT_MAX_FRAME_BYTES)
            .unwrap_err()
            .to_string();
        assert!(err.contains("parse frame json"));
    }
}
