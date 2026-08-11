//! Newline-delimited JSON-RPC stdio bridge to the configured `/mcp` endpoint.

use super::mcp_client::{McpClientError, McpHttpClient, MAX_MCP_MESSAGE_BYTES};
use crate::cli::{Cli, McpCmd};
use ownmesh_domain::{ErrorCode, ExitCode};
use serde_json::Value;
use std::io::{self, BufRead, Read, Write};

#[derive(Debug)]
struct McpFailure {
    code: ErrorCode,
    message: String,
    hint: Option<&'static str>,
}

impl McpFailure {
    fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            hint: None,
        }
    }

    const fn exit_code(&self) -> ExitCode {
        self.code.exit_code()
    }
}

impl From<McpClientError> for McpFailure {
    fn from(value: McpClientError) -> Self {
        Self {
            code: value.code,
            message: value.message,
            hint: value.hint,
        }
    }
}

pub(crate) fn dispatch_mcp(_cli: &Cli, cmd: &McpCmd) -> Result<(), ExitCode> {
    let result = match cmd {
        McpCmd::Serve { stdio: true } => run_stdio(),
        McpCmd::Serve { stdio: false } => Err(McpFailure::new(
            ErrorCode::InvalidArgument,
            "mcp serve requires --stdio",
        )),
    };
    result.map_err(|failure| emit_failure(&failure))
}

fn run_stdio() -> Result<(), McpFailure> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| {
            McpFailure::new(
                ErrorCode::Internal,
                format!("failed to start async runtime: {err}"),
            )
        })?;
    let mut client = runtime
        .block_on(McpHttpClient::from_configured_auth())
        .map_err(McpFailure::from)?;

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();

    while let Some(line) = read_message(&mut input)? {
        let request: Value = serde_json::from_slice(&line).map_err(|err| {
            McpFailure::new(
                ErrorCode::BadEnvelope,
                format!("invalid JSON-RPC input: {err}"),
            )
        })?;
        let response = runtime
            .block_on(client.send_json_rpc(&request))
            .map_err(McpFailure::from)?;
        write_response(&mut output, response.as_ref())?;
    }
    Ok(())
}

fn read_message<R: BufRead>(reader: &mut R) -> Result<Option<Vec<u8>>, McpFailure> {
    let mut line = Vec::new();
    // Two bytes permit CRLF without weakening the 256 KiB message limit; one
    // additional byte proves an unterminated line is oversized without an
    // unbounded allocation.
    let limit = (MAX_MCP_MESSAGE_BYTES + 3) as u64;
    let read = reader
        .take(limit)
        .read_until(b'\n', &mut line)
        .map_err(|err| McpFailure::new(ErrorCode::Internal, format!("read stdin: {err}")))?;
    if read == 0 {
        return Ok(None);
    }
    if line.last() == Some(&b'\n') {
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
    }
    if line.len() > MAX_MCP_MESSAGE_BYTES {
        return Err(McpFailure::new(
            ErrorCode::BadEnvelope,
            format!("MCP input exceeds the {MAX_MCP_MESSAGE_BYTES}-byte limit"),
        ));
    }
    Ok(Some(line))
}

fn write_response<W: Write>(writer: &mut W, response: Option<&Value>) -> Result<(), McpFailure> {
    let Some(response) = response else {
        return Ok(());
    };
    let encoded = serde_json::to_vec(response).map_err(|err| {
        McpFailure::new(
            ErrorCode::Internal,
            format!("encode JSON-RPC response: {err}"),
        )
    })?;
    if encoded.len() > MAX_MCP_MESSAGE_BYTES {
        return Err(McpFailure::new(
            ErrorCode::BadEnvelope,
            format!("MCP output exceeds the {MAX_MCP_MESSAGE_BYTES}-byte limit"),
        ));
    }
    writer
        .write_all(&encoded)
        .and_then(|()| writer.write_all(b"\n"))
        .and_then(|()| writer.flush())
        .map_err(|err| McpFailure::new(ErrorCode::Internal, format!("write stdout: {err}")))
}

fn emit_failure(failure: &McpFailure) -> ExitCode {
    let message = ownmesh_diagnostics::redact_text(&failure.message);
    eprintln!("{}: {message}", failure.code.as_str());
    if let Some(hint) = failure.hint {
        eprintln!("hint: {}", ownmesh_diagnostics::redact_text(hint));
    }
    failure.exit_code()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn oversized_input_is_rejected_without_unbounded_read() {
        let mut input = Cursor::new(vec![b'x'; MAX_MCP_MESSAGE_BYTES + 64]);
        let failure = read_message(&mut input).expect_err("oversized line must fail");
        assert_eq!(failure.code, ErrorCode::BadEnvelope);
        assert!(failure.message.contains("exceeds"));
        assert!(input.position() <= (MAX_MCP_MESSAGE_BYTES + 3) as u64);
    }

    #[test]
    fn notification_produces_no_stdio_response() {
        let mut output = Vec::new();
        write_response(&mut output, None).expect("notification write");
        assert!(output.is_empty());
    }
}
