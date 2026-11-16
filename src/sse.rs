// Event-based SSE rewriter: events are separated by a blank line, data: lines
// within one event are joined per the SSE spec. Only rewritten data frames and
// [DONE] pass; event:, id:, retry: and comment lines are dropped.
use crate::redact::redact_chunk;

pub struct SseRewriter {
    buf: Vec<u8>,
    alias: String,
}

impl SseRewriter {
    pub fn new(alias: &str) -> Self {
        SseRewriter { buf: Vec::new(), alias: alias.to_string() }
    }

    pub fn push(&mut self, chunk: &[u8], out: &mut Vec<u8>) {
        self.buf.extend_from_slice(chunk);
        loop {
            let Some(pos) = find_event_end(&self.buf) else { break };
            let event: Vec<u8> = self.buf.drain(..pos.1).collect();
            self.handle_event(&event[..pos.0], out);
        }
    }

    fn handle_event(&self, event: &[u8], out: &mut Vec<u8>) {
        let text = String::from_utf8_lossy(event);
        let mut data_lines: Vec<String> = Vec::new();
        for line in text.split('\n') {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if let Some(d) = line.strip_prefix("data:") {
                data_lines.push(d.strip_prefix(' ').unwrap_or(d).to_string());
            }
            // event:, id:, retry: and comments are dropped
        }
        if data_lines.is_empty() {
            return;
        }
        let payload = data_lines.join("\n");
        if payload.trim() == "[DONE]" {
            out.extend_from_slice(b"data: [DONE]\n\n");
            return;
        }
        let frames: Vec<serde_json::Value> = match serde_json::from_str::<serde_json::Value>(&payload) {
            Ok(json) => vec![json],
            // some servers pack several JSON chunks into one event's data lines
            Err(_) => data_lines
                .iter()
                .filter_map(|d| serde_json::from_str::<serde_json::Value>(d).ok())
                .collect(),
        };
        for json in frames {
            let rewritten = redact_chunk(&json, &self.alias);
            out.extend_from_slice(b"data: ");
            out.extend_from_slice(rewritten.to_string().as_bytes());
            out.extend_from_slice(b"\n\n");
        }
        // unparseable frames: dropped, not forwarded
    }
}

// returns (event_len, total_len_with_separator)
fn find_event_end(buf: &[u8]) -> Option<(usize, usize)> {
    let mut i = 0;
    while i + 1 < buf.len() {
        if buf[i] == b'\n' && buf[i + 1] == b'\n' {
            return Some((i, i + 2));
        }
        if i + 3 < buf.len() && &buf[i..i + 4] == b"\r\n\r\n" {
            return Some((i, i + 4));
        }
        i += 1;
    }
    None
      }
