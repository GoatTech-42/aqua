// Event-based SSE rewriter: events are separated by a blank line, data: lines
// within one event are joined per the SSE spec. Only rewritten data frames and
// [DONE] pass; event:, id:, retry: and comment lines are dropped.
use crate::redact::redact_chunk;

// bound on one undelimited event: an upstream that never sends a blank line
// must not grow this buffer without limit
pub const MAX_PENDING: usize = 256 * 1024;

pub struct SseRewriter {
    buf: Vec<u8>,
    alias: String,
}

impl SseRewriter {
    pub fn new(alias: &str) -> Self {
        SseRewriter { buf: Vec::new(), alias: alias.to_string() }
    }

    // Incremental per-event cap: the buffer never exceeds MAX_PENDING + 1,
    // whatever size chunk the caller passes - a complete oversize event is
    // refused at the cap, never parsed, and an incomplete one is refused once
    // it crosses the cap. The cap bounds ONE event, not the network batch it
    // arrived in (legal near-cap events pass however they are segmented).
    // On false the caller must end the stream honestly (response headers are
    // long committed - never fail over mid-response); the tail is dropped.
    pub fn push(&mut self, chunk: &[u8], out: &mut Vec<u8>) -> bool {
        let mut rest = chunk;
        while !rest.is_empty() {
            let room = (MAX_PENDING + 1).saturating_sub(self.buf.len());
            if room == 0 {
                return false; // one event crossed the cap; stop accepting bytes
            }
            let take = room.min(rest.len());
            self.buf.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            while let Some(pos) = find_event_end(&self.buf) {
                let event: Vec<u8> = self.buf.drain(..pos.1).collect();
                self.handle_event(&event[..pos.0], out);
            }
        }
        self.buf.len() <= MAX_PENDING
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

#[cfg(test)]
mod tests {
    use super::*;

    // independent watchdog regression, RED on the second cut: a COMPLETE
    // oversize event must be refused at the cap, never parsed or emitted
    #[test]
    fn reviewer_complete_oversize_event_must_not_bypass_cap() {
        let payload = format!("data: {{\"choices\":[{{\"delta\":{{\"content\":\"{}\"}}}}]}}\n\n", "x".repeat(MAX_PENDING));
        let mut r = SseRewriter::new("public");
        let mut out = vec![];
        let split = MAX_PENDING - 1;
        assert!(r.push(&payload.as_bytes()[..split], &mut out));
        assert!(!r.push(&payload.as_bytes()[split..], &mut out), "oversized COMPLETE event bypassed cap at delimiter");
        assert!(out.is_empty());
        // and even as ONE huge push, the append itself is bounded
        let huge = format!("data: {}{}\n\n", "y".repeat(3 * MAX_PENDING), "");
        let mut r2 = SseRewriter::new("public");
        let mut out2 = vec![];
        assert!(!r2.push(huge.as_bytes(), &mut out2));
        assert!(r2.buf.len() <= MAX_PENDING + 1, "append itself bounded");
        assert!(out2.is_empty());
    }

    // independent watchdog boundary regression, RED on the first cut
    // (pending+whole-chunk pre-check rejected legal near-cap events), fixed by
    // drain-then-cap: the cap bounds one pending event, not the network batch
    #[test]
    fn reviewer_legal_event_near_cap_must_not_depend_on_network_segmentation() {
        let payload = format!("data: {{\"choices\":[{{\"delta\":{{\"content\":\"{}\"}}}}]}}\n\n", "x".repeat(MAX_PENDING - 100));
        assert!(payload.len() < MAX_PENDING);
        let split = payload.len() - 2;
        let mut second = payload.as_bytes()[split..].to_vec();
        second.extend_from_slice(
            format!("data: {{\"choices\":[{{\"delta\":{{\"content\":\"{}\"}}}}]}}\n\n", "y".repeat(200)).as_bytes(),
        );
        let mut r = SseRewriter::new("model");
        let mut out = vec![];
        assert!(r.push(&payload.as_bytes()[..split], &mut out));
        assert!(r.push(&second, &mut out), "two individually legal events rejected on batch size");
        let text = String::from_utf8_lossy(&out);
        assert_eq!(text.matches("data: {").count(), 2, "both events delivered");
    }

    #[test]
    fn multiple_events_in_one_chunk_all_drain() {
        let mut r = SseRewriter::new("public");
        let mut out = Vec::new();
        let ev = b"data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n";
        let mut batch = Vec::new();
        for _ in 0..50 {
            batch.extend_from_slice(ev);
        }
        assert!(r.push(&batch, &mut out));
        assert!(r.buf.is_empty());
        assert_eq!(String::from_utf8_lossy(&out).matches("data: {").count(), 50);
    }

    #[test]
    fn crlf_separator_split_across_chunks_still_terminates() {
        let mut r = SseRewriter::new("public");
        let mut out = Vec::new();
        let ev = b"data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\r\n\r\n";
        let split = ev.len() - 1; // leave the final \n for the next chunk
        assert!(r.push(&ev[..split], &mut out));
        assert!(out.is_empty(), "no event before the separator completes");
        assert!(r.push(&ev[split..], &mut out));
        assert_eq!(String::from_utf8_lossy(&out).matches("data: {").count(), 1);
    }

    #[test]
    fn multibyte_utf8_split_across_chunks_survives() {
        let mut r = SseRewriter::new("public");
        let mut out = Vec::new();
        let ev = "data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"héllo\"}}]}\n\n".as_bytes();
        // split inside the two-byte é
        let pos = ev.windows(2).position(|w| w == "é".as_bytes()).unwrap();
        assert!(r.push(&ev[..pos + 1], &mut out));
        assert!(r.push(&ev[pos + 1..], &mut out));
        assert!(String::from_utf8_lossy(&out).contains("héllo"));
    }

    #[test]
    fn undelimited_blob_overflows_instead_of_growing() {
        let mut r = SseRewriter::new("public");
        let mut out = Vec::new();
        let chunk = vec![b'x'; 64 * 1024];
        for _ in 0..4 {
            assert!(r.push(&chunk, &mut out), "exactly at the cap is still legal");
        }
        assert!(!r.push(&chunk, &mut out), "one pending event past the cap overflows");
        let peak = r.buf.len();
        assert!(peak <= MAX_PENDING + chunk.len(), "bounded even at overflow");
        assert!(!r.push(&chunk, &mut out), "stays refused");
        assert_eq!(r.buf.len(), peak, "no further growth after overflow");
    }

    #[test]
    fn delimited_events_still_flow_under_the_cap() {
        let mut r = SseRewriter::new("public");
        let mut out = Vec::new();
        let ev = b"data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n";
        for _ in 0..100 {
            assert!(r.push(ev, &mut out), "small delimited events never overflow");
        }
        assert!(r.buf.is_empty(), "complete events drain the buffer");
        let text = String::from_utf8_lossy(&out);
        assert_eq!(text.matches("data: {").count(), 100);
    }
}
