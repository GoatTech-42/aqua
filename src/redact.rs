// Everything a client receives passes through here. Only whitelisted fields
// survive, so provider model ids, metadata and framing cannot leak downstream.
// Scope note: this covers routing metadata and framing. What the model itself
// writes (its prose) cannot be redacted this way.
use serde_json::{json, Map, Value};

fn usage(u: Option<&Value>) -> Option<Value> {
    let u = u?;
    Some(json!({
        "prompt_tokens": u.get("prompt_tokens").and_then(Value::as_u64).unwrap_or(0),
        "completion_tokens": u.get("completion_tokens").and_then(Value::as_u64).unwrap_or(0),
        "total_tokens": u.get("total_tokens").and_then(Value::as_u64).unwrap_or(0),
    }))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn redact_payload(body: &Value, alias: &str) -> Value {
    let choices: Vec<Value> = body
        .get("choices")
        .and_then(Value::as_array)
        .map(|a| a.as_slice())
        .unwrap_or(&[])
        .iter()
        .map(|c| {
            let m = c.get("message").cloned().unwrap_or(Value::Null);
            let mut msg = Map::new();
            msg.insert("role".into(), json!("assistant"));
            msg.insert("content".into(), m.get("content").cloned().unwrap_or(json!("")));
            if let Some(tc) = m.get("tool_calls") {
                msg.insert("tool_calls".into(), tc.clone());
            }
            json!({
                "index": c.get("index").and_then(Value::as_u64).unwrap_or(0),
                "finish_reason": c.get("finish_reason").cloned().unwrap_or(Value::Null),
                "message": Value::Object(msg),
            })
        })
        .collect();
    let mut out = json!({
        "id": "chatcmpl-aqua",
        "object": "chat.completion",
        "created": now(),
        "model": alias,
        "choices": choices,
    });
    if let Some(u) = usage(body.get("usage")) {
        out["usage"] = u;
    }
    out
}

pub fn redact_chunk(data: &Value, alias: &str) -> Value {
    let choices: Vec<Value> = data
        .get("choices")
        .and_then(Value::as_array)
        .map(|a| a.as_slice())
        .unwrap_or(&[])
        .iter()
        .map(|c| {
            let d = c.get("delta").cloned().unwrap_or(Value::Null);
            let mut delta = Map::new();
            if let Some(r) = d.get("role") {
                delta.insert("role".into(), r.clone());
            }
            if let Some(ct) = d.get("content") {
                delta.insert("content".into(), ct.clone());
            }
            if let Some(tc) = d.get("tool_calls") {
                delta.insert("tool_calls".into(), tc.clone());
            }
            json!({
                "index": c.get("index").and_then(Value::as_u64).unwrap_or(0),
                "finish_reason": c.get("finish_reason").cloned().unwrap_or(Value::Null),
                "delta": Value::Object(delta),
            })
        })
        .collect();
    let mut out = json!({
        "id": "chatcmpl-aqua",
        "object": "chat.completion.chunk",
        "created": now(),
        "model": alias,
        "choices": choices,
    });
    if let Some(u) = usage(data.get("usage")) {
        out["usage"] = u;
    }
    out
}
