//! Display-only maker list prices. Never used for access, caps or spend ledgers.
use serde_json::{json, Value};

pub fn metadata(model: &str) -> Value {
    let (maker_model, source, input, output, basis) = match model {
        "glm-4.7-flash" => ("GLM-4.7-Flash", "https://docs.z.ai/guides/overview/pricing", 0u64, 0u64,
            "maker API is free within its limits; virtual USD"),
        "north-mini-code" | "north-mini-code-1.0" => ("north-mini-code-1.0", "https://docs.cohere.com/docs/north-mini-code-1.0", 0, 0,
            "maker API is free within its limits; dedicated GPU hosting is not a token tariff; virtual USD"),
        "gemma-4-31b-it" => ("gemma-4-31b-it", "https://ai.google.dev/gemini-api/docs/pricing?authuser=002", 0, 0,
            "maker free API tier; no paid token tier published; virtual USD"),
        "deepseek-v4.1-flash-1017" => ("DeepSeek-V4.1-Flash-1017", "https://api-docs.deepseek.com/quick_start/pricing/", 300_000_000, 1_200_000_000,
            "standard online, uncached input, peak list rate; virtual USD"),
        _ => {
            let reason = match model {
                "deepseek-v4.1-flash" | "deepseek-v4.1-flash-route-b" | "deepseek-v4-flash" | "deepseek-v4-flash:fp8" =>
                    "exact maker API snapshot not verified for this build",
                "nemotron-3-ultra-550b-a55b" | "nemotron-3.5-super-vl" =>
                    "maker offers a free trial endpoint, not a published paid per-token tariff",
                _ => "no verified official maker token price",
            };
            return json!({"status":"unavailable", "currency":"USD", "reason":reason});
        }
    };
    json!({
        "status":"verified", "currency":"USD", "units_per_usd":1_000_000_000u64,
        "maker_model":maker_model, "input_nano_usd_per_million":input,
        "output_nano_usd_per_million":output, "basis":basis,
        "source_url":source, "checked_at":"2026-11-17"
    })
}
