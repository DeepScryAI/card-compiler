//! Shared CAS conventions for card-compiler producer scripts — the SS0 layer
//! of the ratified card-skin format package.
//!
//! NORMATIVE SPEC: `docs/CARD_SKIN_FORMATS.md` in the DeepScry repository
//! (the written form of the ds-5432 ratification). The reference Rust
//! implementation lives in DeepScry core (`src/core/src/cas/`); this file is
//! the producer-script twin, pinned to the SAME known-answer vectors so the
//! two cannot drift silently. Per the OD-3 ruling (card-compiler is the
//! factory), this is the compiler-side implementation. The mirror-side copy
//! remains temporarily for fixed-fixture parity; it must not drift silently.
//!
//! Contents:
//! * RFC 8785 (JCS) canonical JSON for the integer-only subset we emit.
//! * Pinned-profile CIDs: CIDv1 / sha2-256 / `raw` / single block / base32.
//! * Deterministic POSIX ustar writer (strict; no pax, no GNU extensions).
//! * Content references: `{cid, size, hints[]}`, hints in-hash.
//!
//! Host scripts must declare `sha2` and `serde_json` in their embedded
//! manifests and include this file with `#[path = "lib/cas.rs"] mod cas;`.


// Shared by several host scripts, each of which uses a different subset;
// per-host dead-code warnings are noise, matching lib/scryfall_bulk.rs.
#![allow(dead_code)]
use anyhow::{bail, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Largest integer magnitude exactly representable as an IEEE 754 double;
/// RFC 8785 forbids us anything bigger (see the DeepScry-side module docs).
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// CIDv1 header for `raw` codec + sha2-256 multihash of length 32.
const CIDV1_RAW_SHA256_HEADER: [u8; 4] = [0x01, 0x55, 0x12, 0x20];

/// Lowercase hex sha2-256 (the TSV envelope's `body_sha256` and the digest
/// inside [`cid_for_bytes`]).
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The pinned-profile CID string (`bafkrei…`) for `bytes`.
pub fn cid_for_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut cid_bytes = Vec::with_capacity(36);
    cid_bytes.extend_from_slice(&CIDV1_RAW_SHA256_HEADER);
    cid_bytes.extend_from_slice(&digest);
    let mut out = String::with_capacity(60);
    out.push('b');
    base32_lower_nopad(&cid_bytes, &mut out);
    out
}

/// RFC 4648 base32, lowercase alphabet, no padding.
fn base32_lower_nopad(bytes: &[u8], out: &mut String) {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
}

/// Serialize `value` to RFC 8785 canonical JSON bytes (integer subset:
/// floats and integers beyond ±(2^53 − 1) are errors, never rounded).
pub fn jcs_canonicalize(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    jcs_write(value, &mut out)?;
    Ok(out)
}

fn jcs_write(value: &Value, out: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => {
            if let Some(signed) = number.as_i64() {
                if signed.unsigned_abs() > MAX_SAFE_INTEGER {
                    bail!("JCS subset violation: integer {number} outside ±(2^53 − 1)");
                }
                out.extend_from_slice(signed.to_string().as_bytes());
            } else if let Some(unsigned) = number.as_u64() {
                if unsigned > MAX_SAFE_INTEGER {
                    bail!("JCS subset violation: integer {number} outside ±(2^53 − 1)");
                }
                out.extend_from_slice(unsigned.to_string().as_bytes());
            } else {
                bail!("JCS subset violation: non-integer JSON number {number}");
            }
        }
        Value::String(text) => jcs_write_string(text, out),
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                jcs_write(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            // RFC 8785 §3.2.3: property names sorted by UTF-16 code units.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by_key(|key| key.encode_utf16().collect::<Vec<u16>>());
            out.push(b'{');
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                jcs_write_string(key, out);
                out.push(b':');
                jcs_write(&map[key.as_str()], out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// RFC 8785 §3.2.2.2 minimal string escaping.
fn jcs_write_string(text: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for character in text.chars() {
        match character {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\r' => out.extend_from_slice(b"\\r"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// Build the `{cid, size, hints[]}` content-reference JSON value for `bytes`.
/// All three keys are always present; hints participate in the containing
/// object's hash (pure content addressing — updating hints mints a new
/// object).
pub fn content_ref(bytes: &[u8], hints: &[String]) -> Value {
    serde_json::json!({
        "cid": cid_for_bytes(bytes),
        "size": bytes.len() as u64,
        "hints": hints,
    })
}

/// Deterministic strict-ustar archive from `(path, bytes)` entries.
///
/// The pinned parameters (normative table in docs/CARD_SKIN_FORMATS.md
/// § SS0.4): POSIX ustar with NO pax or GNU extensions ever (a path over
/// 100 bytes or a member ≥ 8 GiB is an error); regular files only, no
/// directory entries; entries sorted by raw path bytes with duplicates
/// rejected; mode 0644, uid/gid 0, mtime 0, empty uname/gname, all-zero
/// device fields, empty prefix; trailer of exactly two 512-byte zero
/// blocks; no compression at the addressing layer.
pub fn deterministic_tar(mut entries: Vec<(String, Vec<u8>)>) -> Result<Vec<u8>> {
    for (path, bytes) in &entries {
        validate_tar_path(path)?;
        if bytes.len() as u64 > 0o77777777777 {
            bail!("tar entry {path:?} is {} bytes, over the ustar 8 GiB limit", bytes.len());
        }
    }
    entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    for pair in entries.windows(2) {
        if pair[0].0 == pair[1].0 {
            bail!("duplicate tar entry path {:?}", pair[0].0);
        }
    }
    let mut out = Vec::with_capacity(
        entries.iter().map(|(_, b)| 512 + b.len().div_ceil(512) * 512).sum::<usize>() + 1024,
    );
    for (path, bytes) in &entries {
        let mut header = [0u8; 512];
        header[..path.len()].copy_from_slice(path.as_bytes());
        header[100..108].copy_from_slice(b"0000644\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        header[124..136].copy_from_slice(format!("{:011o}\0", bytes.len()).as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[148..156].copy_from_slice(b"        ");
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum: u32 = header.iter().map(|&b| u32::from(b)).sum();
        header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
        out.extend_from_slice(&header);
        out.extend_from_slice(bytes);
        out.resize(out.len().div_ceil(512) * 512, 0);
    }
    out.resize(out.len() + 1024, 0);
    Ok(out)
}

fn validate_tar_path(path: &str) -> Result<()> {
    if path.is_empty() {
        bail!("tar entry path is empty");
    }
    if path.starts_with('/') {
        bail!("tar entry path {path:?} is absolute");
    }
    if !path.bytes().all(|b| (0x21..=0x7e).contains(&b) && b != b'\\') {
        bail!("tar entry path {path:?} must be ASCII graphic characters without backslash or whitespace");
    }
    if path.split('/').any(|part| part.is_empty() || part == "." || part == "..") {
        bail!("tar entry path {path:?} contains an empty, `.`, or `..` component");
    }
    if path.len() > 100 {
        bail!("tar entry path {path:?} exceeds 100 bytes (ustar limit; pax is deliberately unsupported)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same known-answer vectors as DeepScry core's `src/core/src/cas/`
    /// tests (derivation: docs/CARD_SKIN_FORMATS.md § "Known-answer test
    /// provenance" — Python `multiformats` + `jcs` reference packages, GNU
    /// tar 1.35 cross-check). If these two test suites ever disagree, one
    /// side has drifted from the ratified format.
    #[test]
    fn known_answer_cids() {
        assert_eq!(cid_for_bytes(b""), "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku");
        assert_eq!(
            cid_for_bytes(b"hello world\n"),
            "bafkreifjjcie6lypi6ny7amxnfftagclbuxndqonfipmb64f2km2devei4"
        );
        assert_eq!(
            sha256_hex(b"hello world\n"),
            "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447"
        );
    }

    #[test]
    fn known_answer_jcs_object() {
        let value = serde_json::json!({
            "version": 1,
            "format": "deepscry-card-skin",
            "titles": {
                "cid": "bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy",
                "size": 4,
                "hints": [],
            },
            "cardset": {
                "cid": "bafkreif7ju7wj4c6f3sqx5qz3dchflvbfbzgcdgeicot6dyftk37gjukpm",
                "size": 3,
                "hints": ["https://example.invalid/x"],
            },
        });
        let bytes = jcs_canonicalize(&value).expect("canonicalizes");
        assert_eq!(
            cid_for_bytes(&bytes),
            "bafkreievauwpncr7ph26oudqljzyqvo47rdx5uydsiaasqpgcrbrxwuzqi"
        );
        assert!(jcs_canonicalize(&serde_json::json!({"x": 1.5})).is_err());
    }

    #[test]
    fn known_answer_utf16_key_order() {
        let value = serde_json::json!({
            "\u{20ac}": "Euro Sign",
            "\r": "Carriage Return",
            "1": "One",
            "\u{80}": "Control",
            "\u{f6}": "Latin Small Letter O With Diaeresis",
            "\u{fb33}": "Hebrew Letter Dalet With Dagesh",
            "\u{1f600}": "Emoji: Grinning Face",
        });
        assert_eq!(
            cid_for_bytes(&jcs_canonicalize(&value).expect("canonicalizes")),
            "bafkreic6gikvnuradcuwk2mrvhuu657mc5p2de7ffisctuys7baz5sfqrq"
        );
    }

    #[test]
    fn known_answer_golden_tar() {
        let bytes = deterministic_tar(vec![
            ("manifest.json".to_owned(), b"{}".to_vec()),
            ("cards/00/00/00/00000001.txt".to_owned(), b"Id:1\n".to_vec()),
        ])
        .expect("valid archive");
        assert_eq!(bytes.len(), 3072);
        assert_eq!(
            sha256_hex(&bytes),
            "3c44200060029f4abed1e539f1f93babc06a9e3782e725b3771a74e3eda70467"
        );
        assert_eq!(
            cid_for_bytes(&bytes),
            "bafkreib4iqqaayact5fl5upfhhy7so5lybvj4n4c44s3g5y2otr63jyem4"
        );
        assert!(deterministic_tar(vec![
            ("a".to_owned(), vec![]),
            ("a".to_owned(), vec![]),
        ])
        .is_err());
        assert!(deterministic_tar(vec![("x".repeat(101), vec![])]).is_err());
    }

    #[test]
    fn content_ref_shape() {
        let value = content_ref(b"", &[]);
        let bytes = jcs_canonicalize(&value).expect("canonicalizes");
        assert_eq!(
            String::from_utf8(bytes).expect("utf8"),
            "{\"cid\":\"bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku\",\"hints\":[],\"size\":0}"
        );
    }
}
