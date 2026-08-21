//! Scryfall bulk-data download/cache helper.
//!
//! Moved here from DeepScry's `src/cli/src/main.rs` (`fetch_scryfall_bulk`
//! and `parse_scryfall_bulk_records`) so that DeepScry's own source no
//! longer contains an `api.scryfall.com` request or a Scryfall bulk-record
//! parser — the repository boundary stated in DeepScry's
//! `ai_docs/ARTPACK_CARDSKIN_DESIGN_20260817.md`: "DeepScry does not call
//! Scryfall, does not parse Scryfall dumps, and does not carry their
//! metadata."
//!
//! # What changed in the move, and what deliberately did not
//!
//! The logic is a faithful port. Every failure mode, every message, and the
//! on-disk contract are preserved, because a "move" that quietly changes
//! behaviour is the hardest kind of regression to attribute later. Three
//! things HAD to change, and only these three:
//!
//! 1. **The error type.** The original returned DeepScry's
//!    `deepscry_core::MtgError`. This crate has no dependency on DeepScry
//!    and must not acquire one — the dependency edge points this way, not
//!    back. [`BulkFetchError`] carries the same three cases the original
//!    used (`IoError`, a reqwest failure, and a catch-all message) and
//!    formats the same strings.
//! 2. **`tokio::fs` became `std::fs`.** The original mixed the two already
//!    (the gzip path used `std::fs::File::create`). Using `std::fs`
//!    throughout keeps `tokio` out of this crate's dependency list; the
//!    only async left is `reqwest`'s, and the caller supplies the runtime.
//!    These are one-shot offline build commands, not a server hot path.
//! 3. **`log::info!` narration was kept**, which adds `log` to this
//!    crate's `builder` feature. Dropping it would have been the cheaper
//!    port and the wrong one: it is the only progress narration a human
//!    running a multi-minute 556 MB download sees, and silently removing
//!    it trades a visible operation for an invisible one.
//!
//! # The one approved `api.scryfall.com` fetch
//!
//! [`ensure_cache`] performs the only sanctioned `api.scryfall.com`
//! request. It is an OFFLINE, on-demand build step — no scheduled trigger
//! invokes it, and nothing in a running game or web server reaches it.
//! Runtime image URLs are computed locally from an already-built table.

use std::path::{Path, PathBuf};
use std::time::Duration;

/// Failure modes of the bulk fetch/parse path.
///
/// Deliberately three cases rather than one string: an I/O failure, a
/// transport failure, and a protocol/shape failure are different problems
/// with different fixes, and collapsing them loses that at the call site.
#[derive(Debug)]
pub enum BulkFetchError {
    /// A local filesystem operation failed.
    Io(std::io::Error),
    /// The HTTP request itself failed (DNS, TLS, connect, body read).
    Http(reqwest::Error),
    /// The response arrived but was not the shape we require, the cache is
    /// unusable, or a record failed to deserialize. Carries a message that
    /// names what was expected and what was actually found.
    Protocol(String),
}

impl std::fmt::Display for BulkFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BulkFetchError::Io(e) => write!(f, "{e}"),
            BulkFetchError::Http(e) => write!(f, "{e}"),
            BulkFetchError::Protocol(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for BulkFetchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BulkFetchError::Io(e) => Some(e),
            BulkFetchError::Http(e) => Some(e),
            BulkFetchError::Protocol(_) => None,
        }
    }
}

impl From<std::io::Error> for BulkFetchError {
    fn from(e: std::io::Error) -> Self {
        BulkFetchError::Io(e)
    }
}

type Result<T> = std::result::Result<T, BulkFetchError>;

/// Provenance sidecar written next to a cached bulk dump.
///
/// Its presence is what lets a caller distinguish "this cache came from a
/// known Scryfall snapshot" from "this file appeared by other means" —
/// `build-card-catalog` and `build-card-legalities` both refuse a cache
/// with no provenance rather than stamping an unknown snapshot id into a
/// published artifact.
#[derive(serde::Serialize, serde::Deserialize)]
struct ScryfallBulkMeta {
    bulk_type: String,
    updated_at: String,
}

/// Path of the provenance sidecar for a given cache file.
///
/// Ported verbatim, including the `unwrap_or_default()` on `file_name()`:
/// a path with no final component (e.g. one ending in `..`) yields
/// `.meta.json` in the same directory rather than an error. That edge is
/// unreachable from the CLI, which always passes a real file path, and it
/// is preserved rather than "fixed" so this move changes no behaviour.
pub fn bulk_meta_path(bulk_cache: &Path) -> PathBuf {
    let mut name = bulk_cache.file_name().unwrap_or_default().to_os_string();
    name.push(".meta.json");
    bulk_cache.with_file_name(name)
}

/// Parse a Scryfall bulk-data file that [`ensure_cache`] has already
/// decompressed onto disk. Scryfall has shipped bulk dumps in two shapes
/// over time (DeepScry ds-bxy95o: they migrated `unique_artwork` from the
/// first to the second without warning):
///
/// 1. **JSON array** — the whole file is one `[ {...}, {...}, ... ]` value
///    (the historical `download_uri` format).
/// 2. **JSON Lines** — one JSON object per line, no enclosing array (the
///    `jsonl_download_uri` format now used for `unique_artwork`, and
///    possibly other bulk types in the future).
///
/// This is the SINGLE shared parse path for every bulk-data consumer so a
/// future format change (either direction) only needs a fix here.
/// Detection is by the first non-whitespace byte: `[` means array,
/// anything else is treated as JSON Lines. JSON Lines are parsed one line
/// at a time (a real streaming parse — we never require the whole file to
/// be one valid JSON document), which also means a single malformed line
/// fails loudly with its own line number rather than the whole file
/// silently losing records.
///
/// Generic over the record type so every consumer — the art index, the
/// catalog, the legality table — shares one parser rather than each
/// growing its own.
pub fn parse_bulk_records<T: serde::de::DeserializeOwned>(bulk_type: &str, data: &[u8]) -> Result<Vec<T>> {
    let first_non_ws = data.iter().find(|b| !b.is_ascii_whitespace()).copied();
    match first_non_ws {
        Some(b'[') => serde_json::from_slice::<Vec<T>>(data)
            .map_err(|e| BulkFetchError::Protocol(format!("parse {bulk_type} bulk JSON array: {e}"))),
        Some(_) => {
            // JSON Lines: one record per non-empty line.
            let text = std::str::from_utf8(data)
                .map_err(|e| BulkFetchError::Protocol(format!("parse {bulk_type} bulk JSON Lines: not UTF-8: {e}")))?;
            let mut records = Vec::new();
            for (idx, line) in text.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let record: T = serde_json::from_str(line).map_err(|e| {
                    BulkFetchError::Protocol(format!(
                        "parse {bulk_type} bulk JSON Lines: line {} malformed: {e}",
                        idx + 1
                    ))
                })?;
                records.push(record);
            }
            Ok(records)
        }
        None => Err(BulkFetchError::Protocol(format!(
            "parse {bulk_type} bulk data: file is empty"
        ))),
    }
}

/// Ensure a Scryfall bulk dump of `bulk_type` is cached at `bulk_cache`,
/// (re)fetching when forced, missing, or older than `max_cache_age`. The
/// cache is always stored DECOMPRESSED on disk (plain JSON array or plain
/// JSON Lines text — see [`parse_bulk_records`]), regardless of which wire
/// format Scryfall served, so every downstream reader has one on-disk
/// contract to depend on.
///
/// Returns the snapshot's `updated_at` when it is known: `Some(..)` after
/// a fetch, or from the provenance sidecar when reusing a cache. `None`
/// means a cache exists but its provenance is unknown — the caller decides
/// how loud to be about that, and both the catalog and legality builders
/// treat it as a hard error.
///
/// ── THE ONE APPROVED `api.scryfall.com` FETCH ──────────────────────────
/// This is the sole sanctioned `api.scryfall.com` request. It is an
/// offline, on-demand build step; the bulk-list endpoint exists only on
/// `api.scryfall.com`, and there is no stable direct URL to use instead.
/// Nothing at runtime reaches this code.
pub async fn ensure_cache(
    bulk_type: &str,
    bulk_cache: &Path,
    refresh: bool,
    max_cache_age: Option<Duration>,
) -> Result<Option<String>> {
    let neterr = |ctx: &str, e: reqwest::Error| {
        BulkFetchError::Protocol(format!("scryfall bulk fetch ({bulk_type}): {ctx}: {e}"))
    };
    let cache_stale = || -> bool {
        let Some(max_age) = max_cache_age else { return false };
        let Ok(meta) = std::fs::metadata(bulk_cache) else {
            return true;
        };
        let Ok(modified) = meta.modified() else { return true };
        modified.elapsed().map(|age| age > max_age).unwrap_or(true)
    };

    if refresh || !bulk_cache.exists() || cache_stale() {
        if let Some(parent) = bulk_cache.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let client = reqwest::Client::builder()
            .user_agent("deepscry/1.0 (https://deepscry.net; bulk-table builder)")
            .build()
            .map_err(|e| neterr("client build", e))?;
        log::info!("Fetching Scryfall bulk-data metadata…");
        let meta_bytes = client
            .get("https://api.scryfall.com/bulk-data")
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| neterr("bulk-data meta GET", e))?
            .bytes()
            .await
            .map_err(|e| neterr("bulk-data meta body", e))?;
        let meta: serde_json::Value = serde_json::from_slice(&meta_bytes)
            .map_err(|e| BulkFetchError::Protocol(format!("scryfall bulk fetch ({bulk_type}): meta JSON: {e}")))?;
        let entry = meta["data"]
            .as_array()
            .and_then(|a| a.iter().find(|x| x["type"] == bulk_type))
            .ok_or_else(|| {
                BulkFetchError::Protocol(format!("scryfall bulk fetch: no {bulk_type} entry in bulk-data"))
            })?;
        // Prefer the new gzipped-JSON-Lines field; tolerate the old
        // plain-JSON-array field if Scryfall ever restores it. Fail loudly,
        // naming exactly what we looked for and what keys the entry
        // actually has, if neither is present.
        let (uri, is_jsonl_gz) = if let Some(u) = entry["jsonl_download_uri"].as_str() {
            (u, true)
        } else if let Some(u) = entry["download_uri"].as_str() {
            (u, false)
        } else {
            let known_keys: Vec<&str> = entry
                .as_object()
                .map(|o| o.keys().map(String::as_str).collect())
                .unwrap_or_default();
            return Err(BulkFetchError::Protocol(format!(
                "scryfall bulk fetch: {bulk_type} has neither jsonl_download_uri nor download_uri \
                 (expected one of those two keys with a URL; entry keys present: {known_keys:?}) — \
                 Scryfall's bulk-data API has changed shape again; this needs a code fix, not a stale-cache workaround"
            )));
        };
        let updated_at = entry["updated_at"].as_str().unwrap_or("?").to_string();
        log::info!("Downloading {uri} (updated_at={updated_at}, jsonl_gz={is_jsonl_gz})…");
        let accept = if is_jsonl_gz {
            "application/octet-stream"
        } else {
            "application/json"
        };
        let bytes = client
            .get(uri)
            .header("Accept", accept)
            .send()
            .await
            .map_err(|e| neterr("bulk download GET", e))?
            .bytes()
            .await
            .map_err(|e| neterr("bulk download body", e))?;
        if is_jsonl_gz {
            // Stream-decompress the gzipped JSON-Lines payload straight to
            // the cache file (never materialize a second full decompressed
            // copy in memory beyond flate2's internal buffer) so the cache
            // always holds plain, already-decompressed JSON Lines text —
            // the same on-disk contract as the old plain-JSON-array format.
            let mut decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(bytes.as_ref()));
            let mut out = std::fs::File::create(bulk_cache)?;
            std::io::copy(&mut decoder, &mut out).map_err(|e| {
                BulkFetchError::Protocol(format!(
                    "scryfall bulk fetch ({bulk_type}): gunzip of jsonl_download_uri payload failed: {e}"
                ))
            })?;
        } else {
            std::fs::write(bulk_cache, &bytes)?;
        }
        let sidecar = ScryfallBulkMeta {
            bulk_type: bulk_type.to_string(),
            updated_at: updated_at.clone(),
        };
        std::fs::write(
            bulk_meta_path(bulk_cache),
            serde_json::to_string_pretty(&sidecar).expect("sidecar serializes"),
        )?;
        let cached_size = std::fs::metadata(bulk_cache).map(|m| m.len())?;
        if cached_size == 0 {
            // A prior format-drift once produced an empty card-lookup file
            // and images silently vanished site-wide — never let an empty
            // cache pass as success.
            return Err(BulkFetchError::Protocol(format!(
                "scryfall bulk fetch ({bulk_type}): downloaded {} bytes over the wire but the decoded cache at {} \
                 is EMPTY (0 bytes) — refusing to treat this as success",
                bytes.len(),
                bulk_cache.display()
            )));
        }
        log::info!(
            "Cached {:.1} MB ({} on the wire) to {}",
            cached_size as f64 / 1e6,
            if is_jsonl_gz {
                format!("{:.1} MB gzip", bytes.len() as f64 / 1e6)
            } else {
                format!("{:.1} MB", bytes.len() as f64 / 1e6)
            },
            bulk_cache.display()
        );
        return Ok(Some(updated_at));
    }

    log::info!(
        "Using cached bulk dump {} (pass --refresh to re-download)",
        bulk_cache.display()
    );
    // Recover provenance from the sidecar when present; a cache produced by
    // other means has unknown provenance (caller decides how loud to be).
    match std::fs::read(bulk_meta_path(bulk_cache)) {
        Ok(bytes) => {
            let sidecar: ScryfallBulkMeta = serde_json::from_slice(&bytes)
                .map_err(|e| BulkFetchError::Protocol(format!("scryfall bulk cache sidecar unparseable: {e}")))?;
            Ok(Some(sidecar.updated_at))
        }
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Scryfall migrated bulk dumps from a single JSON-array `download_uri`
    // to a gzipped JSON-Lines `jsonl_download_uri` (the `unique_artwork`
    // bulk type stopped offering `download_uri` at all).
    // `parse_bulk_records` is the shared parse path every bulk consumer
    // uses; these tests pin both on-disk shapes plus the loud failure
    // modes, independent of any network access.
    //
    // Fixture names are synthetic, per this repository's rule that no real
    // card titles land here in any form — including test data.
    #[derive(serde::Deserialize, Debug, PartialEq)]
    struct TestRec {
        name: String,
    }

    #[test]
    fn parses_json_array_old_format() {
        let data = br#"[{"name":"Fixture Qzx One"},{"name":"Fixture Qzx Two"}]"#;
        let records: Vec<TestRec> = parse_bulk_records("unique_artwork", data).expect("parses");
        assert_eq!(
            records,
            vec![
                TestRec {
                    name: "Fixture Qzx One".to_string()
                },
                TestRec {
                    name: "Fixture Qzx Two".to_string()
                },
            ]
        );
    }

    #[test]
    fn parses_json_lines_new_format() {
        let data = b"{\"name\":\"Fixture Qzx One\"}\n{\"name\":\"Fixture Qzx Two\"}\n";
        let records: Vec<TestRec> = parse_bulk_records("unique_artwork", data).expect("parses");
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].name, "Fixture Qzx Two");
    }

    #[test]
    fn json_lines_skips_blank_lines_without_losing_records() {
        let data = b"\n{\"name\":\"Fixture Qzx One\"}\n\n  \n{\"name\":\"Fixture Qzx Two\"}\n\n";
        let records: Vec<TestRec> = parse_bulk_records("unique_artwork", data).expect("parses");
        assert_eq!(records.len(), 2, "blank lines must be skipped, not counted or fatal");
    }

    #[test]
    fn empty_file_is_a_loud_error_not_an_empty_vec() {
        // The failure this guards: an empty cache once passed as success
        // and images vanished site-wide. Zero records must never be a
        // silent success.
        let err =
            parse_bulk_records::<TestRec>("unique_artwork", b"   \n  ").expect_err("an empty file must be an error");
        assert!(
            err.to_string().contains("file is empty"),
            "message should name the actual problem, got: {err}"
        );
    }

    #[test]
    fn malformed_json_line_names_its_line_number() {
        // Line 2 is malformed. The error must say so — a whole-file
        // failure would send someone hunting through 556 MB.
        let data = b"{\"name\":\"Fixture Qzx One\"}\n{\"name\":\n{\"name\":\"Fixture Qzx Three\"}\n";
        let err = parse_bulk_records::<TestRec>("default_cards", data).expect_err("malformed line must fail");
        let msg = err.to_string();
        assert!(msg.contains("line 2"), "error should name line 2, got: {msg}");
        assert!(
            msg.contains("default_cards"),
            "error should name the bulk type, got: {msg}"
        );
    }

    #[test]
    fn meta_path_is_the_cache_name_plus_suffix() {
        assert_eq!(
            bulk_meta_path(Path::new("target/scryfall/unique_artwork.json")),
            PathBuf::from("target/scryfall/unique_artwork.json.meta.json")
        );
    }
}
