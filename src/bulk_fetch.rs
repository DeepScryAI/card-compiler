//! Reserved for the Scryfall bulk-data download/cache helper.
//!
//! NOT YET IMPLEMENTED. This module is deliberately empty rather than
//! containing a stub function that returns success without doing
//! anything — a stub that "compiles and passes" while doing nothing is
//! exactly the vacuity trap DeepScry's own conventions warn against (see
//! `ai_docs/transient/SCRYFALL_CRATE_PLAN_20260819.md`'s and the wider
//! project's "Mutation Testing" section: a check that cannot fail is
//! worse than no check).
//!
//! When implemented, per the plan this crate follows, it should:
//! - be based on `card-scripts-mirror`'s existing `scripts/lib/
//!   scryfall_bulk.rs::ensure_cache` (the mirror's own established
//!   pattern for downloading and caching Scryfall's `default_cards` bulk
//!   snapshot), NOT a fresh reimplementation;
//! - fold in whatever DeepScry's own `src/cli/src/main.rs::
//!   fetch_scryfall_bulk`/`parse_scryfall_bulk_records` do that the
//!   mirror's version doesn't yet (JSONL streaming with per-line error
//!   context, an empty-file hard error, a cache-sidecar metadata check) —
//!   diff the two implementations rather than keeping both;
//! - expose `pub fn ensure_cache(...)` and a generic `pub fn
//!   parse_bulk_records<T: serde::de::DeserializeOwned>(...)` so
//!   `builder::ScryfallRecord` and any future title/body-index record
//!   shape can both use it;
//! - need `reqwest`, `flate2`, and `serde_json` as additional optional
//!   dependencies under the `builder` feature (not yet declared in this
//!   crate's `Cargo.toml` — add them when this module gets real content,
//!   not before, so `Cargo.toml` never claims a dependency nothing here
//!   uses).
