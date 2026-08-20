//! `cardskin` — index-compiling machinery for DeepScry's card-skin art
//! index, split out of DeepScry itself per the owner's directive that all
//! art-pack handling and all Scryfall-touching code live in this factory
//! repo, separate from `card-scripts-mirror` (which stays a durable,
//! data-only version history with no build machinery of its own).
//!
//! Moved from DeepScry's `src/engine/src/scryfall.rs` (-> [`wire`]) and
//! `src/engine/src/scryfall_table.rs` (-> [`builder`]), verbatim aside
//! from the module-path rename `crate::scryfall::` -> `crate::wire::`. See
//! `ai_docs/transient/SCRYFALL_CRATE_PLAN_20260819.md` in the DeepScry
//! repo for the plan this crate implements, including which DeepScry call
//! sites still need updating (that DeepScry-side move is a separate,
//! later pass — this crate does not yet have any DeepScry consumer).
//!
//! # Two halves, two audiences
//!
//! [`wire`] is the SCDT binary format: the encoder and decoder for the
//! compact card-lookup table DeepScry ships as a CAS asset. It has ZERO
//! dependencies beyond `std` and compiles to `wasm32` unmodified, because
//! the decoder runs in the browser at runtime — the encoder and decoder
//! must never be split across crates or repos, or the format's two halves
//! can silently drift out of byte-sync with each other.
//!
//! [`builder`] (behind the `builder` feature) is the build-time generator
//! that turns raw Scryfall `unique_artwork` records into the entries
//! [`wire::encode_card_lookup`] serializes. It needs `serde` to
//! deserialize Scryfall's JSON record shape — a real but small cost kept
//! OFF by default so a wire-only consumer (e.g. the wasm client, which
//! only ever decodes an already-built table) pulls nothing extra.
//!
//! `bulk_fetch` (also behind `builder`) is reserved for the Scryfall
//! bulk-data download/cache helper — NOT YET IMPLEMENTED in this crate.
//! See `bulk_fetch.rs`'s own doc comment for why it's an empty module
//! rather than a stub with fake logic in it.

pub mod wire;

#[cfg(feature = "builder")]
pub mod builder;

#[cfg(feature = "builder")]
pub mod bulk_fetch;

// Re-exported at the crate root so a consumer writes `cardskin::CdnSize`
// rather than `cardskin::wire::CdnSize` — matches the call-site shapes in
// the DeepScry-side plan (`ai_docs/transient/SCRYFALL_CRATE_PLAN_
// 20260819.md` section 3). `bulk_fetch` stays namespaced (not
// re-exported), also matching that plan.
#[cfg(feature = "builder")]
pub use builder::*;
pub use wire::*;
