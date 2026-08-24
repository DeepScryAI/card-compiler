# card-compiler

Index-compiling machinery over open Forge card scripts and open Scryfall
data. This repository contains **no Wizards of the Coast card data and no
other third-party intellectual property** — no card titles, no rules text,
no images.

That claim is the reason this repository exists, and it is a constraint,
not a description. Anyone contributing here must keep it true:

- **No card titles or rules text land in this repo, ever, in any form** —
  not as test fixtures, not as example data, not in a comment, not as a
  cached download artifact committed by mistake. Test fixtures use
  synthetic names (`"Fixture Qzx One"`, not a real card name).
- **This repo does not hold card data.** The durable, version-controlled
  record of stripped-down (title-free, oracle-text-free) Forge card
  scripts lives in the sibling repository
  [`card-scripts-mirror`](https://github.com/DeepScryAI/card-scripts-mirror)
  — a data-only repository with no build machinery of its own. This
  repository is the reverse: code only, no data.
- **Anything that touches Scryfall's data, or DeepScry's art-pack
  handling, belongs here** — not in the DeepScry engine repository, and
  not (currently) in `card-scripts-mirror` either, though the mirror
  still holds some of that code as of this writing; migrating it here is
  a planned, sequenced, NOT-YET-STARTED second phase (see
  `ai_docs/transient/SCRYFALL_CRATE_PLAN_20260819.md` in the DeepScry
  repository, section 6).

## What's here

The `cardskin` crate:

- **`wire`** — the SCDT binary format: the compact card-lookup table
  DeepScry ships as a content-addressed asset, mapping a card's lookup key
  to `(Scryfall UUID, image version, double-faced flag)` so a client can
  reconstruct an immutable Scryfall CDN image URL without shipping the URL
  itself. Zero dependencies beyond `std`; compiles to `wasm32` unmodified,
  because the DECODER runs in a browser at runtime. The encoder and
  decoder are kept in this one file deliberately — see the module's own
  doc comment for why splitting them across files or repos is the one
  thing this crate must never do.
- **`builder`** (behind the `builder` feature) — the build-time generator
  that turns raw Scryfall `unique_artwork` bulk-data records into the
  entries `wire::encode_card_lookup` serializes. Needs `serde` to
  deserialize Scryfall's JSON record shape.
- **`bulk_fetch`** (behind `builder`) — the Scryfall bulk-data
  download/cache helper, moved here from DeepScry's CLI so that DeepScry's
  own source no longer contains an `api.scryfall.com` request or a
  Scryfall bulk-record parser. Its `ensure_cache` is the ONE sanctioned
  `api.scryfall.com` fetch: an offline, on-demand build step, never a
  runtime call. See the module's own doc comment for the move provenance
  and the three deliberate deviations from the original.

Both `wire.rs` and `builder.rs` were moved from DeepScry's
`src/engine/src/scryfall.rs` and `src/engine/src/scryfall_table.rs`
verbatim (module-path renames only — no logic changes), including their
existing test suites (9 + 8 = 17 tests at move time). Confirmed by direct diff
against the DeepScry source at move time: identical apart from the
`crate::scryfall::` -> `crate::wire::` path rename.

DeepScry consumes this crate: it pins this repository as its
`card-compiler` submodule and takes `cardskin` as an ordinary Cargo path
dependency from its engine, wasm web-client, and CLI crates, and its
original `scryfall.rs`/`scryfall_table.rs` are deleted (the ds-1zoywb
move in the DeepScry repository).

## What's NOT here yet

- **Distribution.** No tarballs, no release artifacts, no packaging. The
  parent DeepScry checkout keeps its `cardsfolder` symlink and its web
  build keeps reading scripts directly; this crate is consumed as an
  ordinary Cargo path dependency, nothing more, for now.
- **The mirror's own Scryfall-touching build scripts**
  (`generate_uuid_trie.rs`, `scan_scryfall_ip.rs`,
  `scripts/lib/scryfall_bulk.rs`), currently still in
  `card-scripts-mirror`. Planned, sequenced, not started — see the plan
  document's section 6.

## Building and testing

```sh
cargo test                  # wire.rs only — 9 tests, zero external deps
cargo test --features builder   # + builder.rs and bulk_fetch.rs — 23 tests total
cargo build --target wasm32-unknown-unknown   # wire.rs alone, browser target
```

## License

Not yet set. DeepScry's own repository is proprietary; `card-scripts-mirror`
is GPLv3 (inherited from Forge). This repository's license is an open
question for the project owner — do not assume one.

## Single-threaded development policy

Owner ruling, 2026-08-22: this repository is used only by the DeepScry
workstream and is developed **single-threaded, landing to `main` with no
side tracks**.

- Commit directly to `main`, in small commits; history stays linear (plain
  fast-forward only, never force-push).
- Do **not** create side branches or long-lived PR branches. Work that is
  not ready to land on `main` stays local.
- Every commit that an external repository pins (a DeepScry submodule
  gitlink) is anchored by an annotated tag under `pin/` so the pinned
  commit stays fetchable regardless of how `main` moves.

## IP scanning lives here

This repository owns the intellectual-property scanning tooling and the
reviewed allowlist that goes with it:

* `scripts/scan_scryfall_ip.rs` — the scanner.
* `ip_allowlist.tsv` — the reviewed allowlist of titles that must NOT count as
  hits, each with a plain-language reason.

They live here, and not in `cardsfolder-mirror`, because the mirror is moving
toward being purely a data repository: an up-to-date but anonymized copy of the
Forge card scripts, kept as the record of the extraction. Tooling belongs with
the compiler that consumes that data, not inside the data itself.

### Why the allowlist is not optional

A card title can be an ordinary English word. Scanning this repository without
the allowlist reports 23 hits. Twenty-two are false positives:

| matched | where it actually appears |
| --- | --- |
| `Clone` | `#[derive(Debug, Clone, ...)]` |
| `Index` | "Index-compiling machinery" |
| `Rust` | "one implementation, no Rust/JS drift" |
| `Mask` | "Mask isolating the version timestamp" |
| `Extract`, `Recover`, `Deliberate` | ordinary verbs in doc comments |
| `Wizards` | the sentence above declaring no such data is present |
| `Oracle` | "Oracle text", the standard term for a card's rules text |

That last row is the one to remember: **an unallowlisted scan flags the
disclaimer that says there is no Wizards of the Coast data.** A raw hit count
is not a measurement until the allowlist is applied.

The twenty-third was genuine: a real card title used as a test fixture name in
`scripts/scan_scryfall_ip.rs`. It has been replaced with a synthetic name. With
the allowlist applied and that fixture fixed, this repository scans to **zero**,
while the same allowlist still reports 5,551 occurrences elsewhere -- so the
zero is a measurement, not a blinded scanner.
