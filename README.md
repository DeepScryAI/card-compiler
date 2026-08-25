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
- **The mirror's remaining Scryfall-touching producer scripts.** The IP
  scanner and its shared Scryfall bulk-data helper are here now; moving the
  other producers, including `generate_uuid_trie.rs`, remains planned and
  sequenced. See the plan document's section 6.

## Building and testing

```sh
cargo test                  # wire.rs only — 9 tests, zero external deps
cargo test --features builder   # + builder.rs and bulk_fetch.rs — 23 tests total
cargo build --target wasm32-unknown-unknown   # wire.rs alone, browser target
```

## License

This repository is licensed under the BSD 3-Clause License; see `LICENSE`.

The IP scanner, `scripts/lib/scryfall_bulk.rs`, and `ip_allowlist.tsv` first
appeared in the root commit of DeepScryAI's CardScriptsMirror numeric-pipeline
history and were authored by DeepScryAI contributors. Card-compiler adopted
those files from that repository; they were not derived from Forge source
code. CardScriptsMirror is GPL-3.0 because it carries stripped Forge-derived
card data, but that data provenance does not attach to these independently
authored tools. Their copyright holder releases them here under BSD-3-Clause.

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

* `scripts/scan_scryfall_ip.rs` — the one scanner for card-compiler,
  DeepScry, and CardScriptsMirror.
* `ip_allowlist.tsv` — the canonical reviewed allowlist of titles that must
  NOT count as hits because they are ordinary English words or phrases. Each
  entry has a plain-language reason.

They live here, and not in `cardsfolder-mirror`, because the mirror is moving
toward being purely a data repository: an up-to-date but anonymized copy of the
Forge card scripts, kept as the record of the extraction. Tooling belongs with
the compiler that consumes that data, not inside the data itself.

The scanner takes an explicit target and root so every report states which of
the three repositories it measured. A typical invocation is:

```sh
rust-script scripts/scan_scryfall_ip.rs \
  --target card-compiler --root . \
  --cache .cache/scryfall/default_cards.json \
  --report .cache/reports/card-compiler-ip-scan.json
```

For DeepScry only, pass its checked-in local-exception file with
`--local-exceptions`. That file is for a confirmed false positive unique to
DeepScry; it cannot redefine whether a title is ordinary English. An entry
duplicated in the global allowlist is a loud error. Card-compiler and
CardScriptsMirror intentionally have no local exception input.

### Why the allowlist is not optional

A card title can be an ordinary English word. An unallowlisted scan can flag
ordinary source language, including terms such as these:

| matched | where it actually appears |
| --- | --- |
| `Clone` | `#[derive(Debug, Clone, ...)]` |
| `Index` | "Index-compiling machinery" |
| `Rust` | "one implementation, no Rust/JS drift" |
| `Mask` | "Mask isolating the version timestamp" |
| `Extract`, `Recover`, `Deliberate` | ordinary verbs in doc comments |
| `Wizards` | the sentence above declaring no such data is present |
| `Oracle` | "Oracle text", the standard term for a card's rules text |

That last row is the one to remember: **an unallowlisted scan can flag the
disclaimer that says there is no Wizards of the Coast data.** A raw hit count
is not a measurement until the allowlist is applied. Single-word titles are
included deliberately and reviewed through that allowlist; silently discarding
them would make the headline count depend on which scanner happened to run.
The old README recorded a 23-hit figure without a runnable scanner in this
repository and without the input snapshot and exact command needed to reproduce
it, so that figure has been removed. Publish future counts only with the exact
command, Scryfall cache identity, scanned Git revision, target, and resulting
report.

The scanner's focused tests, including the shared bulk-data parser, run with:

```sh
rust-script --test scripts/scan_scryfall_ip.rs
```

## Continuous integration

Every push to `main` runs formatting, the dependency-free WebAssembly wire
build, builder tests, strict Clippy, and the scanner's focused tests. The
scanner and compiler are therefore checked before CardScriptsMirror's nightly
job is permitted to consume the moving `main` revision.

## Mirror production migration

CardScriptsMirror remains the committed anonymous data repository. Its
production programs are moving here additively, one focused, parity-tested
piece at a time; no producer or presentation artifact is removed from the
mirror until a fixed fixture proves byte-identical output. The initial ports
are `scripts/mirror/extract_catalog_ids.rs`, `pack_cardset.rs`,
`make_artpack.rs`, `make_skin_manifest.rs`, and `make_provenance.rs`, sharing
the deterministic CAS helper. `make_wotc_test_skin.rs` is also ported; it
creates only a local, visibly prefixed human-test skin. They write
generated output only to explicitly selected local paths; they do not add card
data, Scryfall downloads, skins, or cardsets to this repository.

`extract_catalog_ids.rs` deliberately accepts a caller-supplied, title-bearing
catalog and emits only one-way digests. The current anonymized DeepScry catalog
is not that input and must fail loudly rather than manufacture a different
identity table. Parity is established against the immutable historical catalog
revision that produced the mirror's checked-in tables; the compiler stores
neither that source catalog nor its generated output.
