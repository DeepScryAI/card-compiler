#!/usr/bin/env rust-script
//! ```cargo
//! [package]
//! edition = "2021"
//!
//! [dependencies]
//! anyhow = "1.0.99"
//! clap = { version = "4.5.45", features = ["derive"] }
//! flate2 = "1.1.2"
//! reqwest = { version = "0.12.28", default-features = false, features = ["blocking", "json", "rustls-tls"] }
//! serde = { version = "1.0.219", features = ["derive"] }
//! serde_json = "1.0.143"
//! sha2 = "0.10.9"
//! uuid = { version = "1.18.0", features = ["serde"] }
//! ```
//!
//! Emit the dense presentation title catalog from the numeric identity bridge
//! and this repository's own Scryfall snapshot.
//!
//! Titles come from Scryfall and from nowhere else. The numeric catalog
//! supplies only `#id` and `oracle_id`; every other catalog column, including
//! any residual `name`, is ignored by construction. That is the property that
//! makes this generator survive DeepScry's title purge instead of quietly
//! depending on the corpus the purge removes.
//!
//! The emitted table carries the `catalog_identity` stamp that DeepScry's
//! strict title-skin loader requires: the SHA-256 of the exact catalog file
//! that assigned these numeric IDs. Without it a stale-but-checksum-valid
//! table would silently name the wrong cards after a catalog regeneration.

use anyhow::{bail, Context, Result};
use clap::Parser;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[path = "../lib/scryfall_bulk.rs"]
mod scryfall_bulk;
#[path = "lib/token_genesis.rs"]
mod token_genesis;

/// The header schema DeepScry's `scripts/extract_catalog_title_skin.py` and
/// `bin/namecards` accept. Changing any token here breaks strict consumers.
const SKIN_KIND: &str = "title-only-skin";
const SKIN_VERSION: &str = "1";

#[derive(Parser, Debug)]
#[command(about = "Emit the dense, catalog-stamped presentation title catalog")]
struct Args {
    /// Numeric identity bridge with `#id` and `oracle_id` columns and a
    /// `metadata:` header field. DeepScry's identity-assigning
    /// `src/engine/assets/card_catalog.tsv` satisfies this contract; this
    /// repository's `catalog_ids.tsv` (the default path) currently does NOT
    /// — it carries no `metadata:` field — so regenerating the committed
    /// table requires `--catalog <DeepScry>/src/engine/assets/card_catalog.tsv`.
    #[arg(long, default_value = "catalog_ids.tsv")]
    catalog: PathBuf,

    /// Decompressed Scryfall default_cards cache.
    #[arg(long, default_value = ".cache/scryfall/default_cards.json")]
    cache: PathBuf,

    /// Generated title catalog. This is generated presentation output, not a
    /// hand-maintained source artifact.
    #[arg(long, default_value = ".cache/presentation/title_catalog.tsv")]
    output: PathBuf,

    /// Ignore a present cache and download the current snapshot.
    #[arg(long)]
    refresh: bool,

    /// Override the catalog identity stamp. Use only when the bridge in
    /// `--catalog` is a derived file and the identity of the originating
    /// catalog generation must be carried across that derivation.
    #[arg(long)]
    catalog_identity: Option<String>,

    /// Verify an existing title catalog against `--catalog` instead of writing
    /// one. Exits non-zero when the table is unstamped, mis-stamped, sparse,
    /// or otherwise unacceptable to a strict consumer.
    #[arg(long)]
    verify: Option<PathBuf>,

    /// Owner-approved titles for Oracle identities that Scryfall describes
    /// with more than one name. Without a row here such an identity is fatal;
    /// this generator never picks a side on its own.
    #[arg(long, default_value = "EXPLICIT_TITLE_RESOLUTIONS.tsv")]
    resolutions: PathBuf,

    /// Historical named token scripts used only to emit presentation titles
    /// for the frozen token genesis block. Required when the catalog contains
    /// token rows; their ordering comes from `lib/token_genesis.rs`, not from
    /// a second title ledger.
    #[arg(long)]
    token_source: Option<PathBuf>,
}

/// Everything the emitted stamp needs from the originating catalog file.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CatalogSource {
    /// SHA-256 of the complete catalog file. This is the `catalog_identity`.
    identity: String,
    /// The catalog's own upstream provenance string.
    snapshot: String,
    /// Dense identity rows ordered by catalog id.
    rows: Vec<CatalogRow>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CatalogRow {
    id: u32,
    provider: CatalogProvider,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CatalogProvider {
    ScryfallOracle(Uuid),
    TokenGenesis,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let catalog = load_catalog(&args.catalog, args.catalog_identity.as_deref())?;

    if let Some(path) = args.verify.as_deref() {
        let bytes = fs::read(path).with_context(|| format!("read title catalog {}", path.display()))?;
        let rows = verify_title_catalog(&bytes, &catalog)?;
        eprintln!("{} verified: {} dense stamped rows", path.display(), rows);
        return Ok(());
    }

    scryfall_bulk::ensure_cache(&args.cache, args.refresh)?;
    let resolutions = load_resolutions(&args.resolutions)?;
    let mut titles = load_titles(&args.cache, &catalog, &resolutions)?;
    load_token_titles(&catalog, args.token_source.as_deref(), &mut titles)?;
    let document = render_title_catalog(&catalog, &titles)?;

    // Re-verify what we are about to publish. A generator that cannot pass its
    // own consumer contract must fail before the file reaches disk.
    verify_title_catalog(&document, &catalog)?;
    write_atomically(&args.output, &document)?;
    eprintln!(
        "Wrote {} ({} titles, catalog_identity={})",
        args.output.display(),
        catalog.rows.len(),
        catalog.identity
    );
    Ok(())
}

/// Read the numeric bridge, verify its self-declared body checksum and row
/// count, and reduce it to dense `(id, oracle_id)` pairs.
fn load_catalog(path: &Path, identity_override: Option<&str>) -> Result<CatalogSource> {
    let bytes = fs::read(path).with_context(|| format!("read numeric catalog {}", path.display()))?;
    let identity = match identity_override {
        Some(value) => {
            check_sha256(value).context("--catalog-identity must be a lowercase hex SHA-256")?;
            value.to_owned()
        }
        None => hex_sha256(&bytes),
    };
    parse_catalog(&bytes, identity).with_context(|| format!("numeric catalog {}", path.display()))
}

fn parse_catalog(bytes: &[u8], identity: String) -> Result<CatalogSource> {
    let text = std::str::from_utf8(bytes).context("catalog is not valid UTF-8")?;
    let (header, body) = text.split_once('\n').context("catalog has no header row")?;
    let columns: Vec<&str> = header.trim_end_matches('\r').split('\t').collect();
    let id_column = column_index(&columns, "#id")?;
    let oracle_column = column_index(&columns, "oracle_id")?;
    let kind_column = columns.iter().position(|column| *column == "kind");

    let metadata = columns
        .iter()
        .find(|column| column.starts_with("metadata:"))
        .context("catalog header has no metadata: field")?;
    let declared_rows: usize = metadata_value(metadata, "cards")
        .context("catalog metadata must declare cards=<count>")?
        .parse()
        .context("catalog metadata has a non-numeric cards= value")?;
    let declared_body = metadata_value(metadata, "body_sha256").context("catalog metadata must declare body_sha256=")?;
    check_sha256(&declared_body).context("catalog metadata body_sha256 is not a SHA-256")?;
    // `snapshot=` is DeepScry's spelling; `catalog_snapshot=` is the spelling a
    // derived bridge inherits from an emitted table. Accept either.
    let snapshot = metadata_value(metadata, "snapshot")
        .or_else(|| metadata_value(metadata, "catalog_snapshot"))
        .context("catalog metadata must declare snapshot=<provenance>")?;

    let actual_body = hex_sha256(body.as_bytes());
    if actual_body != declared_body {
        bail!("catalog body_sha256 mismatch: header declares {declared_body}, body hashes to {actual_body}");
    }

    let mut rows = Vec::with_capacity(declared_rows);
    for (offset, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let line_number = offset + 2;
        let fields: Vec<&str> = line.split('\t').collect();
        // Only these two columns are ever read. A `name` column, if the source
        // still has one, is deliberately unreachable from here.
        let id: u32 = fields
            .get(id_column)
            .with_context(|| format!("catalog line {line_number} has no #id field"))?
            .parse()
            .with_context(|| format!("catalog line {line_number} has a non-numeric #id"))?;
        let kind = kind_column
            .and_then(|column| fields.get(column).copied())
            .unwrap_or("card");
        let oracle = fields
            .get(oracle_column)
            .with_context(|| format!("catalog line {line_number} has no oracle_id field"))?;
        let provider = match kind {
            "card" => CatalogProvider::ScryfallOracle(
                oracle
                    .parse()
                    .with_context(|| format!("catalog line {line_number} has an invalid card oracle_id"))?,
            ),
            "token" => {
                if !oracle.is_empty() {
                    bail!("catalog line {line_number} is a token but has a non-empty oracle_id");
                }
                CatalogProvider::TokenGenesis
            }
            other => bail!("catalog line {line_number} has unknown kind {other:?}"),
        };
        rows.push(CatalogRow { id, provider });
    }

    if rows.len() != declared_rows {
        bail!(
            "catalog has {} rows; its header declares {declared_rows}. Refusing to emit a partial title catalog.",
            rows.len()
        );
    }
    check_dense(&rows.iter().map(|row| row.id).collect::<Vec<_>>())?;
    Ok(CatalogSource {
        identity,
        snapshot,
        rows,
    })
}

/// Read the owner-approved title for Oracle identities Scryfall names more
/// than once.
///
/// Same shape as `EXPLICIT_UNRESOLVED_EXCLUSIONS.tsv`: comment lines, then
/// `oracle_id`, `title`, `status`, `reason`. A missing file is fine — it just
/// means no identity has been resolved yet, and any conflict stays fatal.
fn load_resolutions(path: &Path) -> Result<BTreeMap<Uuid, String>> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
    };
    let mut resolutions = BTreeMap::new();
    for (offset, line) in text.lines().enumerate() {
        let line_number = offset + 1;
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 4 {
            bail!(
                "{}:{line_number} must have oracle_id, title, status and reason",
                path.display()
            );
        }
        let oracle_id: Uuid = fields[0]
            .parse()
            .with_context(|| format!("{}:{line_number} has an invalid oracle_id", path.display()))?;
        let title = fields[1];
        check_title_text(title).with_context(|| format!("{}:{line_number}", path.display()))?;
        if fields[2] != "OWNER_APPROVED_TITLE" {
            bail!(
                "{}:{line_number} has status {:?}; only OWNER_APPROVED_TITLE is honoured",
                path.display(),
                fields[2]
            );
        }
        if fields[3].trim().is_empty() {
            bail!("{}:{line_number} must state a reason", path.display());
        }
        if resolutions.insert(oracle_id, title.to_owned()).is_some() {
            bail!("{}:{line_number} repeats oracle_id {oracle_id}", path.display());
        }
    }
    Ok(resolutions)
}

/// Resolve every catalog Oracle identity to its Scryfall title.
///
/// Scryfall's `name` is the Oracle-level English title on every printing,
/// including non-English ones, where the localized string lives in
/// `printed_name`.
///
/// The Oracle identity comes from [`ScryfallCard::effective_oracle_id`], NOT
/// from the top-level field alone: every `reversible_card` printing has a null
/// top-level `oracle_id` and carries its identity on the faces. Reading only
/// the top level silently drops all of them, and that is not a harmless
/// omission — a dropped reversible printing can leave some other record as the
/// apparent sole owner of an Oracle id, so a card is renamed rather than
/// merely missing.
///
/// Printings that resolve to one Oracle identity must agree on the name. A
/// disagreement is a genuine ambiguity in the source data, not a formatting
/// difference, so it is fatal unless an owner-approved row resolves it. This
/// generator never picks a side by itself.
fn load_titles(
    cache: &Path,
    catalog: &CatalogSource,
    resolutions: &BTreeMap<Uuid, String>,
) -> Result<BTreeMap<u32, String>> {
    let wanted: std::collections::HashSet<Uuid> = catalog
        .rows
        .iter()
        .filter_map(|row| match row.provider {
            CatalogProvider::ScryfallOracle(oracle_id) => Some(oracle_id),
            CatalogProvider::TokenGenesis => None,
        })
        .collect();
    // Names seen per Oracle identity, bucketed by printing precedence.
    let mut by_precedence: BTreeMap<Uuid, BTreeMap<u8, BTreeSet<String>>> = BTreeMap::new();
    scryfall_bulk::for_each_card(cache, |card| {
        let Some(oracle_id) = card.effective_oracle_id() else {
            return;
        };
        if !wanted.contains(&oracle_id) {
            return;
        }
        by_precedence
            .entry(oracle_id)
            .or_default()
            .entry(name_precedence(&card.layout))
            .or_default()
            .insert(card.name);
    })?;

    let mut titles: BTreeMap<Uuid, String> = BTreeMap::new();
    let mut conflicts: BTreeMap<Uuid, BTreeSet<String>> = BTreeMap::new();
    for (oracle_id, tiers) in &by_precedence {
        let Some((_, names)) = tiers.iter().next() else {
            continue;
        };
        let mut names = names.iter();
        let first = names.next().expect("a populated tier has at least one name");
        if names.next().is_some() {
            // Still ambiguous inside the winning tier: precedence cannot help.
            conflicts.insert(*oracle_id, tiers.values().flatten().cloned().collect());
            continue;
        }
        titles.insert(*oracle_id, first.clone());
    }

    // An ambiguity precedence could not settle is fatal unless an
    // owner-approved row settles it. Report it AS a conflict: these identities
    // would otherwise fall out as "no Scryfall title" further down, which
    // names the wrong cause and sends the reader looking for missing data
    // rather than for two records disagreeing.
    let unresolved: Vec<String> = conflicts
        .iter()
        .filter(|(oracle_id, _)| !resolutions.contains_key(oracle_id))
        .map(|(oracle_id, names)| format!("{oracle_id}: {names:?}"))
        .collect();
    if !unresolved.is_empty() {
        bail!(
            "{} Oracle identities have conflicting Scryfall titles that printing precedence cannot settle, \
             and no owner-approved resolution: {}. Add a row to the resolutions file rather than letting \
             this generator guess.",
            unresolved.len(),
            unresolved.iter().take(10).cloned().collect::<Vec<_>>().join("; ")
        );
    }

    for (oracle_id, approved) in resolutions {
        let Some(current) = titles.get_mut(oracle_id) else {
            continue;
        };
        if !conflicts.contains_key(oracle_id) && current == approved {
            continue;
        }
        *current = approved.clone();
    }
    // A resolution that settles nothing is stale bookkeeping; say so rather
    // than carrying it silently forever.
    let inert: Vec<String> = resolutions
        .keys()
        .filter(|oracle_id| !conflicts.contains_key(oracle_id))
        .map(|oracle_id| oracle_id.to_string())
        .collect();
    if !inert.is_empty() {
        bail!(
            "{} title resolution(s) no longer settle any conflict and must be removed: {}",
            inert.len(),
            inert.join(", ")
        );
    }

    let missing: Vec<String> = catalog
        .rows
        .iter()
        .filter_map(|row| match row.provider {
            CatalogProvider::ScryfallOracle(oracle_id) if !titles.contains_key(&oracle_id) => {
                Some(format!("{} ({oracle_id})", row.id))
            }
            _ => None,
        })
        .collect();
    if !missing.is_empty() {
        bail!(
            "{} catalog IDs have no Scryfall title: {}. Refusing to emit a sparse title catalog.",
            missing.len(),
            missing.iter().take(10).cloned().collect::<Vec<_>>().join(", ")
        );
    }
    Ok(catalog
        .rows
        .iter()
        .filter_map(|row| match row.provider {
            CatalogProvider::ScryfallOracle(oracle_id) => Some((row.id, titles[&oracle_id].clone())),
            CatalogProvider::TokenGenesis => None,
        })
        .collect())
}

/// Add the frozen token block to the same dense presentation table as cards.
///
/// The source stem-to-ID ordering comes exclusively from `token_genesis`.
/// This function reads only the ordered `Name:` fields needed for the skin;
/// it neither invents nor persists another token identity namespace.
fn load_token_titles(
    catalog: &CatalogSource,
    source: Option<&Path>,
    titles: &mut BTreeMap<u32, String>,
) -> Result<()> {
    let token_ids: Vec<u32> = catalog
        .rows
        .iter()
        .filter_map(|row| matches!(row.provider, CatalogProvider::TokenGenesis).then_some(row.id))
        .collect();
    if token_ids.is_empty() {
        return Ok(());
    }
    let source = source.context("catalog contains token rows; --token-source is required to title them")?;
    let genesis = token_genesis::rows(source, token_genesis::CARD_MAX_ID)?;
    let genesis_ids: Vec<u32> = genesis.iter().map(|row| row.catalog_id).collect();
    if token_ids != genesis_ids {
        bail!(
            "catalog token rows do not equal the frozen genesis block {}..={}: found {} rows from {:?} to {:?}",
            token_genesis::CARD_MAX_ID + 1,
            token_genesis::CARD_MAX_ID + token_genesis::ROWS,
            token_ids.len(),
            token_ids.first(),
            token_ids.last()
        );
    }
    for row in genesis {
        let script = fs::read_to_string(&row.source_path)
            .with_context(|| format!("read token presentation source {}", row.source_path.display()))?;
        let title = token_presentation_title(&script)
            .with_context(|| format!("token presentation source {}", row.source_path.display()))?;
        if titles.insert(row.catalog_id, title).is_some() {
            bail!("catalog ID {} was titled twice", row.catalog_id);
        }
    }
    Ok(())
}

fn token_presentation_title(script: &str) -> Result<String> {
    let mut names = Vec::new();
    let mut alternate_mode = None;
    for line in script.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key.trim() {
            "Name" => names.push(value.trim()),
            "AlternateMode" => alternate_mode = Some(value.trim()),
            _ => {}
        }
    }
    match names.as_slice() {
        [name] => {
            check_title_text(name)?;
            Ok((*name).to_owned())
        }
        [front, back] if alternate_mode == Some("DoubleFaced") => {
            check_title_text(front)?;
            check_title_text(back)?;
            Ok(format!("{front} // {back}"))
        }
        [] => bail!("script has no Name field"),
        _ => bail!(
            "script has {} Name fields with AlternateMode={alternate_mode:?}; only one title or a two-title DoubleFaced token is supported",
            names.len()
        ),
    }
}

fn render_title_catalog(catalog: &CatalogSource, titles: &BTreeMap<u32, String>) -> Result<Vec<u8>> {
    let mut body = String::new();
    for row in &catalog.rows {
        let title = titles
            .get(&row.id)
            .with_context(|| format!("catalog ID {} has no resolved title", row.id))?;
        check_title(row.id, title)?;
        body.push_str(&format!("{}\t{title}\n", row.id));
    }
    let header = format!(
        "#id\ttitle\tmetadata: v={SKIN_VERSION} kind={SKIN_KIND} catalog_snapshot={} catalog_identity={} cards={} body_sha256={}\n",
        catalog.snapshot,
        catalog.identity,
        catalog.rows.len(),
        hex_sha256(body.as_bytes()),
    );
    let mut document = header.into_bytes();
    document.extend_from_slice(body.as_bytes());
    Ok(document)
}

/// The strict consumer contract, applied to emitted bytes.
///
/// This mirrors what DeepScry's loader enforces, plus the binding to the
/// catalog that this repository is uniquely able to check: an unstamped,
/// mis-stamped, sparse, or truncated table must be rejected here rather than
/// discovered by a consumer.
fn verify_title_catalog(bytes: &[u8], catalog: &CatalogSource) -> Result<usize> {
    let text = std::str::from_utf8(bytes).context("title catalog is not valid UTF-8")?;
    let (header, body) = text.split_once('\n').context("title catalog has no header row")?;
    let columns: Vec<&str> = header.trim_end_matches('\r').split('\t').collect();
    let id_column = column_index(&columns, "#id")?;
    let title_column = column_index(&columns, "title")?;

    let metadata = columns
        .iter()
        .find(|column| column.starts_with("metadata:"))
        .context("title catalog header has no metadata: field")?;
    let declared_kind = metadata_value(metadata, "kind").context("title catalog metadata must declare kind=")?;
    if declared_kind != SKIN_KIND {
        bail!("title catalog declares kind={declared_kind}, expected {SKIN_KIND}");
    }
    let identity =
        metadata_value(metadata, "catalog_identity").context("title catalog metadata must declare catalog_identity=")?;
    check_sha256(&identity).context("title catalog catalog_identity is not a SHA-256")?;
    if identity != catalog.identity {
        bail!(
            "title catalog is stamped for catalog {identity}, but this catalog is {}. \
             It would name the wrong cards.",
            catalog.identity
        );
    }
    metadata_value(metadata, "catalog_snapshot").context("title catalog metadata must declare catalog_snapshot=")?;
    let declared_rows: usize = metadata_value(metadata, "cards")
        .context("title catalog metadata must declare cards=")?
        .parse()
        .context("title catalog metadata has a non-numeric cards= value")?;
    let declared_body =
        metadata_value(metadata, "body_sha256").context("title catalog metadata must declare body_sha256=")?;
    let actual_body = hex_sha256(body.as_bytes());
    if actual_body != declared_body {
        bail!("title catalog body_sha256 mismatch: header declares {declared_body}, body hashes to {actual_body}");
    }

    let data_columns = columns.len() - 1;
    let mut ids = Vec::with_capacity(declared_rows);
    for (offset, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let line_number = offset + 2;
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != data_columns {
            bail!("title catalog line {line_number} has {} fields, expected {data_columns}", fields.len());
        }
        let id: u32 = fields[id_column]
            .parse()
            .with_context(|| format!("title catalog line {line_number} has a non-numeric #id"))?;
        check_title(id, fields[title_column])?;
        ids.push(id);
    }

    if ids.len() != declared_rows {
        bail!("title catalog has {} rows; its header declares {declared_rows}", ids.len());
    }
    if ids.len() != catalog.rows.len() {
        bail!(
            "title catalog has {} rows but the catalog has {}. A sparse table would leave IDs unnamed.",
            ids.len(),
            catalog.rows.len()
        );
    }
    check_dense(&ids)?;
    Ok(ids.len())
}

/// Every ID from 1 to the row count must be present exactly once, in order.
/// This is the density guarantee: a consumer indexes by catalog ID directly.
fn check_dense(ids: &[u32]) -> Result<()> {
    for (offset, id) in ids.iter().enumerate() {
        let expected = u32::try_from(offset + 1).context("catalog is larger than u32")?;
        if *id != expected {
            bail!("table is not dense: expected ID {expected} at row {}, found {id}", offset + 1);
        }
    }
    Ok(())
}

/// Printing precedence for choosing an Oracle identity's title. Lower wins.
///
/// A `reversible_card` is a special double-sided PRINTING of a card that
/// already exists, and Scryfall names it with the doubled `X // X` form; the
/// ordinary printing carries the card's real title. A `token` record is not a
/// catalog card's canonical presentation at all.
///
/// This ordering is derived from the 71 Oracle identities in the current
/// corpus that Scryfall names more than once — 67 `normal`+`reversible_card`,
/// 3 `adventure`+`reversible_card`, and 1 `reversible_card`+`token` — where it
/// reproduces the catalog's own recorded name in all 71 cases with no
/// counterexample. Where an identity has ONLY a reversible printing and a
/// token, the reversible name wins, which is why the token tier sorts last
/// rather than being dropped.
fn name_precedence(layout: &str) -> u8 {
    match layout {
        "reversible_card" => 1,
        "token" => 2,
        _ => 0,
    }
}

fn check_title(id: u32, title: &str) -> Result<()> {
    check_title_text(title).with_context(|| format!("catalog ID {id}"))
}

fn check_title_text(title: &str) -> Result<()> {
    if title.is_empty() {
        bail!("title is blank");
    }
    if title.contains('\t') || title.contains('\n') || title.contains('\r') {
        bail!("title contains a tab or line break");
    }
    Ok(())
}

fn column_index(columns: &[&str], wanted: &str) -> Result<usize> {
    columns
        .iter()
        .position(|column| *column == wanted)
        .with_context(|| format!("header has no {wanted:?} column"))
}

/// Read `key=value` out of a whitespace-separated `metadata:` header field.
fn metadata_value(metadata: &str, key: &str) -> Option<String> {
    metadata
        .split_whitespace()
        .find_map(|token| token.strip_prefix(key)?.strip_prefix('=').map(str::to_owned))
}

fn check_sha256(value: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()) {
        bail!("{value:?} is not a lowercase hex SHA-256");
    }
    Ok(())
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn write_atomically(output: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let temporary = output.with_extension("write-part");
    fs::write(&temporary, bytes).with_context(|| format!("write {}", temporary.display()))?;
    fs::rename(&temporary, output).with_context(|| format!("publish {}", output.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORACLE_A: &str = "12345678-1234-1234-1234-123456789abc";
    const ORACLE_B: &str = "22345678-1234-1234-1234-123456789abc";

    /// Build a catalog whose header honestly describes its body.
    fn catalog_bytes(header_columns: &str, body: &str, extra_metadata: &str) -> Vec<u8> {
        let metadata = format!(
            "metadata: v=2 snapshot=default_cards@test cards={} body_sha256={}{extra_metadata}",
            body.lines().filter(|line| !line.trim().is_empty()).count(),
            hex_sha256(body.as_bytes()),
        );
        format!("{header_columns}\t{metadata}\n{body}").into_bytes()
    }

    fn sample_catalog() -> CatalogSource {
        let body = format!("1\tAlpha\t{ORACLE_A}\n2\tBeta\t{ORACLE_B}\n");
        let bytes = catalog_bytes("#id\tname\toracle_id", &body, "");
        let identity = hex_sha256(&bytes);
        parse_catalog(&bytes, identity).unwrap()
    }

    fn sample_titles() -> BTreeMap<u32, String> {
        BTreeMap::from([
            (1, "Fixture Qzx Alpha".to_owned()),
            (2, "Fixture Qzx Beta".to_owned()),
        ])
    }

    #[test]
    fn catalog_identity_is_the_hash_of_the_whole_catalog_file() {
        let body = format!("1\tAlpha\t{ORACLE_A}\n");
        let bytes = catalog_bytes("#id\tname\toracle_id", &body, "");
        let parsed = parse_catalog(&bytes, hex_sha256(&bytes)).unwrap();
        assert_eq!(parsed.identity, hex_sha256(&bytes));
        assert_eq!(parsed.snapshot, "default_cards@test");
    }

    /// The load-bearing IP property: titles never come from the catalog. A
    /// catalog whose `name` column is poisoned still yields Scryfall titles,
    /// so this generator keeps working once that column is scrubbed away.
    #[test]
    fn titles_never_come_from_the_catalog_name_column() {
        let body = format!("1\tPOISONED\t{ORACLE_A}\n2\tPOISONED\t{ORACLE_B}\n");
        let bytes = catalog_bytes("#id\tname\toracle_id", &body, "");
        let catalog = parse_catalog(&bytes, hex_sha256(&bytes)).unwrap();
        let document = render_title_catalog(&catalog, &sample_titles()).unwrap();
        let text = String::from_utf8(document).unwrap();
        assert!(!text.contains("POISONED"), "catalog title column leaked into the output");
        assert!(text.contains("1\tFixture Qzx Alpha\n"));
    }

    /// A catalog with no `name` column at all — the post-scrub shape — must
    /// still emit a complete table.
    #[test]
    fn emits_from_a_title_free_catalog() {
        let body = format!("1\t{ORACLE_A}\tdigest\n2\t{ORACLE_B}\tdigest\n");
        let bytes = catalog_bytes("#id\toracle_id\tname_sha256", &body, "");
        let catalog = parse_catalog(&bytes, hex_sha256(&bytes)).unwrap();
        let document = render_title_catalog(&catalog, &sample_titles()).unwrap();
        assert_eq!(verify_title_catalog(&document, &catalog).unwrap(), 2);
    }

    #[test]
    fn parses_card_and_token_rows_in_one_dense_catalog() {
        let body = format!("1\tcard\t{ORACLE_A}\n2\ttoken\t\n");
        let bytes = catalog_bytes("#id\tkind\toracle_id", &body, "");
        let catalog = parse_catalog(&bytes, hex_sha256(&bytes)).unwrap();
        assert!(matches!(
            catalog.rows[0].provider,
            CatalogProvider::ScryfallOracle(_)
        ));
        assert_eq!(catalog.rows[1].provider, CatalogProvider::TokenGenesis);
    }

    #[test]
    fn token_titles_preserve_ordered_double_faces() {
        assert_eq!(
            token_presentation_title("Name:Fixture Qzx Token Front\nAlternateMode:DoubleFaced\nALTERNATE\nName:Fixture Qzx Token Back\n")
                .unwrap(),
            "Fixture Qzx Token Front // Fixture Qzx Token Back"
        );
        assert!(token_presentation_title("AlternateMode:DoubleFaced\nName:Front\nName:Middle\nName:Back\n").is_err());
    }

    #[test]
    fn emitted_header_matches_the_strict_consumer_schema() {
        let catalog = sample_catalog();
        let document = render_title_catalog(&catalog, &sample_titles()).unwrap();
        let text = String::from_utf8(document).unwrap();
        let header = text.lines().next().unwrap();
        assert!(header.starts_with("#id\ttitle\tmetadata: v=1 kind=title-only-skin catalog_snapshot=default_cards@test catalog_identity="));
        assert!(header.contains(&format!("catalog_identity={} cards=2 body_sha256=", catalog.identity)));
    }

    #[test]
    fn generation_is_deterministic() {
        let catalog = sample_catalog();
        let first = render_title_catalog(&catalog, &sample_titles()).unwrap();
        let second = render_title_catalog(&catalog, &sample_titles()).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn accepts_its_own_output() {
        let catalog = sample_catalog();
        let document = render_title_catalog(&catalog, &sample_titles()).unwrap();
        assert_eq!(verify_title_catalog(&document, &catalog).unwrap(), 2);
    }

    #[test]
    fn rejects_an_unstamped_table() {
        let catalog = sample_catalog();
        let document = render_title_catalog(&catalog, &sample_titles()).unwrap();
        let stripped = String::from_utf8(document)
            .unwrap()
            .replace(&format!(" catalog_identity={}", catalog.identity), "");
        let error = verify_title_catalog(stripped.as_bytes(), &catalog).unwrap_err().to_string();
        assert!(error.contains("catalog_identity"), "unexpected error: {error}");
    }

    #[test]
    fn rejects_a_table_stamped_for_a_different_catalog() {
        let catalog = sample_catalog();
        let document = render_title_catalog(&catalog, &sample_titles()).unwrap();
        let wrong = String::from_utf8(document)
            .unwrap()
            .replace(&catalog.identity, &"0".repeat(64));
        let error = verify_title_catalog(wrong.as_bytes(), &catalog).unwrap_err().to_string();
        assert!(error.contains("name the wrong cards"), "unexpected error: {error}");
    }

    #[test]
    fn rejects_a_sparse_table() {
        let catalog = sample_catalog();
        let document = render_title_catalog(&catalog, &sample_titles()).unwrap();
        let text = String::from_utf8(document).unwrap();
        // Drop the first data row and honestly restate the count and checksum,
        // so only the density and catalog-coverage checks can reject it.
        let body = "2\tFixture Qzx Beta\n";
        let header = text
            .lines()
            .next()
            .unwrap()
            .replace("cards=2", "cards=1")
            .replace(
                &format!("body_sha256={}", hex_sha256("1\tFixture Qzx Alpha\n2\tFixture Qzx Beta\n".as_bytes())),
                &format!("body_sha256={}", hex_sha256(body.as_bytes())),
            );
        let sparse = format!("{header}\n{body}");
        let error = verify_title_catalog(sparse.as_bytes(), &catalog).unwrap_err().to_string();
        assert!(error.contains("sparse") || error.contains("not dense"), "unexpected error: {error}");
    }

    #[test]
    fn rejects_a_gap_in_the_id_sequence() {
        assert!(check_dense(&[1, 2, 4]).is_err());
        assert!(check_dense(&[2, 3]).is_err());
        assert!(check_dense(&[1, 2, 3]).is_ok());
    }

    #[test]
    fn rejects_a_tampered_body() {
        let catalog = sample_catalog();
        let document = render_title_catalog(&catalog, &sample_titles()).unwrap();
        let tampered = String::from_utf8(document).unwrap().replace("Fixture Qzx Alpha", "Air Elementaz");
        let error = verify_title_catalog(tampered.as_bytes(), &catalog).unwrap_err().to_string();
        assert!(error.contains("body_sha256 mismatch"), "unexpected error: {error}");
    }

    #[test]
    fn rejects_a_catalog_whose_body_checksum_is_wrong() {
        let body = format!("1\tAlpha\t{ORACLE_A}\n");
        let mut bytes = catalog_bytes("#id\tname\toracle_id", &body, "");
        bytes.extend_from_slice(format!("2\tBeta\t{ORACLE_B}\n").as_bytes());
        assert!(parse_catalog(&bytes, "0".repeat(64)).is_err());
    }

    #[test]
    fn rejects_a_catalog_with_no_metadata_header() {
        let body = format!("1\tAlpha\t{ORACLE_A}\n");
        let bytes = format!("#id\tname\toracle_id\n{body}").into_bytes();
        let error = parse_catalog(&bytes, "0".repeat(64)).unwrap_err().to_string();
        assert!(error.contains("metadata:"), "unexpected error: {error}");
    }

    #[test]
    fn rejects_a_non_dense_catalog() {
        let body = format!("1\tAlpha\t{ORACLE_A}\n3\tBeta\t{ORACLE_B}\n");
        let bytes = catalog_bytes("#id\tname\toracle_id", &body, "");
        assert!(parse_catalog(&bytes, hex_sha256(&bytes)).is_err());
    }

    #[test]
    fn rejects_a_blank_or_tabbed_title() {
        assert!(check_title(1, "").is_err());
        assert!(check_title(1, "Air\tElemental").is_err());
        assert!(check_title(1, "Fixture Qzx Alpha").is_ok());
    }

    /// The ordering is load-bearing, and getting it wrong renames real cards
    /// rather than failing: a `reversible_card` printing would rename 70 cards
    /// to their doubled `X // X` form, and demoting the reversible tier below
    /// `token` would rename the one reversible-only identity to a token name.
    #[test]
    fn printing_precedence_prefers_an_ordinary_printing_then_reversible_then_token() {
        assert_eq!(name_precedence("normal"), 0);
        assert_eq!(name_precedence("adventure"), 0);
        assert_eq!(name_precedence("transform"), 0);
        assert_eq!(name_precedence("split"), 0);
        assert!(name_precedence("normal") < name_precedence("reversible_card"));
        assert!(name_precedence("reversible_card") < name_precedence("token"));
    }

    /// A resolution file is parsed strictly: only the approved status counts,
    /// and a row must say why.
    #[test]
    fn resolution_rows_require_the_approved_status_and_a_reason() {
        let directory = std::env::temp_dir().join(format!("title-resolutions-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("resolutions.tsv");

        std::fs::write(&path, "# comment\n").unwrap();
        assert!(load_resolutions(&path).unwrap().is_empty(), "comments only means no resolutions");

        std::fs::write(&path, format!("{ORACLE_A}\tTitle\tGUESSED\tbecause\n")).unwrap();
        assert!(load_resolutions(&path).is_err(), "an unapproved status must be refused");

        std::fs::write(&path, format!("{ORACLE_A}\tTitle\tOWNER_APPROVED_TITLE\t\n")).unwrap();
        assert!(load_resolutions(&path).is_err(), "a row with no reason must be refused");

        std::fs::write(&path, format!("{ORACLE_A}\tTitle\tOWNER_APPROVED_TITLE\tan actual reason\n")).unwrap();
        assert_eq!(load_resolutions(&path).unwrap().get(&ORACLE_A.parse().unwrap()).unwrap(), "Title");

        // A missing file is not an error: it means nothing has been resolved,
        // and any conflict therefore stays fatal.
        std::fs::remove_file(&path).unwrap();
        assert!(load_resolutions(&path).unwrap().is_empty());
        std::fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn metadata_values_are_read_by_exact_key() {
        let metadata = "metadata: v=1 catalog_snapshot=snap catalog_identity=abc cards=7";
        assert_eq!(metadata_value(metadata, "cards").as_deref(), Some("7"));
        assert_eq!(metadata_value(metadata, "catalog_identity").as_deref(), Some("abc"));
        // `snapshot` must not be satisfied by `catalog_snapshot`.
        assert_eq!(metadata_value(metadata, "snapshot"), None);
    }
}
