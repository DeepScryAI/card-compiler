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
//! Emit the sparse presentation body table for DeepScry's unified catalog.
//! Card bodies come only from Scryfall Oracle text. Token bodies come only
//! from the historical named scripts that define the frozen token genesis
//! order. The numeric identity catalog supplies no presentation text.

use anyhow::{bail, Context, Result};
use clap::Parser;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[path = "../lib/scryfall_bulk.rs"]
mod scryfall_bulk;
#[path = "lib/token_genesis.rs"]
mod token_genesis;

const SKIN_KIND: &str = "body-skin";
const SKIN_VERSION: &str = "1";

#[derive(Parser, Debug)]
#[command(about = "Emit the catalog-stamped presentation body table")]
struct Args {
    /// DeepScry identity catalog (`#id`, `kind`, `oracle_id`, metadata).
    #[arg(long, default_value = "catalog_ids.tsv")]
    catalog: PathBuf,

    /// Decompressed Scryfall default_cards cache.
    #[arg(long, default_value = ".cache/scryfall/default_cards.json")]
    cache: PathBuf,

    /// Historical named token scripts for the frozen 837-row token block.
    #[arg(long)]
    token_source: Option<PathBuf>,

    /// Generated sparse SS4 body table.
    #[arg(long, default_value = "presentation/body_catalog.tsv")]
    output: PathBuf,

    /// Ignore a present cache and download the current snapshot.
    #[arg(long)]
    refresh: bool,

    /// Verify an existing body table instead of writing one.
    #[arg(long)]
    verify: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CatalogSource {
    identity: String,
    rows: Vec<CatalogRow>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CatalogRow {
    id: u32,
    provider: CatalogProvider,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CatalogProvider {
    ScryfallOracle(Uuid),
    TokenGenesis,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Coverage {
    card_rows: usize,
    card_bodies: usize,
    token_rows: usize,
    token_bodies: usize,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let catalog = load_catalog(&args.catalog)?;
    if let Some(path) = args.verify.as_deref() {
        let bytes = fs::read(path).with_context(|| format!("read body catalog {}", path.display()))?;
        let rows = verify_body_catalog(&bytes, &catalog)?;
        eprintln!("{} verified: {rows} sparse, stamped body rows", path.display());
        return Ok(());
    }

    scryfall_bulk::ensure_cache(&args.cache, args.refresh)?;
    let (bodies, coverage) = load_bodies(&args.cache, &catalog, args.token_source.as_deref())?;
    let document = render_body_catalog(&catalog, &bodies)?;
    verify_body_catalog(&document, &catalog)?;
    write_atomically(&args.output, &document)?;
    eprintln!(
        "Wrote {} ({} bodies: {}/{} cards, {}/{} tokens; catalog_identity={})",
        args.output.display(),
        bodies.len(),
        coverage.card_bodies,
        coverage.card_rows,
        coverage.token_bodies,
        coverage.token_rows,
        catalog.identity
    );
    Ok(())
}

fn load_catalog(path: &Path) -> Result<CatalogSource> {
    let bytes = fs::read(path).with_context(|| format!("read numeric catalog {}", path.display()))?;
    let identity = hex_sha256(&bytes);
    parse_catalog(&bytes, identity).with_context(|| format!("numeric catalog {}", path.display()))
}

fn parse_catalog(bytes: &[u8], identity: String) -> Result<CatalogSource> {
    let text = std::str::from_utf8(bytes).context("catalog is not valid UTF-8")?;
    let (header, body) = text.split_once('\n').context("catalog has no header row")?;
    let columns: Vec<_> = header.trim_end_matches('\r').split('\t').collect();
    let id_column = column_index(&columns, "#id")?;
    let kind_column = column_index(&columns, "kind")?;
    let oracle_column = column_index(&columns, "oracle_id")?;
    let metadata = metadata_column(&columns, "catalog")?;
    let declared_rows: usize = metadata_value(metadata, "cards")
        .context("catalog metadata must declare cards=")?
        .parse()
        .context("catalog metadata cards= is not numeric")?;
    let declared_body =
        metadata_value(metadata, "body_sha256").context("catalog metadata must declare body_sha256=")?;
    check_sha256(&declared_body)?;
    let actual_body = hex_sha256(body.as_bytes());
    if actual_body != declared_body {
        bail!("catalog body_sha256 mismatch: header declares {declared_body}, body hashes to {actual_body}");
    }

    let mut rows = Vec::with_capacity(declared_rows);
    for (offset, line) in body.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let line_number = offset + 2;
        let fields: Vec<_> = line.split('\t').collect();
        let id: u32 = field(&fields, id_column, line_number, "#id")?
            .parse()
            .with_context(|| format!("catalog line {line_number} has a non-numeric #id"))?;
        let kind = field(&fields, kind_column, line_number, "kind")?;
        let oracle = field(&fields, oracle_column, line_number, "oracle_id")?;
        let provider = match kind {
            "card" => CatalogProvider::ScryfallOracle(
                oracle
                    .parse()
                    .with_context(|| format!("catalog line {line_number} has an invalid card oracle_id"))?,
            ),
            "token" if oracle.is_empty() => CatalogProvider::TokenGenesis,
            "token" => bail!("catalog line {line_number} is a token with a non-empty oracle_id"),
            other => bail!("catalog line {line_number} has unknown kind {other:?}"),
        };
        rows.push(CatalogRow { id, provider });
    }
    if rows.len() != declared_rows {
        bail!("catalog has {} rows; header declares {declared_rows}", rows.len());
    }
    check_dense(rows.iter().map(|row| row.id))?;
    Ok(CatalogSource { identity, rows })
}

fn load_bodies(
    cache: &Path,
    catalog: &CatalogSource,
    token_source: Option<&Path>,
) -> Result<(BTreeMap<u32, String>, Coverage)> {
    let wanted: HashSet<_> = catalog
        .rows
        .iter()
        .filter_map(|row| match row.provider {
            CatalogProvider::ScryfallOracle(oracle_id) => Some(oracle_id),
            CatalogProvider::TokenGenesis => None,
        })
        .collect();
    let mut seen = HashSet::new();
    let mut by_precedence: BTreeMap<Uuid, BTreeMap<u8, BTreeSet<Option<String>>>> = BTreeMap::new();
    scryfall_bulk::for_each_card(cache, |card| {
        let Some(oracle_id) = card.effective_oracle_id() else {
            return;
        };
        if !wanted.contains(&oracle_id) {
            return;
        }
        seen.insert(oracle_id);
        by_precedence
            .entry(oracle_id)
            .or_default()
            .entry(presentation_precedence(&card.layout))
            .or_default()
            .insert(scryfall_body(&card));
    })?;

    let missing: Vec<_> = wanted.difference(&seen).copied().collect();
    if !missing.is_empty() {
        bail!(
            "Scryfall cache has no record for {} catalog Oracle identities (first: {})",
            missing.len(),
            missing[0]
        );
    }

    let mut by_oracle = BTreeMap::new();
    let mut conflicts = Vec::new();
    for (oracle_id, tiers) in by_precedence {
        let (_, candidates) = tiers.iter().next().expect("seen Oracle identity has a precedence tier");
        if candidates.len() != 1 {
            conflicts.push(format!("{oracle_id}: {candidates:?}"));
            continue;
        }
        by_oracle.insert(oracle_id, candidates.iter().next().expect("one candidate").clone());
    }
    if !conflicts.is_empty() {
        bail!(
            "{} Oracle identities have ambiguous bodies in their highest-precedence Scryfall records: {}",
            conflicts.len(),
            conflicts.iter().take(5).cloned().collect::<Vec<_>>().join("; ")
        );
    }

    let mut bodies = BTreeMap::new();
    let mut coverage = Coverage::default();
    for row in &catalog.rows {
        match row.provider {
            CatalogProvider::ScryfallOracle(oracle_id) => {
                coverage.card_rows += 1;
                if let Some(body) = by_oracle.get(&oracle_id).with_context(|| {
                    format!(
                        "no resolved Scryfall body state for catalog ID {} ({oracle_id})",
                        row.id
                    )
                })? {
                    check_body(body).with_context(|| format!("catalog ID {}", row.id))?;
                    bodies.insert(row.id, body.clone());
                    coverage.card_bodies += 1;
                }
            }
            CatalogProvider::TokenGenesis => coverage.token_rows += 1,
        }
    }
    load_token_bodies(catalog, token_source, &mut bodies, &mut coverage)?;
    Ok((bodies, coverage))
}

/// Use top-level Oracle text when Scryfall supplies it. Otherwise preserve all
/// face slots, in source order, separated by one blank line. Empty faces stay
/// represented by their position as long as at least one face has text.
fn scryfall_body(card: &scryfall_bulk::ScryfallCard) -> Option<String> {
    if let Some(body) = card.oracle_text.as_deref().and_then(nonempty_trimmed) {
        return Some(body.to_owned());
    }
    if card.card_faces.is_empty() {
        return None;
    }
    let faces: Vec<_> = card
        .card_faces
        .iter()
        .map(|face| face.oracle_text.as_deref().map(str::trim).unwrap_or_default())
        .collect();
    faces.iter().any(|face| !face.is_empty()).then(|| faces.join("\n\n"))
}

fn presentation_precedence(layout: &str) -> u8 {
    match layout {
        "reversible_card" => 1,
        "token" => 2,
        _ => 0,
    }
}

fn load_token_bodies(
    catalog: &CatalogSource,
    source: Option<&Path>,
    bodies: &mut BTreeMap<u32, String>,
    coverage: &mut Coverage,
) -> Result<()> {
    if coverage.token_rows == 0 {
        return Ok(());
    }
    let source = source.context("catalog contains token rows; --token-source is required to body them")?;
    let token_ids: Vec<_> = catalog
        .rows
        .iter()
        .filter_map(|row| matches!(row.provider, CatalogProvider::TokenGenesis).then_some(row.id))
        .collect();
    let genesis = token_genesis::rows(source, token_genesis::CARD_MAX_ID)?;
    if token_ids != genesis.iter().map(|row| row.catalog_id).collect::<Vec<_>>() {
        bail!("catalog token rows do not equal the frozen token genesis block");
    }
    for row in genesis {
        let script = fs::read_to_string(&row.source_path)
            .with_context(|| format!("read token body source {}", row.source_path.display()))?;
        if let Some(body) = token_presentation_body(&script)
            .with_context(|| format!("token body source {}", row.source_path.display()))?
        {
            check_body(&body).with_context(|| format!("catalog ID {}", row.catalog_id))?;
            if bodies.insert(row.catalog_id, body).is_some() {
                bail!("catalog ID {} received two bodies", row.catalog_id);
            }
            coverage.token_bodies += 1;
        }
    }
    Ok(())
}

fn token_presentation_body(script: &str) -> Result<Option<String>> {
    let mut bodies = Vec::new();
    let mut alternate_mode = None;
    for line in script.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key.trim() {
            "Oracle" => bodies.push(unescape_script_body(value)?),
            "AlternateMode" => alternate_mode = Some(value.trim()),
            _ => {}
        }
    }
    match bodies.as_slice() {
        [body] => Ok((!body.is_empty()).then(|| body.clone())),
        [front, back] if alternate_mode == Some("DoubleFaced") => {
            Ok((!front.is_empty() || !back.is_empty()).then(|| format!("{front}\n\n{back}")))
        }
        [] => bail!("script has no Oracle field"),
        _ => bail!(
            "script has {} Oracle fields with AlternateMode={alternate_mode:?}; expected one body or two DoubleFaced bodies",
            bodies.len()
        ),
    }
}

fn unescape_script_body(value: &str) -> Result<String> {
    let mut decoded = String::new();
    let mut chars = value.trim().chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            decoded.push(character);
            continue;
        }
        match chars.next().context("Oracle field ends with an incomplete escape")? {
            'n' => decoded.push('\n'),
            't' => decoded.push('\t'),
            '\\' => decoded.push('\\'),
            other => bail!("Oracle field contains unsupported escape \\{other}"),
        }
    }
    Ok(decoded)
}

fn render_body_catalog(catalog: &CatalogSource, bodies: &BTreeMap<u32, String>) -> Result<Vec<u8>> {
    let valid_ids: BTreeSet<_> = catalog.rows.iter().map(|row| row.id).collect();
    let mut body = String::new();
    for (id, value) in bodies {
        if !valid_ids.contains(id) {
            bail!("body table contains ID {id}, which is absent from the catalog");
        }
        check_body(value).with_context(|| format!("catalog ID {id}"))?;
        body.push_str(&format!("{id}\t{}\n", escape_body(value)));
    }
    let header = format!(
        "#id\tbody\tmetadata: v={SKIN_VERSION} kind={SKIN_KIND} catalog_identity={} cards={} body_sha256={}\n",
        catalog.identity,
        bodies.len(),
        hex_sha256(body.as_bytes())
    );
    let mut document = header.into_bytes();
    document.extend_from_slice(body.as_bytes());
    Ok(document)
}

fn verify_body_catalog(bytes: &[u8], catalog: &CatalogSource) -> Result<usize> {
    let text = std::str::from_utf8(bytes).context("body catalog is not valid UTF-8")?;
    let (header, body) = text.split_once('\n').context("body catalog has no header row")?;
    let columns: Vec<_> = header.trim_end_matches('\r').split('\t').collect();
    if columns.len() != 3 || columns[0] != "#id" || columns[1] != "body" {
        bail!("body catalog header must be exactly #id, body, metadata");
    }
    let metadata = metadata_column(&columns, "body catalog")?;
    if metadata_value(metadata, "v").as_deref() != Some(SKIN_VERSION) {
        bail!("body catalog does not declare v={SKIN_VERSION}");
    }
    if metadata_value(metadata, "kind").as_deref() != Some(SKIN_KIND) {
        bail!("body catalog does not declare kind={SKIN_KIND}");
    }
    let identity =
        metadata_value(metadata, "catalog_identity").context("body catalog metadata must declare catalog_identity=")?;
    check_sha256(&identity)?;
    if identity != catalog.identity {
        bail!(
            "body catalog is stamped for {identity}, but the catalog is {}",
            catalog.identity
        );
    }
    let declared_rows: usize = metadata_value(metadata, "cards")
        .context("body catalog metadata must declare cards=")?
        .parse()
        .context("body catalog metadata cards= is not numeric")?;
    let declared_body =
        metadata_value(metadata, "body_sha256").context("body catalog metadata must declare body_sha256=")?;
    check_sha256(&declared_body)?;
    let actual_body = hex_sha256(body.as_bytes());
    if actual_body != declared_body {
        bail!("body catalog body_sha256 mismatch: header declares {declared_body}, body hashes to {actual_body}");
    }

    let valid_ids: BTreeSet<_> = catalog.rows.iter().map(|row| row.id).collect();
    let mut previous = 0;
    let mut rows = 0;
    for (offset, line) in body.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let line_number = offset + 2;
        let (id, encoded) = line
            .split_once('\t')
            .with_context(|| format!("body catalog line {line_number} has no body field"))?;
        if encoded.contains('\t') {
            bail!("body catalog line {line_number} has more than two fields");
        }
        let id: u32 = id
            .parse()
            .with_context(|| format!("body catalog line {line_number} has a non-numeric #id"))?;
        if !valid_ids.contains(&id) {
            bail!("body catalog line {line_number} has unknown catalog ID {id}");
        }
        if id <= previous {
            bail!("body catalog IDs are not strictly ascending at line {line_number}");
        }
        let decoded = unescape_body(encoded).with_context(|| format!("body catalog line {line_number}"))?;
        check_body(&decoded).with_context(|| format!("body catalog line {line_number}"))?;
        if escape_body(&decoded) != encoded {
            bail!("body catalog line {line_number} is not canonically escaped");
        }
        previous = id;
        rows += 1;
    }
    if rows != declared_rows {
        bail!("body catalog has {rows} rows; header declares {declared_rows}");
    }
    Ok(rows)
}

fn escape_body(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\t' => escaped.push_str("\\t"),
            _ => escaped.push(character),
        }
    }
    escaped
}

fn unescape_body(value: &str) -> Result<String> {
    let mut decoded = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            decoded.push(character);
            continue;
        }
        match chars.next().context("body ends with an incomplete escape")? {
            'n' => decoded.push('\n'),
            't' => decoded.push('\t'),
            '\\' => decoded.push('\\'),
            other => bail!("body contains unsupported escape \\{other}"),
        }
    }
    Ok(decoded)
}

fn check_body(value: &str) -> Result<()> {
    if value.is_empty() {
        bail!("body is blank; omit blank bodies from the sparse table");
    }
    if value.contains('\r') {
        bail!("body contains a carriage return");
    }
    Ok(())
}

fn nonempty_trimmed(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then_some(trimmed)
}

fn check_dense(ids: impl Iterator<Item = u32>) -> Result<()> {
    for (offset, id) in ids.enumerate() {
        let expected = u32::try_from(offset + 1).context("catalog is larger than u32")?;
        if id != expected {
            bail!("catalog is not dense: expected ID {expected}, found {id}");
        }
    }
    Ok(())
}

fn column_index(columns: &[&str], wanted: &str) -> Result<usize> {
    columns
        .iter()
        .position(|column| *column == wanted)
        .with_context(|| format!("header has no {wanted:?} column"))
}

fn metadata_column<'a>(columns: &'a [&str], subject: &str) -> Result<&'a str> {
    columns
        .iter()
        .find(|column| column.starts_with("metadata:"))
        .copied()
        .with_context(|| format!("{subject} header has no metadata: field"))
}

fn metadata_value(metadata: &str, key: &str) -> Option<String> {
    metadata
        .split_whitespace()
        .find_map(|token| token.strip_prefix(key)?.strip_prefix('=').map(str::to_owned))
}

fn field<'a>(fields: &'a [&str], index: usize, line: usize, name: &str) -> Result<&'a str> {
    fields
        .get(index)
        .copied()
        .with_context(|| format!("catalog line {line} has no {name} field"))
}

fn check_sha256(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
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

    fn catalog_bytes(body: &str) -> Vec<u8> {
        format!(
            "#id\tkind\toracle_id\tgeneration\tmetadata: v=3 cards={} body_sha256={}\n{body}",
            body.lines().count(),
            hex_sha256(body.as_bytes())
        )
        .into_bytes()
    }

    fn sample_catalog() -> CatalogSource {
        let bytes = catalog_bytes(&format!("1\tcard\t{ORACLE_A}\t1\n2\ttoken\t\t2\n"));
        parse_catalog(&bytes, hex_sha256(&bytes)).unwrap()
    }

    fn card(json: &str) -> scryfall_bulk::ScryfallCard {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn catalog_parser_requires_dense_checked_card_and_token_rows() {
        let valid = catalog_bytes(&format!("1\tcard\t{ORACLE_A}\t1\n2\ttoken\t\t2\n"));
        assert_eq!(parse_catalog(&valid, hex_sha256(&valid)).unwrap().rows.len(), 2);

        let sparse = catalog_bytes(&format!("1\tcard\t{ORACLE_A}\t1\n3\ttoken\t\t2\n"));
        assert!(parse_catalog(&sparse, hex_sha256(&sparse)).is_err());

        let named_token = catalog_bytes(&format!("1\tcard\t{ORACLE_A}\t1\n2\ttoken\t{ORACLE_A}\t2\n"));
        assert!(parse_catalog(&named_token, hex_sha256(&named_token)).is_err());
    }

    #[test]
    fn multi_face_scryfall_bodies_preserve_face_order_and_empty_slots() {
        let value = card(
            r#"{"name":"A // B","lang":"en","layout":"transform","card_faces":[{"name":"A","oracle_text":"Front."},{"name":"B","oracle_text":"Back."}]}"#,
        );
        assert_eq!(scryfall_body(&value).as_deref(), Some("Front.\n\nBack."));

        let empty_front = card(
            r#"{"name":"A // B","lang":"en","layout":"transform","card_faces":[{"name":"A","oracle_text":""},{"name":"B","oracle_text":"Back."}]}"#,
        );
        assert_eq!(scryfall_body(&empty_front).as_deref(), Some("\n\nBack."));
    }

    #[test]
    fn token_bodies_decode_script_escapes_and_preserve_double_faces() {
        assert_eq!(
            token_presentation_body("Name:X\nOracle:Flying\\nCrew 3\n")
                .unwrap()
                .as_deref(),
            Some("Flying\nCrew 3")
        );
        assert_eq!(
            token_presentation_body(
                "Name:Front\nAlternateMode:DoubleFaced\nOracle:Transform.\nALTERNATE\nName:Back\nOracle:\n"
            )
            .unwrap()
            .as_deref(),
            Some("Transform.\n\n")
        );
        assert!(token_presentation_body("Name:X\n").is_err());
        assert!(token_presentation_body("Name:X\nOracle:bad\\q\n").is_err());
    }

    #[test]
    fn ss4_escape_round_trip_is_canonical() {
        let body = "First\\line\nSecond\tcolumn";
        assert_eq!(unescape_body(&escape_body(body)).unwrap(), body);
        assert!(unescape_body("bad\\q").is_err());
    }

    #[test]
    fn sparse_table_is_stamped_sorted_and_self_verifying() {
        let catalog = sample_catalog();
        let bodies = BTreeMap::from([(2, "Token body".to_owned())]);
        let document = render_body_catalog(&catalog, &bodies).unwrap();
        assert_eq!(verify_body_catalog(&document, &catalog).unwrap(), 1);
        let text = String::from_utf8(document).unwrap();
        assert!(text.contains("kind=body-skin"));
        assert!(text.ends_with("2\tToken body\n"));
    }

    #[test]
    fn verifier_rejects_bad_stamp_checksum_order_and_escape() {
        let catalog = sample_catalog();
        let good = render_body_catalog(&catalog, &BTreeMap::from([(1, "A".to_owned()), (2, "B".to_owned())])).unwrap();

        let wrong_catalog = CatalogSource {
            identity: "0".repeat(64),
            rows: catalog.rows.clone(),
        };
        assert!(verify_body_catalog(&good, &wrong_catalog).is_err());

        let bad_order_body = "2\tB\n1\tA\n";
        let bad_order = format!(
            "#id\tbody\tmetadata: v=1 kind=body-skin catalog_identity={} cards=2 body_sha256={}\n{bad_order_body}",
            catalog.identity,
            hex_sha256(bad_order_body.as_bytes())
        );
        assert!(verify_body_catalog(bad_order.as_bytes(), &catalog).is_err());

        let bad_escape_body = "1\tbad\\q\n";
        let bad_escape = format!(
            "#id\tbody\tmetadata: v=1 kind=body-skin catalog_identity={} cards=1 body_sha256={}\n{bad_escape_body}",
            catalog.identity,
            hex_sha256(bad_escape_body.as_bytes())
        );
        assert!(verify_body_catalog(bad_escape.as_bytes(), &catalog).is_err());
    }
}
