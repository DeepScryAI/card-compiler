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
//! uuid = { version = "1.18.0", features = ["serde"] }
//! ```

use anyhow::{bail, Context, Result};
use clap::Parser;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::BufWriter;
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;

#[path = "../lib/scryfall_bulk.rs"]
mod scryfall_bulk;

use scryfall_bulk::ScryfallCard;

#[derive(Parser, Debug)]
#[command(about = "Extract an uncommitted presentation skin keyed by numeric card ID")]
struct Args {
    /// Decompressed Scryfall default_cards cache.
    #[arg(long, default_value = ".cache/scryfall/default_cards.json")]
    cache: PathBuf,

    /// Anonymous numeric/Oracle identity bridge.
    #[arg(long, default_value = "catalog_ids.tsv")]
    catalog: PathBuf,

    /// Generated name and Oracle-text table. The default is gitignored.
    #[arg(long, default_value = ".cache/card-skins/default.json")]
    output: PathBuf,

    /// Ignore a present cache and download the current snapshot.
    #[arg(long)]
    refresh: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SkinText {
    title: String,
    oracle_text: Option<String>,
}

#[derive(Debug, Serialize)]
struct CardSkinEntry {
    card_id: u32,
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    oracle_text: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    validate_output_path(&args.output)?;
    scryfall_bulk::ensure_cache(&args.cache, args.refresh)?;

    let catalog = load_catalog(&args.catalog)?;
    let mut by_oracle_id = BTreeMap::new();
    let mut conflicts = BTreeSet::new();
    scryfall_bulk::for_each_card(&args.cache, |card| {
        let Some(oracle_id) = card.oracle_id else {
            return;
        };
        if !catalog.contains_key(&oracle_id) {
            return;
        }
        let skin = skin_text(&card);
        match by_oracle_id.get(&oracle_id) {
            Some(previous) if previous != &skin => {
                conflicts.insert(oracle_id);
            }
            None => {
                by_oracle_id.insert(oracle_id, skin);
            }
            _ => {}
        }
    })?;

    let missing: Vec<_> = catalog
        .keys()
        .filter(|oracle_id| !by_oracle_id.contains_key(oracle_id))
        .collect();
    if !missing.is_empty() {
        bail!(
            "Scryfall cache has no English presentation record for {} catalog Oracle identities (first: {})",
            missing.len(),
            missing[0]
        );
    }
    if !conflicts.is_empty() {
        bail!(
            "Scryfall cache contains conflicting presentation records for {} Oracle identities (first: {})",
            conflicts.len(),
            conflicts.iter().next().expect("nonempty conflict set")
        );
    }

    let mut entries = Vec::with_capacity(catalog.values().map(Vec::len).sum());
    for (oracle_id, card_ids) in catalog {
        let skin = by_oracle_id
            .remove(&oracle_id)
            .with_context(|| format!("missing validated skin for Oracle identity {oracle_id}"))?;
        for card_id in card_ids {
            entries.push(CardSkinEntry {
                card_id,
                title: skin.title.clone(),
                oracle_text: skin.oracle_text.clone(),
            });
        }
    }
    entries.sort_unstable_by_key(|entry| entry.card_id);
    write_entries(&args.output, &entries)?;
    eprintln!(
        "Wrote {} presentation records to {} (uncommitted skin data)",
        entries.len(),
        args.output.display()
    );
    Ok(())
}

fn validate_output_path(output: &Path) -> Result<()> {
    if output.as_os_str().is_empty() || output == Path::new("/") {
        bail!("refusing unsafe output path: {}", output.display());
    }
    if output
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        bail!("output path may not contain '..': {}", output.display());
    }
    Ok(())
}

fn load_catalog(path: &Path) -> Result<BTreeMap<Uuid, Vec<u32>>> {
    let source = fs::read_to_string(path).with_context(|| format!("read catalog {}", path.display()))?;
    load_catalog_text(&source)
}

fn load_catalog_text(source: &str) -> Result<BTreeMap<Uuid, Vec<u32>>> {
    let mut lines = source.lines();
    let header = lines.next().context("catalog is empty")?;
    let columns: Vec<_> = header.split('\t').collect();
    let id_column = column_index(&columns, "#id")?;
    let oracle_id_column = column_index(&columns, "oracle_id")?;
    let mut ids = BTreeSet::new();
    let mut catalog: BTreeMap<Uuid, Vec<u32>> = BTreeMap::new();

    for (offset, line) in lines.enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let line_number = offset + 2;
        let fields: Vec<_> = line.split('\t').collect();
        let card_id: u32 = field(&fields, id_column, line_number, "id")?
            .parse()
            .with_context(|| format!("invalid numeric card ID on catalog line {line_number}"))?;
        if card_id == 0 || !ids.insert(card_id) {
            bail!("catalog line {line_number} has zero or duplicate numeric card ID {card_id}");
        }
        let oracle_id = field(&fields, oracle_id_column, line_number, "oracle_id")?
            .parse::<Uuid>()
            .with_context(|| format!("invalid Oracle UUID on catalog line {line_number}"))?;
        catalog.entry(oracle_id).or_default().push(card_id);
    }
    if catalog.is_empty() {
        bail!("catalog contains no card rows");
    }
    Ok(catalog)
}

fn column_index(columns: &[&str], wanted: &str) -> Result<usize> {
    columns
        .iter()
        .position(|column| *column == wanted)
        .with_context(|| format!("catalog header has no {wanted:?} column"))
}

fn field<'a>(fields: &'a [&str], index: usize, line_number: usize, name: &str) -> Result<&'a str> {
    fields
        .get(index)
        .copied()
        .with_context(|| format!("catalog line {line_number} has no {name} field"))
}

fn skin_text(card: &ScryfallCard) -> SkinText {
    let oracle_text = card
        .oracle_text
        .as_deref()
        .and_then(nonempty_trimmed)
        .map(str::to_owned)
        .or_else(|| {
            let faces: Vec<_> = card
                .card_faces
                .iter()
                .filter_map(|face| face.oracle_text.as_deref().and_then(nonempty_trimmed))
                .collect();
            (!faces.is_empty()).then(|| faces.join("\n\n"))
        });
    SkinText {
        title: card.name.trim().to_owned(),
        oracle_text,
    }
}

fn nonempty_trimmed(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then_some(trimmed)
}

fn write_entries(path: &Path, entries: &[CardSkinEntry]) -> Result<()> {
    let parent = path.parent().context("skin output path has no parent directory")?;
    fs::create_dir_all(parent).with_context(|| format!("create skin output directory {}", parent.display()))?;
    let temporary = path.with_extension("write-part");
    let output = File::create(&temporary).with_context(|| format!("create {}", temporary.display()))?;
    serde_json::to_writer(BufWriter::new(output), entries).context("serialize card skin JSON")?;
    fs::rename(&temporary, path).with_context(|| format!("publish card skin {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card(json: &str) -> ScryfallCard {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn catalog_allows_multiple_numeric_ids_for_one_oracle_identity() {
        let catalog = load_catalog_text(
            "#id\toracle_id\tname_sha256\tset_group\n7\t12345678-1234-1234-1234-123456789abc\tx\ty\n9\t12345678-1234-1234-1234-123456789abc\tx\ty\n",
        )
        .unwrap();
        assert_eq!(catalog.values().next().unwrap(), &[7, 9]);
    }

    #[test]
    fn multi_face_oracle_text_is_joined_in_face_order() {
        let value = card(
            r#"{"oracle_id":"12345678-1234-1234-1234-123456789abc","name":"Fixture Alpha // Fixture Beta","lang":"en","layout":"transform","card_faces":[{"name":"Fixture Alpha","oracle_text":"First face text."},{"name":"Fixture Beta","oracle_text":"Second face text."}]}"#,
        );
        assert_eq!(
            skin_text(&value),
            SkinText {
                title: "Fixture Alpha // Fixture Beta".to_owned(),
                oracle_text: Some("First face text.\n\nSecond face text.".to_owned()),
            }
        );
    }

    #[test]
    fn top_level_oracle_text_is_preserved_without_faces() {
        let value = card(
            r#"{"oracle_id":"12345678-1234-1234-1234-123456789abc","name":"Fixture Gamma","oracle_text":"Display-only rules text.","lang":"en","layout":"normal"}"#,
        );
        assert_eq!(
            skin_text(&value).oracle_text.as_deref(),
            Some("Display-only rules text.")
        );
    }
}
