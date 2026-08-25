#!/usr/bin/env rust-script
//! ```cargo
//! [package]
//! edition = "2021"
//!
//! [dependencies]
//! anyhow = "1.0.99"
//! clap = { version = "4.5.45", features = ["derive"] }
//! sha2 = "0.10.9"
//! uuid = "1.18.0"
//! ```
//!
//! Two title-free join tables are published side by side:
//!
//! * `catalog_ids.tsv` — one row per card: numeric id, Oracle UUID, the
//!   SHA-256 of the card's REGISTRY SPELLING, and the anonymous set group.
//! * `catalog_face_ids.tsv` — one row per SINGLE-FACE spelling of a
//!   multi-face card ("Front" for "Front // Back"),
//!   digested exactly the same way, so a caller holding only a face name can
//!   still find the host card's id.
//!
//! Neither table redistributes a title: both carry one-way digests only.
//! Both are published at the corpus root and are EXCLUDED from the packed
//! cardset tarball (`pack_cardset.rs` packs `manifest.json` plus the `cards/`
//! and `tokens/` tries and nothing else), so adding the face table changes no
//! cardset content id.

use anyhow::{bail, Context, Result};
use clap::Parser;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(about = "Extract the anonymous numeric/Oracle identity bridge from DeepScry's catalog")]
struct Args {
    /// DeepScry card_catalog.tsv containing id, name, and oracle_id columns.
    ///
    /// An anonymized catalog cannot regenerate these name-derived tables because
    /// it no longer contains names, and that is the point of anonymizing it.
    /// Rejecting that input is therefore correct behavior, not a missing-data
    /// fallback: callers must supply the historical title-bearing catalog that
    /// corresponds to the table they are reproducing.
    #[arg(long)]
    source: PathBuf,

    /// Anonymous output consumed by generate_uuid_trie.rs.
    #[arg(long, default_value = "catalog_ids.tsv")]
    output: PathBuf,

    /// Anonymous single-face spelling index, written alongside `--output`.
    #[arg(long, default_value = "catalog_face_ids.tsv")]
    face_output: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let source =
        fs::read_to_string(&args.source).with_context(|| format!("read DeepScry catalog {}", args.source.display()))?;
    let rows = parse_catalog(&source)?;
    let faces = face_index(&rows);
    publish(&args.output, &render_identity_table(&rows), "anonymous catalog")?;
    publish(&args.face_output, &render_face_table(&faces), "anonymous face index")?;
    let ambiguous = faces.values().filter(|entry| **entry == FaceOwner::Ambiguous).count();
    eprintln!(
        "Wrote {} ({} cards) and {} ({} face spellings, {} refused as ambiguous)",
        args.output.display(),
        rows.len(),
        args.face_output.display(),
        faces.len(),
        ambiguous
    );
    Ok(())
}

/// Write `text` to `path` through a temporary file so a failed run never
/// leaves a half-written table where a complete one used to be.
fn publish(path: &Path, text: &str, what: &str) -> Result<()> {
    let temporary = path.with_extension("write-part");
    fs::write(&temporary, text).with_context(|| format!("write temporary {what} {}", temporary.display()))?;
    fs::rename(&temporary, path).with_context(|| format!("publish {what} {}", path.display()))
}

/// One validated row of DeepScry's card catalog.
#[derive(Debug, Clone)]
struct CatalogRow {
    id: u32,
    /// The registry spelling. For a multi-face card this is the combined
    /// `"A // B"` form, which is what the face index is derived from.
    name: String,
    /// Additional spellings the registry accepts for the same id, carried in
    /// the catalog's `flags` column as `alias=<spelling>`.
    aliases: Vec<String>,
    oracle_id: Uuid,
    set_group: String,
}

impl CatalogRow {
    /// Every spelling this row owns: its registry name first, then aliases.
    fn spellings(&self) -> impl Iterator<Item = &String> {
        std::iter::once(&self.name).chain(self.aliases.iter())
    }
}

/// Who a spelling belongs to, for both the full-name and the face index.
///
/// A spelling several distinct cards share cannot be resolved: handing it to
/// one of them would hand that card another card's identity. It is recorded
/// as ambiguous and refused instead of silently picked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FaceOwner {
    Unique(u32),
    Ambiguous,
}

/// Read and validate DeepScry's catalog into rows.
fn parse_catalog(source: &str) -> Result<Vec<CatalogRow>> {
    let mut lines = source.lines();
    let header = lines.next().context("DeepScry catalog is empty")?;
    let columns: Vec<&str> = header.split('\t').collect();
    let id_column = column_index(&columns, "#id")?;
    let name_column = column_index(&columns, "name")?;
    let first_set_column = column_index(&columns, "first_set")?;
    let oracle_id_column = column_index(&columns, "oracle_id")?;
    // The flags column is optional: older catalogs predate it, and a row with
    // no flags simply owns no aliases.
    let flags_column = columns.iter().position(|column| *column == "flags");

    let mut rows = Vec::new();
    let mut ids = BTreeSet::new();
    let mut identities = HashSet::new();
    for (offset, line) in lines.enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let line_number = offset + 2;
        let fields: Vec<&str> = line.split('\t').collect();
        let id: u32 = field(&fields, id_column, line_number, "id")?
            .parse()
            .with_context(|| format!("invalid numeric id on line {line_number}"))?;
        if id == 0 || !ids.insert(id) {
            bail!("line {line_number} has zero or duplicate numeric id {id}");
        }
        let name = field(&fields, name_column, line_number, "name")?;
        if name.is_empty() {
            bail!("line {line_number} has an empty card name");
        }
        let oracle_id = field(&fields, oracle_id_column, line_number, "oracle_id")?
            .parse::<Uuid>()
            .with_context(|| format!("invalid oracle UUID on line {line_number}"))?;
        let name_hash = hex_sha256(name.as_bytes());
        let first_set = field(&fields, first_set_column, line_number, "first_set")?;
        if !identities.insert((oracle_id, name_hash)) {
            bail!("line {line_number} duplicates an Oracle UUID/name identity");
        }
        let aliases = match flags_column {
            Some(index) => parse_aliases(fields.get(index).copied().unwrap_or_default(), line_number)?,
            None => Vec::new(),
        };
        rows.push(CatalogRow {
            id,
            name: name.to_owned(),
            aliases,
            oracle_id,
            set_group: anonymous_set_group(first_set),
        });
    }
    if rows.is_empty() {
        bail!("DeepScry catalog contains no card rows");
    }
    Ok(rows)
}

/// `alias=<spelling>` entries out of the catalog's `;`-separated flags column.
///
/// Unknown flags are DeepScry's business, not this generator's, so they are
/// passed over; an `alias=` with nothing after it is malformed and fails.
fn parse_aliases(flags: &str, line_number: usize) -> Result<Vec<String>> {
    let mut aliases = Vec::new();
    for flag in flags.split(';').filter(|flag| !flag.is_empty()) {
        if let Some(alias) = flag.strip_prefix("alias=") {
            if alias.is_empty() {
                bail!("line {line_number} has an empty alias= flag");
            }
            aliases.push(alias.to_owned());
        }
    }
    Ok(aliases)
}

/// The single-face spelling index, digest -> owner.
///
/// This REPRODUCES DeepScry's own derived face index (`CardCatalog`, in
/// `src/engine/src/card_catalog.rs`) so the anonymized corpus resolves face
/// names exactly the way the titled catalog does. Two rules, both load-bearing:
///
/// 1. **A full card spelling owns its spelling.** A face that is also some
///    card's registry name or alias is left out entirely, so the full-name
///    table answers it and the face table never overrides it.
/// 2. **A face two different cards share is ambiguous**, and recorded as such
///    so the consumer refuses rather than resolving to whichever came first.
fn face_index(rows: &[CatalogRow]) -> BTreeMap<String, FaceOwner> {
    let mut full_spellings: HashSet<&str> = HashSet::new();
    for row in rows {
        for spelling in row.spellings() {
            full_spellings.insert(spelling.as_str());
        }
    }
    let mut faces: HashMap<&str, FaceOwner> = HashMap::new();
    for row in rows {
        for spelling in row.spellings() {
            if !spelling.contains(FACE_SEPARATOR) {
                continue;
            }
            for face in spelling.split(FACE_SEPARATOR) {
                if face.is_empty() || full_spellings.contains(face) {
                    continue; // rule 1: a full card spelling owns this name
                }
                faces
                    .entry(face)
                    .and_modify(|owner| {
                        if *owner != FaceOwner::Unique(row.id) {
                            *owner = FaceOwner::Ambiguous; // rule 2
                        }
                    })
                    .or_insert(FaceOwner::Unique(row.id));
            }
        }
    }
    // Keyed by digest, sorted, so the published table is byte-deterministic
    // and carries no plaintext face names.
    faces
        .into_iter()
        .map(|(face, owner)| (hex_sha256(face.as_bytes()), owner))
        .collect()
}

/// The face separator DeepScry's registry uses in combined names.
const FACE_SEPARATOR: &str = " // ";

const IDENTITY_HEADER: &str = "#id\toracle_id\tname_sha256\tset_group";
const FACE_HEADER: &str = "#face_sha256\tid";
/// The `id` cell of a face several cards share.
const AMBIGUOUS: &str = "ambiguous";

fn render_identity_table(rows: &[CatalogRow]) -> String {
    let mut output = format!("{IDENTITY_HEADER}\n");
    for row in rows {
        output.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            row.id,
            row.oracle_id.hyphenated(),
            hex_sha256(row.name.as_bytes()),
            row.set_group
        ));
    }
    output
}

fn render_face_table(faces: &BTreeMap<String, FaceOwner>) -> String {
    let mut output = format!("{FACE_HEADER}\n");
    for (digest, owner) in faces {
        match owner {
            FaceOwner::Unique(id) => output.push_str(&format!("{digest}\t{id}\n")),
            FaceOwner::Ambiguous => output.push_str(&format!("{digest}\t{AMBIGUOUS}\n")),
        }
    }
    output
}

fn column_index(columns: &[&str], wanted: &str) -> Result<usize> {
    columns
        .iter()
        .position(|column| *column == wanted)
        .with_context(|| format!("DeepScry catalog header has no {wanted:?} column"))
}

fn field<'a>(fields: &'a [&str], index: usize, line_number: usize, name: &str) -> Result<&'a str> {
    fields
        .get(index)
        .copied()
        .with_context(|| format!("catalog line {line_number} has no {name} field"))
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn anonymous_set_group(set_code: &str) -> String {
    format!(
        "G{}",
        &hex_sha256(set_code.trim().to_ascii_uppercase().as_bytes())[..16]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extract_catalog(source: &str) -> Result<String> {
        Ok(render_identity_table(&parse_catalog(source)?))
    }

    fn faces_of(source: &str) -> BTreeMap<String, FaceOwner> {
        face_index(&parse_catalog(source).unwrap())
    }

    fn owner_of(faces: &BTreeMap<String, FaceOwner>, face: &str) -> Option<FaceOwner> {
        faces.get(&hex_sha256(face.as_bytes())).copied()
    }

    #[test]
    fn extracts_only_identity_and_one_way_name_digest() {
        let source = "#id\tname\tfirst_set\toracle_id\tgeneration\tflags\n1\tExample Card\tset\t12345678-1234-1234-1234-123456789abc\t1\t\n";
        let output = extract_catalog(source).unwrap();
        assert!(output.starts_with("#id\toracle_id\tname_sha256\tset_group\n1\t12345678-1234-1234-1234-123456789abc\t"));
        assert!(!output.contains("Example Card"));
        assert!(output.ends_with("\tG2992d15897b5bbe7\n"));
    }

    #[test]
    fn rejects_duplicate_numeric_ids() {
        let source = "#id\tname\toracle_id\n1\tA\t12345678-1234-1234-1234-123456789abc\n1\tB\t22345678-1234-1234-1234-123456789abc\n";
        assert!(extract_catalog(source).is_err());
    }

    /// A two-face card publishes a digest for each single-face spelling, both
    /// pointing at the host card, and the table carries no plaintext.
    #[test]
    fn each_face_of_a_two_faced_card_resolves_to_its_host() {
        let source = "#id\tname\tfirst_set\toracle_id\tgeneration\tflags\n\
            1\tQzx One // Qzx Two\teld\t12345678-1234-1234-1234-123456789abc\t1\t\n";
        let faces = faces_of(source);
        assert_eq!(owner_of(&faces, "Qzx One"), Some(FaceOwner::Unique(1)));
        assert_eq!(owner_of(&faces, "Qzx Two"), Some(FaceOwner::Unique(1)));
        assert_eq!(faces.len(), 2);
        let rendered = render_face_table(&faces);
        assert!(rendered.starts_with("#face_sha256\tid\n"));
        assert!(!rendered.contains("Qzx"));
    }

    /// A single-faced card contributes nothing: there is no face spelling
    /// distinct from the registry spelling, which the identity table answers.
    #[test]
    fn a_single_faced_card_contributes_no_face_rows() {
        let source = "#id\tname\tfirst_set\toracle_id\tgeneration\tflags\n\
            1\tQzx One\teld\t12345678-1234-1234-1234-123456789abc\t1\t\n";
        assert!(faces_of(source).is_empty());
    }

    /// Rule 1: a face spelling that is also some card's full registry name is
    /// left out, so the full-name table stays the answer for it.
    #[test]
    fn a_full_card_name_owns_its_spelling_against_a_face() {
        let source = "#id\tname\tfirst_set\toracle_id\tgeneration\tflags\n\
            1\tQzx One\teld\t12345678-1234-1234-1234-123456789abc\t1\t\n\
            2\tQzx One // Qzx Two\teld\t22345678-1234-1234-1234-123456789abc\t1\t\n";
        let faces = faces_of(source);
        assert_eq!(owner_of(&faces, "Qzx One"), None);
        assert_eq!(owner_of(&faces, "Qzx Two"), Some(FaceOwner::Unique(2)));
    }

    /// Rule 2: a face two different cards share is refused, not resolved to
    /// whichever card the generator happened to read first.
    #[test]
    fn a_face_shared_by_two_cards_is_recorded_ambiguous() {
        let source = "#id\tname\tfirst_set\toracle_id\tgeneration\tflags\n\
            1\tQzx Shared // Qzx Two\teld\t12345678-1234-1234-1234-123456789abc\t1\t\n\
            2\tQzx Shared // Qzx Three\teld\t22345678-1234-1234-1234-123456789abc\t1\t\n";
        let faces = faces_of(source);
        assert_eq!(owner_of(&faces, "Qzx Shared"), Some(FaceOwner::Ambiguous));
        assert_eq!(owner_of(&faces, "Qzx Two"), Some(FaceOwner::Unique(1)));
        assert_eq!(owner_of(&faces, "Qzx Three"), Some(FaceOwner::Unique(2)));
        let rendered = render_face_table(&faces);
        assert_eq!(rendered.lines().filter(|line| line.ends_with("\tambiguous")).count(), 1);
    }

    /// One card repeating the same face on both sides is still that one card;
    /// only a COLLISION BETWEEN CARDS is ambiguous.
    #[test]
    fn one_card_repeating_a_face_on_both_sides_stays_unique() {
        let source = "#id\tname\tfirst_set\toracle_id\tgeneration\tflags\n\
            1\tQzx Twin // Qzx Twin\teld\t12345678-1234-1234-1234-123456789abc\t1\t\n";
        assert_eq!(owner_of(&faces_of(source), "Qzx Twin"), Some(FaceOwner::Unique(1)));
    }

    /// Aliases participate on both sides, exactly as they do in DeepScry's
    /// catalog: they contribute their own faces, and they own a spelling
    /// against a face the same way a registry name does.
    #[test]
    fn aliases_contribute_faces_and_own_spellings() {
        let source = "#id\tname\tfirst_set\toracle_id\tgeneration\tflags\n\
            1\tQzx Plain\teld\t12345678-1234-1234-1234-123456789abc\t1\talias=Qzx Alias // Qzx Aliased Back\n\
            2\tQzx Plain // Qzx Second\teld\t22345678-1234-1234-1234-123456789abc\t1\t\n";
        let faces = faces_of(source);
        assert_eq!(owner_of(&faces, "Qzx Alias"), Some(FaceOwner::Unique(1)));
        assert_eq!(owner_of(&faces, "Qzx Aliased Back"), Some(FaceOwner::Unique(1)));
        assert_eq!(owner_of(&faces, "Qzx Plain"), None, "a full registry name owns its spelling");
        assert_eq!(owner_of(&faces, "Qzx Second"), Some(FaceOwner::Unique(2)));
    }

    /// The two tables are generated from one parse of one file, so they can
    /// never disagree about which id a spelling belongs to.
    #[test]
    fn both_tables_come_from_the_same_parsed_rows() {
        let source = "#id\tname\tfirst_set\toracle_id\tgeneration\tflags\n\
            1\tQzx One // Qzx Two\teld\t12345678-1234-1234-1234-123456789abc\t1\t\n";
        let rows = parse_catalog(source).unwrap();
        let identity = render_identity_table(&rows);
        let combined_digest = hex_sha256("Qzx One // Qzx Two".as_bytes());
        assert!(identity.contains(&format!("\t{combined_digest}\t")));
        assert_eq!(owner_of(&face_index(&rows), "Qzx One"), Some(FaceOwner::Unique(1)));
    }
}
