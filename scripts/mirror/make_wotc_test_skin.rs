#!/usr/bin/env rust-script
//! ```cargo
//! [package]
//! edition = "2021"
//!
//! [dependencies]
//! anyhow = "1.0.99"
//! clap = { version = "4.5.45", features = ["derive"] }
//! serde_json = "1.0.143"
//! sha2 = "0.10.9"
//! ```
//!
//! Build the local-only human-test variant of the WotC presentation skin.
//! Every title face and every body begins with `TEST `; catalog identities,
//! row ordering, table structure, and the skin's non-presentation members
//! stay unchanged.

use anyhow::{bail, Context, Result};
use clap::Parser;
use serde_json::Value;
use std::fs;
use std::path::{Component, Path, PathBuf};

#[path = "lib/cas.rs"]
mod cas;

const PREFIX: &str = "TEST ";
const TITLES_FILENAME: &str = "title_catalog.tsv";
const BODIES_FILENAME: &str = "body_catalog.tsv";
const MANIFEST_FILENAME: &str = "wotc-test.skin.json";

#[derive(Parser, Debug)]
#[command(about = "Build a local WotC TEST skin whose titles and bodies are visibly prefixed")]
struct Args {
    /// Existing WotC skin manifest whose non-title/body members are retained.
    #[arg(long, default_value = "presentation/skins/wotc.skin.json")]
    source_manifest: PathBuf,

    /// Existing WotC SS3 title table.
    #[arg(long, default_value = "presentation/title_catalog.tsv")]
    titles: PathBuf,

    /// Existing WotC SS4 body table.
    #[arg(long, default_value = "presentation/body_catalog.tsv")]
    bodies: PathBuf,

    /// Local ignored output directory. No generated skin is committed.
    #[arg(long, default_value = ".cache/generated-skins/wotc-test")]
    output_dir: PathBuf,

    /// Recompute and byte-verify the existing output instead of writing it.
    #[arg(long)]
    verify: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TableKind {
    Titles,
    Bodies,
}

impl TableKind {
    fn label(self) -> &'static str {
        match self {
            Self::Titles => "title",
            Self::Bodies => "body",
        }
    }

    fn expected_header(self) -> &'static str {
        match self {
            Self::Titles => "#id\ttitle\tmetadata:",
            Self::Bodies => "#id\tbody\tmetadata:",
        }
    }
}

struct GeneratedSkin {
    titles: Vec<u8>,
    bodies: Vec<u8>,
    manifest: Vec<u8>,
    title_rows: usize,
    body_rows: usize,
}

fn main() -> Result<()> {
    let args = Args::parse();
    require_local_cache_output(&args.output_dir)?;
    let generated = build_skin(&args.source_manifest, &args.titles, &args.bodies)?;
    let titles_path = args.output_dir.join(TITLES_FILENAME);
    let bodies_path = args.output_dir.join(BODIES_FILENAME);
    let manifest_path = args.output_dir.join(MANIFEST_FILENAME);

    if args.verify {
        verify_file(&titles_path, &generated.titles)?;
        verify_file(&bodies_path, &generated.bodies)?;
        verify_file(&manifest_path, &generated.manifest)?;
        eprintln!("Verified {}", args.output_dir.display());
    } else {
        fs::create_dir_all(&args.output_dir)
            .with_context(|| format!("create {}", args.output_dir.display()))?;
        write_atomically(&titles_path, &generated.titles)?;
        write_atomically(&bodies_path, &generated.bodies)?;
        // Publish the manifest last: readers never observe a new manifest
        // pointing at tables that have not been written yet.
        write_atomically(&manifest_path, &generated.manifest)?;
        eprintln!("Wrote {}", args.output_dir.display());
    }

    println!("skin_manifest_path={}", manifest_path.display());
    println!(
        "skin_manifest_cid={}",
        cas::cid_for_bytes(&generated.manifest)
    );
    println!("titles_path={}", titles_path.display());
    println!("titles_rows={}", generated.title_rows);
    println!("bodies_path={}", bodies_path.display());
    println!("bodies_rows={}", generated.body_rows);
    Ok(())
}

fn require_local_cache_output(output_dir: &Path) -> Result<()> {
    let mut components = output_dir.components();
    if components.next() != Some(Component::Normal(".cache".as_ref()))
        || components.any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!(
            "--output-dir {} must be a relative path beneath .cache/; generated skins are local and must never enter tracked presentation data",
            output_dir.display()
        );
    }
    Ok(())
}

fn build_skin(
    source_manifest_path: &Path,
    titles_path: &Path,
    bodies_path: &Path,
) -> Result<GeneratedSkin> {
    let source_manifest = fs::read(source_manifest_path)
        .with_context(|| format!("read source manifest {}", source_manifest_path.display()))?;
    let source_titles =
        fs::read(titles_path).with_context(|| format!("read titles {}", titles_path.display()))?;
    let source_bodies =
        fs::read(bodies_path).with_context(|| format!("read bodies {}", bodies_path.display()))?;

    let (titles, title_rows) = transform_table(&source_titles, TableKind::Titles)
        .with_context(|| format!("transform titles {}", titles_path.display()))?;
    let (bodies, body_rows) = transform_table(&source_bodies, TableKind::Bodies)
        .with_context(|| format!("transform bodies {}", bodies_path.display()))?;
    let manifest = transform_manifest(
        &source_manifest,
        &source_titles,
        &source_bodies,
        &titles,
        &bodies,
    )
    .with_context(|| {
        format!(
            "transform source manifest {}",
            source_manifest_path.display()
        )
    })?;

    Ok(GeneratedSkin {
        titles,
        bodies,
        manifest,
        title_rows,
        body_rows,
    })
}

fn transform_table(source: &[u8], kind: TableKind) -> Result<(Vec<u8>, usize)> {
    let text = std::str::from_utf8(source).context("table is not UTF-8")?;
    if !text.ends_with('\n') {
        bail!("{} table must end with a newline", kind.label());
    }
    let (header, body) = text.split_once('\n').context("table is empty")?;
    if !header.starts_with(kind.expected_header()) {
        bail!(
            "{} table has an unexpected header: {header:?}",
            kind.label()
        );
    }

    let declared_rows = metadata_usize(header, "cards")?;
    let declared_hash = metadata_value(header, "body_sha256")?;
    let actual_hash = cas::sha256_hex(body.as_bytes());
    if declared_hash != actual_hash {
        bail!(
            "{} table body_sha256 mismatch: header declares {declared_hash}, body hashes to {actual_hash}",
            kind.label()
        );
    }

    let mut transformed_body = String::with_capacity(body.len() + declared_rows * PREFIX.len());
    let mut previous_id = 0_u32;
    let mut rows = 0_usize;
    for (offset, line) in body.lines().enumerate() {
        let line_number = offset + 2;
        let (raw_id, value) = line.split_once('\t').with_context(|| {
            format!(
                "{} table line {line_number} has no value column",
                kind.label()
            )
        })?;
        if value.contains('\t') {
            bail!(
                "{} table line {line_number} has more than two columns",
                kind.label()
            );
        }
        let id: u32 = raw_id.parse().with_context(|| {
            format!(
                "{} table line {line_number} has non-numeric ID {raw_id:?}",
                kind.label()
            )
        })?;
        if id <= previous_id {
            bail!(
                "{} table IDs are not strictly ascending at line {line_number}",
                kind.label()
            );
        }
        if kind == TableKind::Titles {
            let expected = u32::try_from(rows + 1).context("title table is larger than u32")?;
            if id != expected {
                bail!("title table is not dense: expected ID {expected}, found {id}");
            }
        }
        if value.is_empty() {
            bail!(
                "{} table line {line_number} has a blank value",
                kind.label()
            );
        }

        transformed_body.push_str(raw_id);
        transformed_body.push('\t');
        match kind {
            TableKind::Titles => {
                transformed_body.push_str(&prefix_title_faces(value, line_number)?)
            }
            TableKind::Bodies => {
                transformed_body.push_str(&prefix_once(value, "body", line_number)?)
            }
        }
        transformed_body.push('\n');
        previous_id = id;
        rows += 1;
    }
    if rows != declared_rows {
        bail!(
            "{} table has {rows} rows; header declares {declared_rows}",
            kind.label()
        );
    }

    let transformed_hash = cas::sha256_hex(transformed_body.as_bytes());
    let transformed_header = replace_metadata_value(header, "body_sha256", &transformed_hash)?;
    let mut document = transformed_header.into_bytes();
    document.push(b'\n');
    document.extend_from_slice(transformed_body.as_bytes());
    Ok((document, rows))
}

fn prefix_title_faces(value: &str, line_number: usize) -> Result<String> {
    value
        .split(" // ")
        .map(|face| prefix_once(face, "title face", line_number))
        .collect::<Result<Vec<_>>>()
        .map(|faces| faces.join(" // "))
}

fn prefix_once(value: &str, subject: &str, line_number: usize) -> Result<String> {
    if value.is_empty() {
        bail!("{subject} at line {line_number} is blank");
    }
    if value.starts_with(PREFIX) {
        bail!("{subject} at line {line_number} already starts with {PREFIX:?}; refusing a double prefix");
    }
    Ok(format!("{PREFIX}{value}"))
}

fn transform_manifest(
    source_manifest: &[u8],
    source_titles: &[u8],
    source_bodies: &[u8],
    titles: &[u8],
    bodies: &[u8],
) -> Result<Vec<u8>> {
    let mut manifest: Value =
        serde_json::from_slice(source_manifest).context("source manifest is not JSON")?;
    let object = manifest
        .as_object_mut()
        .context("source manifest is not a JSON object")?;
    if object.get("format").and_then(Value::as_str) != Some("deepscry-card-skin") {
        bail!("source manifest format is not deepscry-card-skin");
    }
    if object.get("version").and_then(Value::as_u64) != Some(1) {
        bail!("source manifest version is not 1");
    }
    verify_content_ref(object.get("titles"), source_titles, "titles")?;
    verify_content_ref(object.get("bodies"), source_bodies, "bodies")?;

    // Local preloading supplies the bytes by CID, so zero hints are complete
    // and avoid retaining upstream URLs that name different bytes.
    object.insert("titles".to_owned(), cas::content_ref(titles, &[]));
    object.insert("bodies".to_owned(), cas::content_ref(bodies, &[]));
    cas::jcs_canonicalize(&manifest).context("canonicalize WotC TEST manifest")
}

fn verify_content_ref(reference: Option<&Value>, bytes: &[u8], name: &str) -> Result<()> {
    let reference = reference.with_context(|| format!("source manifest has no {name} member"))?;
    let object = reference
        .as_object()
        .with_context(|| format!("source manifest {name} member is not an object"))?;
    let declared_cid = object
        .get("cid")
        .and_then(Value::as_str)
        .with_context(|| format!("source manifest {name}.cid is not a string"))?;
    let declared_size = object
        .get("size")
        .and_then(Value::as_u64)
        .with_context(|| format!("source manifest {name}.size is not an unsigned integer"))?;
    let actual_cid = cas::cid_for_bytes(bytes);
    if declared_cid != actual_cid || declared_size != bytes.len() as u64 {
        bail!(
            "source manifest {name} reference does not match supplied bytes: declared cid={declared_cid} size={declared_size}, actual cid={actual_cid} size={}",
            bytes.len()
        );
    }
    Ok(())
}

fn metadata_usize(header: &str, key: &str) -> Result<usize> {
    metadata_value(header, key)?
        .parse()
        .with_context(|| format!("table metadata {key}= is not an unsigned integer"))
}

fn metadata_value<'a>(header: &'a str, key: &str) -> Result<&'a str> {
    let prefix = format!("{key}=");
    let mut values = header
        .split_whitespace()
        .filter_map(|token| token.strip_prefix(&prefix));
    let value = values
        .next()
        .with_context(|| format!("table header has no {key}="))?;
    if values.next().is_some() {
        bail!("table header has duplicate {key}= metadata");
    }
    Ok(value)
}

fn replace_metadata_value(header: &str, key: &str, replacement: &str) -> Result<String> {
    let old = metadata_value(header, key)?;
    let needle = format!("{key}={old}");
    let replacement = format!("{key}={replacement}");
    if header.matches(&needle).count() != 1 {
        bail!("table header does not contain exactly one {needle:?}");
    }
    Ok(header.replacen(&needle, &replacement, 1))
}

fn write_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_extension("write-part");
    fs::write(&temporary, bytes).with_context(|| format!("write {}", temporary.display()))?;
    fs::rename(&temporary, path).with_context(|| format!("publish {}", path.display()))?;
    Ok(())
}

fn verify_file(path: &Path, expected: &[u8]) -> Result<()> {
    let actual =
        fs::read(path).with_context(|| format!("read generated output {}", path.display()))?;
    if actual != expected {
        bail!(
            "generated output {} does not match the current source artifacts",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(header: &str, body: &str) -> Vec<u8> {
        format!(
            "{header} cards={} body_sha256={}\n{body}",
            body.lines().count(),
            cas::sha256_hex(body.as_bytes())
        )
        .into_bytes()
    }

    fn titles(body: &str) -> Vec<u8> {
        table(
            "#id\ttitle\tmetadata: v=1 kind=title-only-skin catalog_identity=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            body,
        )
    }

    fn bodies(body: &str) -> Vec<u8> {
        table(
            "#id\tbody\tmetadata: v=1 kind=body-skin catalog_identity=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            body,
        )
    }

    fn source_manifest(title_bytes: &[u8], body_bytes: &[u8]) -> Vec<u8> {
        cas::jcs_canonicalize(&serde_json::json!({
            "format": "deepscry-card-skin",
            "version": 1,
            "cardset": {"cid": "cardset", "size": 7, "hints": []},
            "titles": cas::content_ref(title_bytes, &["https://example.test/titles".to_owned()]),
            "bodies": cas::content_ref(body_bytes, &["https://example.test/bodies".to_owned()]),
            "artpack": {"cid": "artpack", "size": 8, "hints": ["https://example.test/art"]},
        }))
        .unwrap()
    }

    #[test]
    fn local_output_must_stay_beneath_the_ignored_cache() {
        assert!(require_local_cache_output(Path::new(".cache/generated-skins/wotc-test")).is_ok());
        for unsafe_path in [
            "presentation/skins",
            ".",
            "../outside",
            ".cache/../presentation",
        ] {
            assert!(
                require_local_cache_output(Path::new(unsafe_path)).is_err(),
                "unsafe output path was accepted: {unsafe_path}"
            );
        }
    }

    #[test]
    fn prefixes_each_title_face_and_preserves_ids_and_metadata() {
        let source = titles("1\tFixture Qzx Front // Fixture Qzx Back\n2\tFixture Qzx Single\n");
        let (generated, rows) = transform_table(&source, TableKind::Titles).unwrap();
        let text = std::str::from_utf8(&generated).unwrap();
        assert_eq!(rows, 2);
        assert!(text.contains(
            "\n1\tTEST Fixture Qzx Front // TEST Fixture Qzx Back\n2\tTEST Fixture Qzx Single\n"
        ));
        assert!(text.contains(
            "catalog_identity=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
        let (_, body) = text.split_once('\n').unwrap();
        assert!(text.contains(&format!("body_sha256={}", cas::sha256_hex(body.as_bytes()))));
    }

    #[test]
    fn prefixes_encoded_body_without_changing_its_escapes() {
        let source = bodies("3\tSynthetic Qzx Alpha\\nSynthetic Qzx Beta\\tQzx Tab\\\\Qzx Slash\n");
        let (generated, rows) = transform_table(&source, TableKind::Bodies).unwrap();
        let text = std::str::from_utf8(&generated).unwrap();
        assert_eq!(rows, 1);
        assert!(text.ends_with(
            "3\tTEST Synthetic Qzx Alpha\\nSynthetic Qzx Beta\\tQzx Tab\\\\Qzx Slash\n"
        ));
    }

    #[test]
    fn rejects_an_already_prefixed_source_instead_of_doubling_it() {
        let error = transform_table(
            &titles("1\tTEST Fixture Qzx Already Marked\n"),
            TableKind::Titles,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("refusing a double prefix"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_a_stale_source_checksum() {
        let mut source = titles("1\tFixture Qzx One\n");
        let body_offset = source
            .windows(3)
            .position(|window| window == b"Qzx")
            .unwrap();
        source[body_offset] = b'X';
        let error = transform_table(&source, TableKind::Titles)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("body_sha256 mismatch"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn manifest_changes_only_title_and_body_references() {
        let source_titles = titles("1\tFixture Qzx One\n");
        let source_bodies = bodies("1\tSynthetic Qzx Body\n");
        let (test_titles, _) = transform_table(&source_titles, TableKind::Titles).unwrap();
        let (test_bodies, _) = transform_table(&source_bodies, TableKind::Bodies).unwrap();
        let source = source_manifest(&source_titles, &source_bodies);
        let generated = transform_manifest(
            &source,
            &source_titles,
            &source_bodies,
            &test_titles,
            &test_bodies,
        )
        .unwrap();
        let source_json: Value = serde_json::from_slice(&source).unwrap();
        let generated_json: Value = serde_json::from_slice(&generated).unwrap();

        assert_eq!(generated_json["cardset"], source_json["cardset"]);
        assert_eq!(generated_json["artpack"], source_json["artpack"]);
        assert_eq!(
            generated_json["titles"],
            cas::content_ref(&test_titles, &[])
        );
        assert_eq!(
            generated_json["bodies"],
            cas::content_ref(&test_bodies, &[])
        );
        assert_ne!(generated_json["titles"], source_json["titles"]);
        assert_ne!(generated_json["bodies"], source_json["bodies"]);
    }

    #[test]
    fn manifest_rejects_supplied_tables_that_do_not_match_the_source_skin() {
        let source_titles = titles("1\tFixture Qzx One\n");
        let source_bodies = bodies("1\tSynthetic Qzx Body\n");
        let source = source_manifest(&source_titles, &source_bodies);
        let wrong_titles = titles("1\tFixture Qzx Different\n");
        let error = transform_manifest(
            &source,
            &wrong_titles,
            &source_bodies,
            b"test titles",
            b"test bodies",
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("titles reference does not match"),
            "unexpected error: {error}"
        );
    }
}
