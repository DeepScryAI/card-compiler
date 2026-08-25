use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

/// The final ID in the pre-token catalog. This is deliberately frozen for
/// the one-time migration: changing the input base would silently move every
/// token instead of appending a new definition after the established range.
pub const CARD_MAX_ID: u32 = 35_307;
pub const ROWS: u32 = 837;

/// SHA-256 of the 837 genesis source stems in bytewise sorted order, one per
/// line with a final newline. This makes the one-time allocation reproducible
/// without retaining a second token catalog.
const SORTED_KEYS_SHA256: &str = "eb1a79e8569edfa737e250d7dbb2b97f945359351a425ce3d88297fd8388c964";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Row {
    pub catalog_id: u32,
    pub source_key: String,
    pub source_path: PathBuf,
}

/// Enumerate the frozen genesis block in catalog-ID order.
///
/// This is the only producer of the token ordering. Both anonymous script
/// generation and presentation-title generation consume these rows, so a
/// title can never be assigned to a different numeric token than its script.
pub fn rows(source: &Path, card_max_id: u32) -> Result<Vec<Row>> {
    if card_max_id != CARD_MAX_ID {
        bail!(
            "token genesis requires final card id {CARD_MAX_ID}, found {card_max_id}; \
             append later definitions after the unified range instead of replaying genesis"
        );
    }
    let mut sources = BTreeSet::new();
    for path in source_scripts(source)? {
        let key = path
            .file_stem()
            .and_then(OsStr::to_str)
            .with_context(|| format!("token script has no UTF-8 stem: {}", path.display()))?
            .to_owned();
        if !sources.insert((key.clone(), path)) {
            bail!("duplicate token source stem {key:?}");
        }
    }
    if sources.len() != ROWS as usize {
        bail!(
            "token genesis requires exactly {ROWS} source stems, found {}; append later definitions through the unified catalog instead of replaying genesis",
            sources.len()
        );
    }
    let mut keys = String::new();
    for (key, _) in &sources {
        keys.push_str(key);
        keys.push('\n');
    }
    let actual_sha = Sha256::digest(keys.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if actual_sha != SORTED_KEYS_SHA256 {
        bail!(
            "token genesis source-key checksum mismatch: expected {SORTED_KEYS_SHA256}, found {actual_sha}; the frozen genesis universe changed"
        );
    }

    sources
        .into_iter()
        .enumerate()
        .map(|(offset, (source_key, source_path))| {
            let one_based = u32::try_from(offset + 1).context("token genesis row exceeds u32")?;
            let catalog_id = card_max_id.checked_add(one_based).context("appended token allocation exceeds u32")?;
            Ok(Row {
                catalog_id,
                source_key,
                source_path,
            })
        })
        .collect()
}

pub fn source_scripts(root: &Path) -> Result<Vec<PathBuf>> {
    fn visit(directory: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
        let mut entries: Vec<_> = fs::read_dir(directory)
            .with_context(|| format!("read source directory {}", directory.display()))?
            .collect::<std::result::Result<_, _>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let file_type = entry.file_type().with_context(|| format!("stat {}", entry.path().display()))?;
            if file_type.is_dir() {
                visit(&entry.path(), files)?;
            } else if file_type.is_file() && entry.path().extension() == Some(OsStr::new("txt")) {
                files.push(entry.path());
            }
        }
        Ok(())
    }

    let mut files = Vec::new();
    visit(root, &mut files)?;
    Ok(files)
}

