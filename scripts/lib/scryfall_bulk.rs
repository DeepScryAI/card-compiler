use anyhow::{bail, Context, Result};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use uuid::Uuid;

const BULK_MANIFEST_URL: &str = "https://api.scryfall.com/bulk-data";
const USER_AGENT: &str = "CardScriptsMirror/uuid-pipeline (https://github.com/DeepScryAI/CardScriptsMirror)";

#[derive(Debug, Deserialize)]
struct BulkManifest {
    data: Vec<BulkEntry>,
}

#[derive(Debug, Deserialize)]
struct BulkEntry {
    #[serde(rename = "type")]
    bulk_type: String,
    updated_at: String,
    download_uri: Option<String>,
    jsonl_download_uri: Option<String>,
}

#[derive(Debug, Serialize)]
struct CacheMetadata<'a> {
    bulk_type: &'a str,
    updated_at: &'a str,
    source_url: &'a str,
    encoding: &'a str,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ScryfallCard {
    /// Scryfall's per-printing card UUID — the identity the image CDN's
    /// directory fan-out is computed from. Distinct from `oracle_id`.
    #[serde(default)]
    pub id: Option<Uuid>,
    pub oracle_id: Option<Uuid>,
    pub name: String,
    pub printed_name: Option<String>,
    pub oracle_text: Option<String>,
    #[serde(default)]
    pub mana_cost: String,
    #[serde(default)]
    pub type_line: String,
    pub lang: String,
    pub layout: String,
    #[serde(default)]
    pub color_identity: Vec<String>,
    #[serde(default)]
    pub colors: Vec<String>,
    #[serde(default)]
    pub color_indicator: Option<Vec<String>>,
    #[serde(default)]
    pub card_faces: Vec<ScryfallFace>,
    #[serde(default)]
    pub released_at: String,
    #[serde(default)]
    pub digital: bool,
    #[serde(default)]
    pub image_status: Option<String>,
    #[serde(default)]
    pub image_uris: Option<ScryfallImageUris>,
    #[serde(default)]
    pub set_type: Option<String>,
}

/// The subset of Scryfall's `image_uris` object we consult: presence of a
/// real image, nothing more (URL construction is a layout function of the
/// printing UUID, not of these strings).
#[allow(dead_code)]
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ScryfallImageUris {
    #[serde(default)]
    pub normal: Option<String>,
    #[serde(default)]
    pub small: Option<String>,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ScryfallFace {
    pub name: String,
    /// Face-level Oracle id. Present on `reversible_card` printings, whose
    /// TOP-LEVEL `oracle_id` is null; absent on ordinary faces.
    #[serde(default)]
    pub oracle_id: Option<Uuid>,
    pub printed_name: Option<String>,
    pub oracle_text: Option<String>,
    #[serde(default)]
    pub mana_cost: String,
    #[serde(default)]
    pub type_line: String,
    #[serde(default)]
    pub colors: Vec<String>,
    #[serde(default)]
    pub color_indicator: Option<Vec<String>>,
    #[serde(default)]
    pub image_uris: Option<ScryfallImageUris>,
}

impl ScryfallCard {
    /// The record's Oracle identity: top level, falling back to the first face.
    ///
    /// Every `reversible_card` printing has a NULL top-level `oracle_id` and
    /// carries the real identity on each face. A consumer that reads only the
    /// top level silently drops all of them, which is invisible until one of
    /// those faces is the only source of some catalog row's title.
    pub fn effective_oracle_id(&self) -> Option<Uuid> {
        self.oracle_id
            .or_else(|| self.card_faces.iter().find_map(|face| face.oracle_id))
    }
}

pub fn ensure_cache(cache: &Path, refresh: bool) -> Result<()> {
    if cache.is_file() && !refresh {
        eprintln!("Using cached Scryfall snapshot at {}", cache.display());
        return Ok(());
    }
    let parent = cache.parent().context("Scryfall cache path has no parent directory")?;
    fs::create_dir_all(parent).with_context(|| format!("create cache directory {}", parent.display()))?;

    eprintln!("Fetching Scryfall bulk-data manifest");
    let client = reqwest::blocking::Client::builder()
        .user_agent(USER_AGENT)
        .build()
        .context("build Scryfall HTTP client")?;
    let manifest: BulkManifest = client
        .get(BULK_MANIFEST_URL)
        .header("Accept", "application/json")
        .send()
        .context("fetch Scryfall bulk-data manifest")?
        .error_for_status()
        .context("Scryfall bulk-data manifest returned an error")?
        .json()
        .context("parse Scryfall bulk-data manifest")?;
    let entry = manifest
        .data
        .iter()
        .find(|entry| entry.bulk_type == "default_cards")
        .context("Scryfall manifest has no default_cards entry")?;
    let (url, gzipped_json_lines) = if let Some(url) = entry.jsonl_download_uri.as_deref() {
        (url, true)
    } else if let Some(url) = entry.download_uri.as_deref() {
        (url, false)
    } else {
        bail!("Scryfall default_cards entry has neither jsonl_download_uri nor download_uri");
    };

    eprintln!(
        "Downloading Scryfall default_cards snapshot {} ({})",
        entry.updated_at,
        if gzipped_json_lines {
            "gzip JSON Lines"
        } else {
            "JSON array"
        }
    );
    let mut response = client
        .get(url)
        .header("Accept", "application/octet-stream")
        .send()
        .context("download Scryfall default_cards snapshot")?
        .error_for_status()
        .context("Scryfall default_cards download returned an error")?;
    let temporary = cache.with_extension("download-part");
    let output = File::create(&temporary).with_context(|| format!("create {}", temporary.display()))?;
    let mut writer = BufWriter::new(output);
    if gzipped_json_lines {
        let mut decoder = GzDecoder::new(response);
        io::copy(&mut decoder, &mut writer).context("decompress Scryfall JSON Lines snapshot")?;
    } else {
        io::copy(&mut response, &mut writer).context("write Scryfall JSON snapshot")?;
    }
    writer.flush().context("flush Scryfall cache")?;
    drop(writer);
    fs::rename(&temporary, cache).with_context(|| format!("publish cache {}", cache.display()))?;

    let metadata = CacheMetadata {
        bulk_type: "default_cards",
        updated_at: &entry.updated_at,
        source_url: url,
        encoding: if gzipped_json_lines { "json-lines" } else { "json-array" },
    };
    let metadata_path = cache.with_extension("meta.json");
    let metadata_file =
        File::create(&metadata_path).with_context(|| format!("create cache metadata {}", metadata_path.display()))?;
    serde_json::to_writer_pretty(metadata_file, &metadata).context("write Scryfall cache metadata")?;
    eprintln!("Cached decompressed snapshot at {}", cache.display());
    Ok(())
}

pub fn for_each_card(cache: &Path, mut visitor: impl FnMut(ScryfallCard)) -> Result<()> {
    let file = File::open(cache).with_context(|| format!("open {}", cache.display()))?;
    let mut reader = BufReader::new(file);
    let first = first_non_whitespace_byte(&mut reader)?;
    match first {
        Some(b'[') => {
            let cards: Vec<ScryfallCard> = serde_json::from_reader(reader).context("parse Scryfall JSON array")?;
            for card in cards {
                visitor(card);
            }
        }
        Some(_) => {
            let mut line = String::new();
            let mut line_number = 0usize;
            loop {
                line.clear();
                if reader.read_line(&mut line).context("read Scryfall JSON Lines cache")? == 0 {
                    break;
                }
                line_number += 1;
                if line.trim().is_empty() {
                    continue;
                }
                let card: ScryfallCard = serde_json::from_str(&line)
                    .with_context(|| format!("parse Scryfall JSON Lines record {line_number}"))?;
                visitor(card);
            }
        }
        None => bail!("Scryfall cache is empty: {}", cache.display()),
    }
    Ok(())
}

fn first_non_whitespace_byte(reader: &mut BufReader<File>) -> Result<Option<u8>> {
    loop {
        let available = reader.fill_buf().context("inspect Scryfall cache encoding")?;
        if available.is_empty() {
            return Ok(None);
        }
        if let Some(index) = available.iter().position(|byte| !byte.is_ascii_whitespace()) {
            let byte = available[index];
            reader.consume(index);
            return Ok(Some(byte));
        }
        let length = available.len();
        reader.consume(length);
    }
}
