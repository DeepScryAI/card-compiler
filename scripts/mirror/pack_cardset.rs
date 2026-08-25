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
//! Pack this repository's numeric corpus into the SS1 **anonymous cardset
//! tarball** and print its content id (CID).
//!
//! Normative format: `docs/CARD_SKIN_FORMATS.md` in the DeepScry repository
//! (the ds-5432 ratification). The tarball contains exactly
//! `manifest.json` + the `cards/` and `tokens/` tries — and deliberately
//! NOT `catalog_ids.tsv` (Scryfall oracle ids are worldly provenance and
//! live in the skin-side provenance table instead). The manifest carries
//! format/version/counts/id-space only: a cardset is an anonymous
//! mathematical object that acquires worldly identity only by being bound
//! into a card skin.
//!
//! The archive is the pinned deterministic strict-ustar byte stream
//! (`scripts/lib/cas.rs`), so the same corpus always yields the same CID
//! from any machine.

use anyhow::{bail, Context, Result};
use clap::Parser;
use std::fs;
use std::path::{Path, PathBuf};

#[path = "lib/cas.rs"]
mod cas;

#[derive(Parser, Debug)]
#[command(about = "Pack cards/ + tokens/ into the anonymous SS1 cardset tarball and print its CID")]
struct Args {
    /// Card-script trie root.
    #[arg(long, default_value = "cards")]
    cards: PathBuf,

    /// Token-script trie root.
    #[arg(long, default_value = "tokens")]
    tokens: PathBuf,

    /// Output tarball (generated artifact, below the gitignored cache).
    #[arg(long, default_value = ".cache/cas/cardset.tar")]
    output: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();

    let card_count = collect_trie(&args.cards, "cards", &mut entries)?;
    let token_count = collect_trie(&args.tokens, "tokens", &mut entries)?;
    if card_count == 0 {
        bail!("no card scripts found under {}", args.cards.display());
    }

    let manifest = serde_json::json!({
        "card_count": card_count,
        "format": "deepscry-cardset",
        "id_space": "shared-decimal-u32",
        "token_count": token_count,
        "version": 2,
    });
    let manifest_bytes = cas::jcs_canonicalize(&manifest).context("canonicalize cardset manifest")?;
    entries.push(("manifest.json".to_owned(), manifest_bytes));

    let tar_bytes = cas::deterministic_tar(entries).context("build deterministic cardset tarball")?;
    let cid = cas::cid_for_bytes(&tar_bytes);

    if let Some(parent) = args.output.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let temporary = args.output.with_extension("write-part");
    fs::write(&temporary, &tar_bytes).with_context(|| format!("write {}", temporary.display()))?;
    fs::rename(&temporary, &args.output).with_context(|| format!("publish {}", args.output.display()))?;

    println!("cardset_cid={cid}");
    println!("cardset_size={}", tar_bytes.len());
    println!("cardset_sha256={}", cas::sha256_hex(&tar_bytes));
    println!("card_count={card_count}");
    println!("token_count={token_count}");
    eprintln!("Wrote {}", args.output.display());
    Ok(())
}

/// Walk one numeric trie, validating every path against the SS1 shape
/// `<root>/<t1>/<t2>/<t3>/<id8>.txt` where the three 2-digit shard
/// directories are the id's leading digit pairs. Anything else in the tree
/// is a hard error — an unexpected file must never ride into an addressed
/// artifact silently.
fn collect_trie(root: &Path, label: &str, entries: &mut Vec<(String, Vec<u8>)>) -> Result<usize> {
    if !root.is_dir() {
        bail!("{label} trie root {} is not a directory", root.display());
    }
    let mut count = 0usize;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .with_context(|| format!("{} is outside {}", path.display(), root.display()))?;
            let relative_str = relative.to_str().context("non-UTF-8 path in trie")?.replace('\\', "/");
            validate_trie_path(label, &relative_str)?;
            let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            entries.push((format!("{label}/{relative_str}"), bytes));
            count += 1;
        }
    }
    Ok(count)
}

fn validate_trie_path(label: &str, relative: &str) -> Result<()> {
    // The trie name is `format!("{:08}", id)` for a u32 id: zero-padded to
    // at least 8 digits, longer ids (up to 10 digits) keep their natural
    // decimal length. Shard dirs are the padded name's first three pairs.
    let parts: Vec<&str> = relative.split('/').collect();
    let ok = parts.len() == 4
        && parts[..3].iter().all(|part| part.len() == 2 && part.bytes().all(|b| b.is_ascii_digit()))
        && parts[3].ends_with(".txt")
        && {
            let stem = &parts[3][..parts[3].len() - 4];
            (8..=10).contains(&stem.len())
                && stem.bytes().all(|b| b.is_ascii_digit())
                && (stem.len() == 8 || !stem.starts_with('0'))
                // The manifest declares a shared decimal-u32 id space, so an id the
                // path grammar admits but u32 cannot hold (a 10-digit value
                // above 4294967295) must fail loudly here rather than mint a
                // cardset whose manifest lies about its own id space.
                && stem.parse::<u32>().is_ok()
                && stem[..2] == *parts[0]
                && stem[2..4] == *parts[1]
                && stem[4..6] == *parts[2]
        };
    if !ok {
        bail!(
            "unexpected file {label}/{relative}: every {label} trie entry must be \
             <t1>/<t2>/<t3>/<id>.txt (id zero-padded to at least 8 digits, within u32 range) \
             with matching shard digits"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_trie_path;

    #[test]
    fn accepts_canonical_trie_paths() {
        assert!(validate_trie_path("cards", "00/00/00/00000001.txt").is_ok());
        assert!(validate_trie_path("tokens", "98/24/82/982482567.txt").is_ok());
        // The largest id the declared decimal-u32 id space allows.
        assert!(validate_trie_path("cards", "42/94/96/4294967295.txt").is_ok());
    }

    #[test]
    fn rejects_ids_beyond_the_declared_u32_id_space() {
        // 10 digits, valid shape, but above u32::MAX = 4294967295: packing it
        // would mint a cardset whose manifest asserts an id space it violates.
        assert!(validate_trie_path("cards", "42/94/96/4294967296.txt").is_err());
        assert!(validate_trie_path("cards", "99/99/99/9999999999.txt").is_err());
    }

    #[test]
    fn rejects_malformed_trie_paths() {
        assert!(validate_trie_path("cards", "00/00/00/0000001.txt").is_err()); // 7 digits
        assert!(validate_trie_path("cards", "00/00/01/00000001.txt").is_err()); // shard mismatch
        assert!(validate_trie_path("cards", "00/00/00/00000001.md").is_err()); // wrong extension
        assert!(validate_trie_path("cards", "00/00/00/0982482567.txt").is_err()); // leading zero on 10 digits
    }
}
