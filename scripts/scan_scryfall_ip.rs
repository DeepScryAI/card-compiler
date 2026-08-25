#!/usr/bin/env rust-script
//! ```cargo
//! [package]
//! edition = "2021"
//!
//! [dependencies]
//! aho-corasick = "1.1.3"
//! anyhow = "1.0.99"
//! clap = { version = "4.5.45", features = ["derive"] }
//! flate2 = "1.1.2"
//! reqwest = { version = "0.12.28", default-features = false, features = ["blocking", "json", "rustls-tls"] }
//! serde = { version = "1.0.219", features = ["derive"] }
//! serde_json = "1.0.143"
//! uuid = { version = "1.18.0", features = ["serde"] }
//! ```

use aho_corasick::{AhoCorasickBuilder, AhoCorasickKind};
use anyhow::{bail, Context, Result};
use clap::Parser;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "lib/scryfall_bulk.rs"]
mod scryfall_bulk;

const MAX_REPORTED_HITS: usize = 20_000;

#[derive(Parser, Debug)]
#[command(about = "Scan tracked repository text for normalized Scryfall titles and Oracle text")]
struct Args {
    /// Git repository whose tracked files will be scanned.
    #[arg(long)]
    root: PathBuf,

    /// Restrict the scan to tracked paths beneath this repository-relative prefix.
    #[arg(long)]
    path_prefix: Option<String>,

    /// Decompressed Scryfall default_cards cache shared with the generator.
    #[arg(long, default_value = ".cache/scryfall/default_cards.json")]
    cache: PathBuf,

    /// Reviewed normalized patterns that are too generic to reject.
    #[arg(long, default_value = "ip_allowlist.tsv")]
    allowlist: PathBuf,

    /// Machine-readable result; kept below the untracked cache by default.
    #[arg(long, default_value = ".cache/reports/ip-scan.json")]
    report: PathBuf,

    /// Ignore a present cache and download the current Scryfall snapshot.
    #[arg(long)]
    refresh: bool,

    /// Treat submodule entries as opaque gitlinks instead of traversing their
    /// independently versioned repositories.
    #[arg(long)]
    exclude_submodules: bool,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum PatternKind {
    CardTitle,
    OracleText,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct PatternSource {
    kind: PatternKind,
    oracle_id: Option<String>,
}

#[derive(Clone, Debug)]
struct PatternEntry {
    normalized: String,
    sources: BTreeSet<PatternSource>,
}

#[derive(Debug, Serialize)]
struct ScanReport {
    submodules_included: bool,
    patterns_from_scryfall: usize,
    allowlisted_patterns: usize,
    active_patterns: usize,
    tracked_files_considered: usize,
    text_files_scanned: usize,
    binary_files_skipped: usize,
    non_regular_paths_skipped: usize,
    hit_pairs: usize,
    omitted_hit_pairs: usize,
    hit_pairs_by_path_group: BTreeMap<String, usize>,
    pattern_hit_counts: Vec<PatternHitCount>,
    hits: Vec<Hit>,
}

#[derive(Debug, Serialize)]
struct PatternHitCount {
    normalized_pattern: String,
    files: usize,
    sources: Vec<PatternSource>,
}

#[derive(Debug, Serialize)]
struct Hit {
    path: String,
    normalized_pattern: String,
    sources: Vec<PatternSource>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    if !args.root.is_dir() {
        bail!("scan root is not a directory: {}", args.root.display());
    }
    scryfall_bulk::ensure_cache(&args.cache, args.refresh)?;
    let all_patterns = build_patterns(&args.cache)?;
    let allowlist = load_allowlist(&args.allowlist)?;
    let active_patterns: Vec<PatternEntry> = all_patterns
        .values()
        .filter(|entry| !allowlist.contains_key(&entry.normalized))
        .cloned()
        .collect();
    if active_patterns.is_empty() {
        bail!("all Scryfall patterns were allowlisted; refusing a vacuous scan");
    }

    eprintln!(
        "Compiling {} normalized patterns with an Aho-Corasick contiguous NFA",
        active_patterns.len()
    );
    let wrapped_patterns: Vec<String> = active_patterns
        .iter()
        .map(|entry| format!(" {} ", entry.normalized))
        .collect();
    let matcher = AhoCorasickBuilder::new()
        .kind(Some(AhoCorasickKind::ContiguousNFA))
        .build(&wrapped_patterns)
        .context("compile normalized Scryfall pattern automaton")?;

    let mut tracked_files = git_tracked_files(&args.root, !args.exclude_submodules)?;
    if let Some(prefix) = args.path_prefix.as_deref() {
        tracked_files.retain(|path| path == prefix || path.starts_with(&format!("{prefix}/")));
    }
    let mut report = ScanReport {
        submodules_included: !args.exclude_submodules,
        patterns_from_scryfall: all_patterns.len(),
        allowlisted_patterns: allowlist.len(),
        active_patterns: active_patterns.len(),
        tracked_files_considered: tracked_files.len(),
        text_files_scanned: 0,
        binary_files_skipped: 0,
        non_regular_paths_skipped: 0,
        hit_pairs: 0,
        omitted_hit_pairs: 0,
        hit_pairs_by_path_group: BTreeMap::new(),
        pattern_hit_counts: Vec::new(),
        hits: Vec::new(),
    };
    let mut pattern_hit_counts = vec![0usize; active_patterns.len()];

    for relative_path in tracked_files {
        let path = args.root.join(&relative_path);
        if !path.is_file() {
            report.non_regular_paths_skipped += 1;
            continue;
        }
        let bytes = fs::read(&path).with_context(|| format!("read tracked file {}", path.display()))?;
        if bytes.contains(&0) {
            report.binary_files_skipped += 1;
            continue;
        }
        let text = std::str::from_utf8(&bytes)
            .with_context(|| format!("tracked text file is not UTF-8: {}", path.display()))?;
        report.text_files_scanned += 1;
        let matched_pattern_ids = matched_patterns_in_file(&relative_path, text, &matcher);
        report.hit_pairs += matched_pattern_ids.len();
        *report
            .hit_pairs_by_path_group
            .entry(path_group(&relative_path))
            .or_default() += matched_pattern_ids.len();
        for pattern_id in matched_pattern_ids {
            pattern_hit_counts[pattern_id] += 1;
            if report.hits.len() >= MAX_REPORTED_HITS {
                report.omitted_hit_pairs += 1;
                continue;
            }
            let entry = &active_patterns[pattern_id];
            report.hits.push(Hit {
                path: relative_path.clone(),
                normalized_pattern: entry.normalized.clone(),
                sources: entry.sources.iter().cloned().collect(),
            });
        }
    }
    report.pattern_hit_counts = pattern_hit_counts
        .into_iter()
        .enumerate()
        .filter(|(_, files)| *files > 0)
        .map(|(pattern_id, files)| PatternHitCount {
            normalized_pattern: active_patterns[pattern_id].normalized.clone(),
            files,
            sources: active_patterns[pattern_id].sources.iter().cloned().collect(),
        })
        .collect();

    write_report(&args.report, &report)?;
    eprintln!(
        "Scanned {} UTF-8 tracked files ({} binary files and {} non-file git entries skipped); found {} file/pattern hit pairs",
        report.text_files_scanned,
        report.binary_files_skipped,
        report.non_regular_paths_skipped,
        report.hit_pairs
    );
    if report.omitted_hit_pairs > 0 {
        eprintln!(
            "WARNING: report retained the first {} hits and omitted {} additional hit pairs",
            report.hits.len(),
            report.omitted_hit_pairs
        );
    }
    if report.hit_pairs > 0 {
        bail!(
            "IP scan failed with {} normalized Scryfall matches; see {}",
            report.hit_pairs,
            args.report.display()
        );
    }
    Ok(())
}

fn path_group(relative_path: &str) -> String {
    let mut components = relative_path.split('/');
    let first = components.next().unwrap_or(".");
    if first == "src" {
        let second = components.next().unwrap_or(".");
        let third = components.next().unwrap_or(".");
        return format!("{first}/{second}/{third}");
    }
    let grouped_two_levels = matches!(
        first,
        ".minibeads" | "debug" | "decks" | "experiment_results" | "experiments"
    );
    if grouped_two_levels {
        if let Some(second) = components.next() {
            return format!("{first}/{second}");
        }
    }
    first.to_owned()
}

fn matched_patterns_in_file(relative_path: &str, text: &str, matcher: &aho_corasick::AhoCorasick) -> BTreeSet<usize> {
    let is_corpus_record = is_corpus_card_record(relative_path);
    text.lines()
        .filter(|line| !is_nonexpressive_card_record(relative_path, line))
        .flat_map(|line| {
            let scanned = if is_corpus_record {
                strip_keyword_operands(line)
            } else {
                line.to_owned()
            };
            let normalized = format!(" {} ", normalize_for_scan(&scanned));
            matcher
                .find_overlapping_iter(&normalized)
                .map(|matched| matched.pattern().as_usize())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Card-script fields whose value is a list of KEYWORD NAMES.
///
/// A keyword name is a game mechanic, not expression: the rules print it and an
/// executable corpus has to spell it. A list of them therefore carries no
/// third-party content, even when the normalized text of the list happens to
/// coincide with some card's Oracle sentence — `AddKeyword$ Flying & First
/// Strike & Vigilance` normalizes to exactly the Oracle text of a card that
/// prints those three keywords, which is a false positive about mechanics
/// vocabulary and nothing else.
///
/// Deliberately NOT extended to `K:` lines as a whole. A `K:` line can carry
/// real lore — the Flavor words scrubbed in `021b2355b` rode on `K:Equip:`
/// segments — so those lines stay fully scanned.
const KEYWORD_OPERAND_FIELDS: [&str; 5] = ["AddKeyword", "AddKWs", "KW", "KWChoice", "Keywords"];

fn is_corpus_card_record(relative_path: &str) -> bool {
    let is_corpus_path = relative_path.starts_with("cards/")
        || relative_path.starts_with("tokens/")
        || relative_path.contains("/cards/")
        || relative_path.contains("/tokens/");
    is_corpus_path && relative_path.ends_with(".txt")
}

/// Blank out the VALUE of every keyword-operand field on a card-script line,
/// leaving the rest of the line — including the field's own name and every
/// other clause — to be scanned normally.
fn strip_keyword_operands(line: &str) -> String {
    line.split('|')
        .map(|clause| {
            let Some((key, _)) = clause.split_once('$') else {
                return clause.to_owned();
            };
            // The key is the last whitespace-separated word before the `$`, so
            // a leading `S:Mode` or `A:AB` prefix does not hide it.
            let field = key.trim().rsplit(char::is_whitespace).next().unwrap_or("").trim();
            if KEYWORD_OPERAND_FIELDS.contains(&field) {
                format!("{key}$")
            } else {
                clause.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("|")
}

fn is_nonexpressive_card_record(relative_path: &str, line: &str) -> bool {
    if !is_corpus_card_record(relative_path) {
        return false;
    }
    let key = line.split_once(':').map(|(key, _)| key.trim()).unwrap_or(line.trim());
    matches!(
        key,
        "Id" | "TokenId"
            | "ColorIdentity"
            | "ManaCost"
            | "Types"
            | "PT"
            | "Colors"
            | "Loyalty"
            | "Defense"
            | "HandLifeModifier"
            | "AlternateMode"
            | "ALTERNATE"
            | "SPECIALIZE"
    )
}

fn build_patterns(cache: &Path) -> Result<BTreeMap<String, PatternEntry>> {
    let mut patterns = BTreeMap::new();
    scryfall_bulk::for_each_card(cache, |card| {
        if card.lang != "en" {
            return;
        }
        let oracle_id = card.oracle_id.map(|id| id.hyphenated().to_string());
        insert_pattern(&mut patterns, &card.name, PatternKind::CardTitle, oracle_id.clone());
        if let Some(printed_name) = card.printed_name.as_deref() {
            insert_pattern(&mut patterns, printed_name, PatternKind::CardTitle, oracle_id.clone());
        }
        if let Some(oracle_text) = card.oracle_text.as_deref() {
            insert_pattern(&mut patterns, oracle_text, PatternKind::OracleText, oracle_id.clone());
        }
        for face in card.card_faces {
            insert_pattern(&mut patterns, &face.name, PatternKind::CardTitle, oracle_id.clone());
            if let Some(printed_name) = face.printed_name.as_deref() {
                insert_pattern(&mut patterns, printed_name, PatternKind::CardTitle, oracle_id.clone());
            }
            if let Some(oracle_text) = face.oracle_text.as_deref() {
                insert_pattern(&mut patterns, oracle_text, PatternKind::OracleText, oracle_id.clone());
            }
        }
    })?;
    Ok(patterns)
}

fn insert_pattern(
    patterns: &mut BTreeMap<String, PatternEntry>,
    original: &str,
    kind: PatternKind,
    oracle_id: Option<String>,
) {
    let normalized = normalize_for_scan(original);
    let words = normalized.split_whitespace().count();
    // A repository-wide scan cannot meaningfully treat ordinary identifiers
    // such as `copy`, `index`, or `return` as evidence merely because an
    // unrelated card has that one-word title. Require multi-word titles and a
    // substantive Oracle sentence; exact forbidden script fields are audited
    // separately by the corpus generator.
    let is_actionable = match kind {
        PatternKind::CardTitle => words >= 2,
        PatternKind::OracleText => words >= 4 && normalized.len() >= 20,
    };
    if !is_actionable {
        return;
    }
    patterns
        .entry(normalized.clone())
        .or_insert_with(|| PatternEntry {
            normalized,
            sources: BTreeSet::new(),
        })
        .sources
        .insert(PatternSource { kind, oracle_id });
}

fn normalize_for_scan(text: &str) -> String {
    let mut normalized = String::with_capacity(text.len());
    let mut needs_space = false;
    for character in text.chars().flat_map(char::to_lowercase) {
        if character.is_alphanumeric() {
            if needs_space && !normalized.is_empty() {
                normalized.push(' ');
            }
            normalized.push(character);
            needs_space = false;
        } else {
            needs_space = true;
        }
    }
    normalized
}

fn load_allowlist(path: &Path) -> Result<BTreeMap<String, String>> {
    let text = fs::read_to_string(path).with_context(|| format!("read reviewed allowlist {}", path.display()))?;
    let mut entries = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (pattern, reason) = line.split_once('\t').with_context(|| {
            format!(
                "allowlist line {} must be '<normalized pattern><TAB><plain-language reason>'",
                index + 1
            )
        })?;
        let pattern = pattern.trim();
        let reason = reason.trim();
        if normalize_for_scan(pattern) != pattern {
            bail!("allowlist line {} is not normalized: {pattern:?}", index + 1);
        }
        if reason.len() < 12 {
            bail!("allowlist line {} has no meaningful justification", index + 1);
        }
        if entries.insert(pattern.to_owned(), reason.to_owned()).is_some() {
            bail!("duplicate allowlist pattern on line {}: {pattern:?}", index + 1);
        }
    }
    Ok(entries)
}

fn git_tracked_files(root: &Path, recurse_submodules: bool) -> Result<Vec<String>> {
    let mut command = Command::new("git");
    command.arg("-C").arg(root).args(["ls-files", "-z"]);
    if recurse_submodules {
        command.arg("--recurse-submodules");
    }
    let output = command.output().context("run git ls-files for IP scan")?;
    if !output.status.success() {
        bail!(
            "git ls-files failed for {}: {}",
            root.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| {
            std::str::from_utf8(path)
                .map(str::to_owned)
                .context("git returned a non-UTF-8 tracked path")
        })
        .collect()
}

fn write_report(path: &Path, report: &ScanReport) -> Result<()> {
    let parent = path.parent().context("scan report path has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("create report directory {}", parent.display()))?;
    let file = File::create(path).with_context(|| format!("create {}", path.display()))?;
    serde_json::to_writer_pretty(file, report).context("write IP scan report")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_lowercases_and_turns_punctuation_into_boundaries() {
        assert_eq!(normalize_for_scan("First-strike!  CAT_name"), "first strike cat name");
    }

    #[test]
    fn wrapped_patterns_do_not_match_inside_larger_words() {
        let matcher = AhoCorasickBuilder::new()
            .kind(Some(AhoCorasickKind::ContiguousNFA))
            .build([" cat "])
            .unwrap();
        assert!(matcher.is_match(" a cat naps "));
        assert!(!matcher.is_match(" concatenate values "));
    }

    #[test]
    fn card_scan_ignores_structural_type_records_but_not_executable_records() {
        let matcher = AhoCorasickBuilder::new()
            .kind(Some(AhoCorasickKind::ContiguousNFA))
            .build([" human soldier "])
            .unwrap();
        let text = "Types:Creature Human Soldier\nSVar:X:DB$ Effect | Name$ Human Soldier\n";
        assert_eq!(
            matched_patterns_in_file("cards/00/00/00/00000001.txt", text, &matcher).len(),
            1
        );
        assert_eq!(
            matched_patterns_in_file("README.md", "Types: Human Soldier", &matcher).len(),
            1
        );
    }

    #[test]
    fn keyword_operand_lists_are_mechanics_vocabulary_not_expression() {
        let matcher = AhoCorasickBuilder::new()
            .kind(Some(AhoCorasickKind::ContiguousNFA))
            .build([" flying first strike vigilance ", " fixture drake qzx "])
            .unwrap();
        // The keyword list normalizes to a real card's Oracle sentence; that
        // is mechanics vocabulary, so it must not count as a hit.
        let keyword_grant =
            "S:Mode$ Continuous | Affected$ Creature.YouCtrl | AddKeyword$ Flying & First Strike & Vigilance\n";
        assert_eq!(
            matched_patterns_in_file("cards/00/00/00/00000001.txt", keyword_grant, &matcher).len(),
            0
        );
        // Only the operand VALUE is exempt: a card title elsewhere on the same
        // line still counts.
        let with_a_title =
            "SVar:C:DB$ Clone | NewName$ Fixture Drake Qzx | KW$ Flying & First Strike & Vigilance\n";
        assert_eq!(
            matched_patterns_in_file("cards/00/00/00/00000001.txt", with_a_title, &matcher).len(),
            1
        );
        // Outside the corpus the exemption does not apply at all.
        assert_eq!(matched_patterns_in_file("README.md", keyword_grant, &matcher).len(), 1);
    }

    #[test]
    fn allowlist_requires_a_plain_language_reason() {
        let temporary = std::env::temp_dir().join(format!("cardsmirror-allowlist-test-{}.tsv", std::process::id()));
        fs::write(&temporary, "cat\tshort\n").unwrap();
        assert!(load_allowlist(&temporary).is_err());
        fs::remove_file(temporary).unwrap();
    }
}
