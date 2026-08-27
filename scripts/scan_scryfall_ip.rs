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
//! sha2 = "0.10.9"
//! uuid = { version = "1.18.0", features = ["serde"] }
//! ```

use aho_corasick::{AhoCorasickBuilder, AhoCorasickKind};
use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "lib/scryfall_bulk.rs"]
mod scryfall_bulk;
#[path = "lib/title_vocabulary.rs"]
mod title_vocabulary;

const MAX_REPORTED_HITS: usize = 20_000;

#[derive(Parser, Debug)]
#[command(about = "Scan tracked repository text for normalized Scryfall titles and Oracle text")]
struct Args {
    /// The repository being measured. This is deliberately explicit: the
    /// compiler, DeepScry, and CardScriptsMirror use one scanner contract.
    #[arg(long, value_enum)]
    target: ScanTarget,

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

    /// Checked-in, repository-specific false positives. Only DeepScry may use
    /// this: ordinary-English title decisions belong in the global allowlist.
    #[arg(long)]
    local_exceptions: Option<PathBuf>,

    /// Machine-readable result; kept below the untracked cache by default.
    #[arg(long, default_value = ".cache/reports/ip-scan.json")]
    report: PathBuf,

    /// Ignore a present cache and download the current Scryfall snapshot.
    #[arg(long)]
    refresh: bool,

    /// Aspell executable used to expand the standard en_US dictionary. The
    /// normalized version and content digest are recorded in the report.
    #[arg(long, default_value = "aspell")]
    aspell: String,

    /// Treat submodule entries as opaque gitlinks instead of traversing their
    /// independently versioned repositories.
    #[arg(long)]
    exclude_submodules: bool,
}

/// The three repositories measured by the canonical scanner.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ScanTarget {
    CardCompiler,
    DeepScry,
    CardScriptsMirror,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum PatternKind {
    FullTitle,
    DistinctiveTitleWord,
    FullOracleText,
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
    schema_version: u32,
    target: ScanTarget,
    submodules_included: bool,
    policy_input_paths_skipped: usize,
    patterns_from_scryfall: usize,
    patterns_by_kind: BTreeMap<PatternKind, usize>,
    global_allowlisted_patterns: usize,
    local_exception_patterns: usize,
    active_patterns: usize,
    active_patterns_by_kind: BTreeMap<PatternKind, usize>,
    distinctive_vocabulary: DistinctiveVocabularyReport,
    tracked_files_considered: usize,
    text_files_scanned: usize,
    binary_files_skipped: usize,
    non_regular_paths_skipped: usize,
    hit_pairs: usize,
    omitted_hit_pairs: usize,
    hit_pairs_by_path_group: BTreeMap<String, usize>,
    hit_pairs_by_pattern_kind: BTreeMap<PatternKind, usize>,
    pattern_hit_counts: Vec<PatternHitCount>,
    hits: Vec<Hit>,
}

#[derive(Debug, Serialize)]
struct DistinctiveVocabularyReport {
    scryfall_cache_path: String,
    scryfall_cache_sha256: String,
    dictionary_command: String,
    dictionary_version: String,
    normalized_dictionary_words: usize,
    normalized_dictionary_sha256: String,
    normalized_catalog_title_words: usize,
    ordinary_dictionary_words: usize,
    reviewed_allowlisted_words: usize,
    distinctive_candidate_words: usize,
    distinctive_candidate_sha256: String,
    distinctive_candidates: Vec<String>,
}

#[derive(Debug)]
struct PatternBuild {
    patterns: BTreeMap<String, PatternEntry>,
    title_word_sources: BTreeMap<String, BTreeSet<Option<String>>>,
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
    if args.local_exceptions.is_some() && args.target != ScanTarget::DeepScry {
        bail!("--local-exceptions is only valid with --target deepscry");
    }
    scryfall_bulk::ensure_cache(&args.cache, args.refresh)?;
    let scryfall_cache_sha256 = title_vocabulary::file_sha256(&args.cache)?;
    let allowlist = load_exceptions(&args.allowlist, "global allowlist")?;
    let local_exceptions = args
        .local_exceptions
        .as_deref()
        .map(|path| load_exceptions(path, "DeepScry local exceptions"))
        .transpose()?
        .unwrap_or_default();
    let mut pattern_build = build_patterns(&args.cache)?;
    let dictionary = title_vocabulary::expanded_aspell_dictionary(&args.aspell)?;
    let vocabulary = title_vocabulary::derive_distinctive_vocabulary(
        &pattern_build.title_word_sources,
        &dictionary.words,
        &allowlist,
    );
    for word in &vocabulary.distinctive_words {
        let sources = pattern_build
            .title_word_sources
            .get(word)
            .context("distinctive title word lost its source identities")?;
        for oracle_id in sources {
            insert_pattern(
                &mut pattern_build.patterns,
                word,
                PatternKind::DistinctiveTitleWord,
                oracle_id.clone(),
            );
        }
    }
    let all_patterns = pattern_build.patterns;
    let active_patterns = active_patterns(&all_patterns, &allowlist, &local_exceptions)?;
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

    let policy_paths = policy_paths_under_root(
        &args.root,
        [&args.allowlist]
            .into_iter()
            .chain(args.local_exceptions.as_ref())
            .collect(),
    )?;
    let mut tracked_files = git_tracked_files(&args.root, !args.exclude_submodules)?;
    if let Some(prefix) = args.path_prefix.as_deref() {
        tracked_files.retain(|path| path == prefix || path.starts_with(&format!("{prefix}/")));
    }
    let policy_input_paths_skipped = tracked_files.iter().filter(|path| policy_paths.contains(*path)).count();
    tracked_files.retain(|path| !policy_paths.contains(path));
    let mut report = ScanReport {
        schema_version: 2,
        target: args.target,
        submodules_included: !args.exclude_submodules,
        policy_input_paths_skipped,
        patterns_from_scryfall: all_patterns.len(),
        patterns_by_kind: pattern_counts_by_kind(all_patterns.values()),
        global_allowlisted_patterns: allowlist.len(),
        local_exception_patterns: local_exceptions.len(),
        active_patterns: active_patterns.len(),
        active_patterns_by_kind: pattern_counts_by_kind(active_patterns.iter()),
        distinctive_vocabulary: DistinctiveVocabularyReport {
            scryfall_cache_path: args.cache.display().to_string(),
            scryfall_cache_sha256,
            dictionary_command: format!("{} --lang=en_US dump master", args.aspell),
            dictionary_version: dictionary.version,
            normalized_dictionary_words: dictionary.words.len(),
            normalized_dictionary_sha256: dictionary.sha256,
            normalized_catalog_title_words: vocabulary.catalog_words.len(),
            ordinary_dictionary_words: vocabulary.ordinary_words.len(),
            reviewed_allowlisted_words: vocabulary.allowlisted_words.len(),
            distinctive_candidate_words: vocabulary.distinctive_words.len(),
            distinctive_candidate_sha256: vocabulary.sha256,
            distinctive_candidates: vocabulary.distinctive_words.into_iter().collect(),
        },
        tracked_files_considered: tracked_files.len(),
        text_files_scanned: 0,
        binary_files_skipped: 0,
        non_regular_paths_skipped: 0,
        hit_pairs: 0,
        omitted_hit_pairs: 0,
        hit_pairs_by_path_group: BTreeMap::new(),
        hit_pairs_by_pattern_kind: zero_counts_by_kind(),
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
            let kinds: BTreeSet<PatternKind> = active_patterns[pattern_id]
                .sources
                .iter()
                .map(|source| source.kind.clone())
                .collect();
            for kind in kinds {
                *report.hit_pairs_by_pattern_kind.entry(kind).or_default() += 1;
            }
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

fn pattern_counts_by_kind<'a>(entries: impl Iterator<Item = &'a PatternEntry>) -> BTreeMap<PatternKind, usize> {
    let mut counts = zero_counts_by_kind();
    for entry in entries {
        let kinds: BTreeSet<PatternKind> = entry.sources.iter().map(|source| source.kind.clone()).collect();
        for kind in kinds {
            *counts.entry(kind).or_default() += 1;
        }
    }
    counts
}

fn zero_counts_by_kind() -> BTreeMap<PatternKind, usize> {
    BTreeMap::from([
        (PatternKind::FullTitle, 0),
        (PatternKind::DistinctiveTitleWord, 0),
        (PatternKind::FullOracleText, 0),
    ])
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

fn build_patterns(cache: &Path) -> Result<PatternBuild> {
    let mut patterns = BTreeMap::new();
    let mut title_word_sources: BTreeMap<String, BTreeSet<Option<String>>> = BTreeMap::new();
    scryfall_bulk::for_each_card(cache, |card| {
        if card.lang != "en" {
            return;
        }
        let oracle_id = card.oracle_id.map(|id| id.hyphenated().to_string());
        insert_title(&mut patterns, &mut title_word_sources, &card.name, oracle_id.clone());
        if let Some(printed_name) = card.printed_name.as_deref() {
            insert_title(&mut patterns, &mut title_word_sources, printed_name, oracle_id.clone());
        }
        if let Some(oracle_text) = card.oracle_text.as_deref() {
            insert_pattern(
                &mut patterns,
                oracle_text,
                PatternKind::FullOracleText,
                oracle_id.clone(),
            );
        }
        for face in card.card_faces {
            insert_title(&mut patterns, &mut title_word_sources, &face.name, oracle_id.clone());
            if let Some(printed_name) = face.printed_name.as_deref() {
                insert_title(&mut patterns, &mut title_word_sources, printed_name, oracle_id.clone());
            }
            if let Some(oracle_text) = face.oracle_text.as_deref() {
                insert_pattern(
                    &mut patterns,
                    oracle_text,
                    PatternKind::FullOracleText,
                    oracle_id.clone(),
                );
            }
        }
    })?;
    Ok(PatternBuild {
        patterns,
        title_word_sources,
    })
}

fn insert_title(
    patterns: &mut BTreeMap<String, PatternEntry>,
    title_word_sources: &mut BTreeMap<String, BTreeSet<Option<String>>>,
    original: &str,
    oracle_id: Option<String>,
) {
    insert_pattern(patterns, original, PatternKind::FullTitle, oracle_id.clone());
    for word in title_vocabulary::normalized_title_words(original) {
        title_word_sources.entry(word).or_default().insert(oracle_id.clone());
    }
}

fn insert_pattern(
    patterns: &mut BTreeMap<String, PatternEntry>,
    original: &str,
    kind: PatternKind,
    oracle_id: Option<String>,
) {
    let normalized = normalize_for_scan(original);
    // Single-word titles are included deliberately. The global allowlist is
    // where reviewed ordinary-English collisions belong; dropping them here
    // would make the allowlist inert and give a different answer from the
    // DeepScry scan.
    let is_actionable = match kind {
        PatternKind::FullTitle => normalized.len() >= 4,
        PatternKind::DistinctiveTitleWord => !normalized.is_empty(),
        PatternKind::FullOracleText => normalized.split_whitespace().count() >= 4 && normalized.len() >= 20,
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

fn load_exceptions(path: &Path, label: &str) -> Result<BTreeMap<String, String>> {
    let text = fs::read_to_string(path).with_context(|| format!("read {label} {}", path.display()))?;
    let mut entries = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (pattern, reason) = line.split_once('\t').with_context(|| {
            format!(
                "{label} line {} must be '<normalized pattern><TAB><plain-language reason>'",
                index + 1
            )
        })?;
        let pattern = pattern.trim();
        let reason = reason.trim();
        if normalize_for_scan(pattern) != pattern {
            bail!("{label} line {} is not normalized: {pattern:?}", index + 1);
        }
        if reason.len() < 12 {
            bail!("{label} line {} has no meaningful justification", index + 1);
        }
        if entries.insert(pattern.to_owned(), reason.to_owned()).is_some() {
            bail!("duplicate {label} pattern on line {}: {pattern:?}", index + 1);
        }
    }
    Ok(entries)
}

fn active_patterns(
    all_patterns: &BTreeMap<String, PatternEntry>,
    global_allowlist: &BTreeMap<String, String>,
    local_exceptions: &BTreeMap<String, String>,
) -> Result<Vec<PatternEntry>> {
    if let Some(overlap) = global_allowlist
        .keys()
        .find(|pattern| local_exceptions.contains_key(*pattern))
    {
        bail!(
            "DeepScry local exception {overlap:?} duplicates the global allowlist; \
             ordinary-English title policy belongs in the global list"
        );
    }
    Ok(all_patterns
        .values()
        .filter(|entry| {
            !global_allowlist.contains_key(&entry.normalized) && !local_exceptions.contains_key(&entry.normalized)
        })
        .cloned()
        .collect())
}

/// Return configured policy files that are tracked beneath this scan root.
///
/// An allowlist or local-exception file necessarily spells the patterns it
/// governs. Counting that audited policy input as a repository exposure would
/// make a clean result impossible while hiding the scanner's real target.
fn policy_paths_under_root(root: &Path, paths: Vec<&PathBuf>) -> Result<BTreeSet<String>> {
    let canonical_root = root
        .canonicalize()
        .with_context(|| format!("canonicalize scan root {}", root.display()))?;
    let mut relative_paths = BTreeSet::new();
    for path in paths {
        let canonical_path = path
            .canonicalize()
            .with_context(|| format!("canonicalize policy input {}", path.display()))?;
        if let Ok(relative) = canonical_path.strip_prefix(&canonical_root) {
            relative_paths.insert(relative.to_string_lossy().replace('\\', "/"));
        }
    }
    Ok(relative_paths)
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
            .build([" fixture qzxclass "])
            .unwrap();
        let text = "Types:Creature Fixture Qzxclass\nSVar:X:DB$ Effect | Name$ Fixture Qzxclass\n";
        assert_eq!(
            matched_patterns_in_file("cards/00/00/00/00000001.txt", text, &matcher).len(),
            1
        );
        assert_eq!(
            matched_patterns_in_file("README.md", "Types: Fixture Qzxclass", &matcher).len(),
            1
        );
    }

    #[test]
    fn keyword_operand_lists_are_mechanics_vocabulary_not_expression() {
        let matcher = AhoCorasickBuilder::new()
            .kind(Some(AhoCorasickKind::ContiguousNFA))
            .build([" flying first strike vigilance ", " fixture qzxmark "])
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
        let with_a_title = "SVar:C:DB$ Clone | NewName$ Fixture Qzxmark | KW$ Flying & First Strike & Vigilance\n";
        assert_eq!(
            matched_patterns_in_file("cards/00/00/00/00000001.txt", with_a_title, &matcher).len(),
            1
        );
        // Outside the corpus the exemption does not apply at all.
        assert_eq!(matched_patterns_in_file("README.md", keyword_grant, &matcher).len(), 1);
    }

    #[test]
    fn exception_file_requires_a_plain_language_reason() {
        let temporary = std::env::temp_dir().join(format!("cardsmirror-allowlist-test-{}.tsv", std::process::id()));
        fs::write(&temporary, "cat\tshort\n").unwrap();
        assert!(load_exceptions(&temporary, "test exceptions").is_err());
        fs::remove_file(temporary).unwrap();
    }

    #[test]
    fn single_word_titles_are_selected_then_global_allowlist_applies() {
        let mut patterns = BTreeMap::new();
        insert_pattern(&mut patterns, "Fixtureword", PatternKind::FullTitle, None);
        assert!(
            patterns.contains_key("fixtureword"),
            "single-word titles must reach policy review"
        );

        let global = BTreeMap::from([(
            "fixtureword".to_owned(),
            "A synthetic ordinary-English fixture for this scanner test.".to_owned(),
        )]);
        assert!(active_patterns(&patterns, &global, &BTreeMap::new())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn short_distinctive_words_are_not_hidden_by_the_full_title_floor() {
        let mut patterns = BTreeMap::new();
        insert_pattern(&mut patterns, "Qzx", PatternKind::DistinctiveTitleWord, None);
        assert!(
            patterns.contains_key("qzx"),
            "the dictionary-derived bucket must include short proper names"
        );
    }

    #[test]
    fn report_counts_a_shared_pattern_in_each_semantic_bucket() {
        let mut patterns = BTreeMap::new();
        insert_pattern(&mut patterns, "Fixtureword", PatternKind::FullTitle, None);
        insert_pattern(&mut patterns, "Fixtureword", PatternKind::DistinctiveTitleWord, None);
        insert_pattern(
            &mut patterns,
            "A sufficiently long synthetic Oracle body.",
            PatternKind::FullOracleText,
            None,
        );
        assert_eq!(
            pattern_counts_by_kind(patterns.values()),
            BTreeMap::from([
                (PatternKind::FullTitle, 1),
                (PatternKind::DistinctiveTitleWord, 1),
                (PatternKind::FullOracleText, 1),
            ])
        );
    }

    #[test]
    fn deepscry_local_exception_is_separate_and_cannot_shadow_global_policy() {
        let mut patterns = BTreeMap::new();
        insert_pattern(&mut patterns, "Fixtureword", PatternKind::FullTitle, None);
        let local = BTreeMap::from([(
            "fixtureword".to_owned(),
            "A synthetic repository-specific false positive for this test.".to_owned(),
        )]);
        assert!(active_patterns(&patterns, &BTreeMap::new(), &local).unwrap().is_empty());

        let global = BTreeMap::from([(
            "fixtureword".to_owned(),
            "A synthetic ordinary-English fixture for this scanner test.".to_owned(),
        )]);
        assert!(active_patterns(&patterns, &global, &local).is_err());
    }

    #[test]
    fn policy_paths_are_skipped_only_when_they_are_under_the_scan_root() {
        let directory = std::env::temp_dir().join(format!("cardskin-policy-path-test-{}", std::process::id()));
        let nested = directory.join("nested");
        fs::create_dir_all(&nested).unwrap();
        let inside = nested.join("exceptions.tsv");
        fs::write(&inside, "fixtureword\tA synthetic exception reason for this test.\n").unwrap();
        let outside = std::env::temp_dir().join(format!("cardskin-policy-outside-{}.tsv", std::process::id()));
        fs::write(&outside, "fixtureword\tA synthetic exception reason for this test.\n").unwrap();

        let paths = policy_paths_under_root(&directory, vec![&inside, &outside]).unwrap();
        assert_eq!(paths, BTreeSet::from(["nested/exceptions.tsv".to_owned()]));

        fs::remove_file(inside).unwrap();
        fs::remove_file(outside).unwrap();
        fs::remove_dir_all(directory).unwrap();
    }
}
