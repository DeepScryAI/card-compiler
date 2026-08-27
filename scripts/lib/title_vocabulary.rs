use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process::Command;

#[derive(Clone, Debug)]
pub struct DictionarySnapshot {
    pub words: BTreeSet<String>,
    pub sha256: String,
    pub version: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistinctiveVocabulary {
    pub catalog_words: BTreeSet<String>,
    pub ordinary_words: BTreeSet<String>,
    pub allowlisted_words: BTreeSet<String>,
    pub distinctive_words: BTreeSet<String>,
    pub sha256: String,
}

/// Tokenize ASCII title words and normalize only grammatical possessive suffixes.
///
/// Internal apostrophes remain part of the word (`Qzx'Var`, `don't`). Straight
/// and curly `'<s>` suffixes and a terminal possessive apostrophe are removed.
/// This deliberately never uses character-set stripping: `fixture's` becomes
/// `fixture`, while an ordinary word ending in `s` remains intact.
pub fn normalized_title_words(text: &str) -> Vec<String> {
    let characters: Vec<char> = text.chars().collect();
    let mut words = Vec::new();
    let mut index = 0;

    while index < characters.len() {
        if !characters[index].is_ascii_alphabetic() {
            index += 1;
            continue;
        }

        let mut word = String::new();
        while index < characters.len() && characters[index].is_ascii_alphabetic() {
            word.push(characters[index].to_ascii_lowercase());
            index += 1;
        }

        if index < characters.len() && matches!(characters[index], '\'' | '’') {
            let apostrophe_index = index;
            index += 1;
            if index < characters.len() && characters[index].is_ascii_alphabetic() {
                word.push('\'');
                while index < characters.len() && characters[index].is_ascii_alphabetic() {
                    word.push(characters[index].to_ascii_lowercase());
                    index += 1;
                }
            } else {
                word.push('\'');
            }

            // The grammar accepts at most one apostrophe in a word. Leave any
            // later apostrophe for the outer loop rather than swallowing text.
            debug_assert!(index > apostrophe_index);
        }

        if word.len() > 2 && word.ends_with("'s") {
            word.truncate(word.len() - 2);
        } else if word.len() > 1 && word.ends_with('\'') {
            word.pop();
        }
        if !word.is_empty() {
            words.push(word);
        }
    }

    words
}

pub fn normalized_word_set_sha256(words: &BTreeSet<String>) -> String {
    let mut hasher = Sha256::new();
    for word in words {
        hasher.update(word.as_bytes());
        hasher.update(b"\n");
    }
    format!("{:x}", hasher.finalize())
}

pub fn file_sha256(path: &Path) -> Result<String> {
    let mut file = File::open(path).with_context(|| format!("open {} for hashing", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("read {} for hashing", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn parse_expanded_dictionary(output: &str) -> Result<BTreeSet<String>> {
    let words: BTreeSet<String> = output
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && line
                    .chars()
                    .all(|character| character.is_ascii_alphabetic() || matches!(character, '\'' | '’'))
        })
        .filter_map(|line| normalized_title_words(line).into_iter().next())
        .collect();
    if words.is_empty() {
        bail!("expanded dictionary is empty or malformed");
    }
    Ok(words)
}

pub fn expanded_aspell_dictionary(aspell: &str) -> Result<DictionarySnapshot> {
    let output = Command::new(aspell)
        .args(["--lang=en_US", "dump", "master"])
        .output()
        .with_context(|| format!("run {aspell} --lang=en_US dump master"))?;
    if !output.status.success() {
        bail!(
            "expanded dictionary command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let text = std::str::from_utf8(&output.stdout).context("expanded dictionary output is not UTF-8")?;
    let words = parse_expanded_dictionary(text)?;

    let version_output = Command::new(aspell)
        .arg("--version")
        .output()
        .with_context(|| format!("run {aspell} --version"))?;
    if !version_output.status.success() {
        bail!("{aspell} --version failed");
    }
    let version = String::from_utf8_lossy(&version_output.stdout).trim().to_owned();
    let sha256 = normalized_word_set_sha256(&words);
    Ok(DictionarySnapshot { words, sha256, version })
}

pub fn derive_distinctive_vocabulary(
    title_word_sources: &BTreeMap<String, BTreeSet<Option<String>>>,
    dictionary: &BTreeSet<String>,
    normalized_allowlist: &BTreeMap<String, String>,
) -> DistinctiveVocabulary {
    let catalog_words: BTreeSet<String> = title_word_sources.keys().cloned().collect();
    let ordinary_words = catalog_words.intersection(dictionary).cloned().collect();
    let allowlisted_words = catalog_words
        .iter()
        .filter(|word| !dictionary.contains(*word) && normalized_allowlist.contains_key(*word))
        .cloned()
        .collect();
    let distinctive_words: BTreeSet<String> = catalog_words
        .iter()
        .filter(|word| !dictionary.contains(*word) && !normalized_allowlist.contains_key(*word))
        .cloned()
        .collect();
    let sha256 = normalized_word_set_sha256(&distinctive_words);
    DistinctiveVocabulary {
        catalog_words,
        ordinary_words,
        allowlisted_words,
        distinctive_words,
        sha256,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn title_words_normalize_only_grammatical_possessives() {
        assert_eq!(
            normalized_title_words("Fixture's Fixture’s Fixtures' Qzx'Var don't glass"),
            ["fixture", "fixture", "fixtures", "qzx'var", "don't", "glass"]
        );
    }

    #[test]
    fn expanded_dictionary_keeps_inflections_and_normalizes_possessives() {
        let words = parse_expanded_dictionary("accelerated\nadvisors\nFixture's\nQzx'Var\nnaïve\n").unwrap();
        assert!(words.contains("accelerated"));
        assert!(words.contains("advisors"));
        assert!(words.contains("fixture"));
        assert!(words.contains("qzx'var"));
        assert!(!words.contains("na"));
    }

    #[test]
    fn subtraction_uses_dictionary_then_reviewed_single_word_allowlist() {
        let sources = BTreeMap::from([
            ("accelerated".to_owned(), BTreeSet::from([None])),
            ("qzxcoined".to_owned(), BTreeSet::from([None])),
            ("reviewedname".to_owned(), BTreeSet::from([None])),
        ]);
        let dictionary = BTreeSet::from(["accelerated".to_owned()]);
        let allowlist = BTreeMap::from([(
            "reviewedname".to_owned(),
            "A synthetic reviewed name used only by this focused test.".to_owned(),
        )]);
        let vocabulary = derive_distinctive_vocabulary(&sources, &dictionary, &allowlist);
        assert_eq!(vocabulary.ordinary_words, BTreeSet::from(["accelerated".to_owned()]));
        assert_eq!(
            vocabulary.allowlisted_words,
            BTreeSet::from(["reviewedname".to_owned()])
        );
        assert_eq!(vocabulary.distinctive_words, BTreeSet::from(["qzxcoined".to_owned()]));
    }

    #[test]
    fn file_digest_records_the_exact_cached_snapshot_bytes() {
        let path = std::env::temp_dir().join(format!("card-compiler-title-vocabulary-hash-{}", std::process::id()));
        std::fs::write(&path, b"abc").unwrap();
        assert_eq!(
            file_sha256(&path).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        std::fs::remove_file(path).unwrap();
    }
}
