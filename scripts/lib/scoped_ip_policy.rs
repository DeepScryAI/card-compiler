//! Shared policy parsing and mirror-only, component-scoped mechanic exceptions.
use super::normalize_for_scan;
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

#[derive(Debug, Default)]
pub struct ScopedRules(BTreeMap<String, BTreeSet<String>>);

impl ScopedRules {
    pub fn len(&self) -> usize {
        self.0.values().map(BTreeSet::len).sum()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn mask(&self, scope: &str, text: &str) -> String {
        let Some(patterns) = self.0.get(scope) else {
            return text.to_owned();
        };
        let mut normalized = format!(" {} ", normalize_for_scan(text));
        for pattern in patterns {
            let wrapped = format!(" {pattern} ");
            // A numeric sentinel cannot join the surviving words into a new phrase.
            while normalized.contains(&wrapped) {
                normalized = normalized.replace(&wrapped, " 0 ");
            }
        }
        normalized
    }

    // Optional sacrifice labels are prose even though they occur inside a cost
    // parameter. Never let a typed-field exception hide that label.
    fn mask_parameter_value(&self, scope: &str, value: &str) -> String {
        let mut output = String::new();
        let mut cursor = 0;
        let mut search = 0;
        while let Some(relative) = value[search..].find('<') {
            let opening = search + relative;
            let body_start = opening + 1;
            let Some(relative_end) = value[body_start..].find('>') else {
                return value.to_owned();
            };
            let end = body_start + relative_end;
            let body = &value[body_start..end];
            if body.contains('<') {
                return value.to_owned();
            }
            let operator_start = value[..opening]
                .rfind(|c: char| !c.is_ascii_alphabetic())
                .map_or(0, |i| i + 1);
            let operator = &value[operator_start..opening];
            if matches!(operator, "SubCounter" | "AddCounter") {
                search = end + 1;
                continue;
            }
            if let Some(first) = body.find('/') {
                if let Some(second) = body[first + 1..].find('/') {
                    let display_start = body_start + first + second + 2;
                    output.push_str(&self.mask(scope, &value[cursor..display_start]));
                    output.push_str(&value[display_start..end]);
                    cursor = end;
                }
            }
            search = end + 1;
        }
        output.push_str(&self.mask(scope, &value[cursor..]));
        output
    }

    fn mask_keyword_value(&self, value: &str) -> String {
        let opcode = value.split(':').next().unwrap_or("").trim();
        let key = if !opcode.is_empty() && opcode.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            opcode.to_owned()
        } else {
            format!("sha256-{:x}", Sha256::digest(opcode.as_bytes()))
        };
        let scope = format!("mirror/keyword/{key}");
        value
            .split(':')
            .map(|field| {
                let lower = field.trim().to_ascii_lowercase();
                if lower.starts_with("flavor")
                    || lower.starts_with("flavour")
                    || lower.starts_with("description")
                    || lower.contains(" named ")
                {
                    field.to_owned()
                } else {
                    self.mask(&scope, field)
                }
            })
            .collect::<Vec<_>>()
            .join(":")
    }

    /// Apply only to executable mirror records, never prose or presentation files.
    pub fn mask_line(&self, path: &str, line: &str) -> String {
        if !(path.starts_with("cards/") || path.starts_with("tokens/")) || !path.ends_with(".txt") {
            return line.to_owned();
        }
        // A raw SVar value may itself be a pipe-delimited typed selector.
        if line.starts_with("SVar:") && !line.contains('$') {
            return self.mask_clause(line);
        }
        line.split('|')
            .map(|clause| self.mask_clause(clause.trim()))
            .collect::<Vec<_>>()
            .join(" | ")
    }

    fn mask_clause(&self, clause: &str) -> String {
        let original_svar_label = clause_label(clause).to_owned();
        let mut clause = clause.to_owned();
        if let Some(rest) = clause.strip_prefix("SVar:") {
            if let Some((label, tail)) = rest.split_once(':') {
                clause = format!("SVar:{}:{tail}", self.mask("mirror/svar-label", label));
            }
        }
        if let Some((prefix, value)) = clause.split_once('$') {
            let key = prefix.rsplit(':').next().unwrap_or(prefix).trim();
            let masked_value = self.mask_parameter_value(&format!("mirror/parameter/{key}"), value);
            let key_start = prefix.rfind(':').map_or(0, |i| i + 1);
            let masked_prefix = format!(
                "{}{}",
                &prefix[..key_start],
                self.mask("mirror/parameter-key", &prefix[key_start..])
            );
            let masked_prefix = if let Some(body) = masked_prefix.strip_prefix("K:") {
                format!("K:{}", self.mask_keyword_value(body))
            } else {
                masked_prefix
            };
            return format!("{masked_prefix}${masked_value}");
        }
        if let Some(value) = clause.strip_prefix("Types:") {
            return format!("Types:{}", self.mask("mirror/types", value));
        }
        if let Some(value) = clause.strip_prefix("K:") {
            return format!("K:{}", self.mask_keyword_value(value));
        }
        if let Some(rest) = clause.strip_prefix("SVar:") {
            if let Some((label, value)) = rest.split_once(':') {
                // The label can have been normalized above; raw SVar value scopes
                // are addressed by their original identifier, before masking it.
                let original_label = &original_svar_label;
                return format!(
                    "SVar:{label}:{}",
                    self.mask(&format!("mirror/svar-value/{original_label}"), value)
                );
            }
        }
        if let Some((key, value)) = clause.split_once(':') {
            return format!("{}:{value}", self.mask("mirror/record-key", key));
        }
        clause
    }
}

fn clause_label(clause: &str) -> &str {
    clause
        .strip_prefix("SVar:")
        .and_then(|rest| rest.split_once(':'))
        .map_or("", |(label, _)| label)
}

pub fn load(path: &Path, label: &str) -> Result<(BTreeMap<String, String>, ScopedRules)> {
    let text = fs::read_to_string(path).with_context(|| format!("read {label} {}", path.display()))?;
    parse(&text, label)
}

fn valid_scope(scope: &str) -> bool {
    if matches!(
        scope,
        "mirror/types" | "mirror/svar-label" | "mirror/parameter-key" | "mirror/record-key"
    ) {
        return true;
    }
    if let Some(opcode) = scope.strip_prefix("mirror/keyword/") {
        if let Some(digest) = opcode.strip_prefix("sha256-") {
            return digest.len() == 64 && digest.bytes().all(|c| c.is_ascii_hexdigit());
        }
        return !opcode.is_empty() && opcode.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    }
    let Some(key) = scope
        .strip_prefix("mirror/parameter/")
        .or_else(|| scope.strip_prefix("mirror/svar-value/"))
    else {
        return false;
    };
    if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '>')) {
        return false;
    }
    let key = key.to_ascii_lowercase();
    !["description", "prompt", "desc", "message", "title"]
        .iter()
        .any(|suffix| key.ends_with(suffix))
        && !matches!(
            key.as_str(),
            "name" | "text" | "word" | "optionquestion" | "roomname" | "flavor" | "oracle" | "image" | "spellbookname"
        )
}

fn parse(text: &str, label: &str) -> Result<(BTreeMap<String, String>, ScopedRules)> {
    let mut global = BTreeMap::new();
    let mut scoped = ScopedRules::default();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let fields: Vec<_> = line.split('\t').collect();
        if !(2..=3).contains(&fields.len()) {
            bail!(
                "{label} line {} must have a pattern, reason, and optional mirror scopes",
                index + 1
            );
        }
        let pattern = fields[0].trim();
        let reason = fields[1].trim();
        if pattern.is_empty() || normalize_for_scan(pattern) != pattern {
            bail!("{label} line {} is not normalized: {pattern:?}", index + 1);
        }
        if reason.len() < 12 {
            bail!("{label} line {} has no meaningful justification", index + 1);
        }
        if fields.len() == 2 {
            if global.insert(pattern.to_owned(), reason.to_owned()).is_some() {
                bail!("duplicate {label} pattern on line {}: {pattern:?}", index + 1);
            }
        } else {
            if pattern == "0" {
                bail!("reserved scoped-policy sentinel");
            }
            for scope in fields[2].split(',').map(str::trim) {
                if !valid_scope(scope) {
                    bail!(
                        "{label} line {} has invalid or display-capable scope {scope:?}",
                        index + 1
                    );
                }
                if !scoped.0.entry(scope.to_owned()).or_default().insert(pattern.to_owned()) {
                    bail!("duplicate scoped {label} pattern on line {}", index + 1);
                }
            }
        }
    }
    if let Some(pattern) = scoped
        .0
        .values()
        .flat_map(|words| words.iter())
        .find(|word| global.contains_key(*word))
    {
        bail!("scoped {label} pattern {pattern:?} also has a global exception");
    }
    Ok((global, scoped))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shipped_master_policy_has_valid_disjoint_scopes() {
        let (global, scoped) = parse(include_str!("../../ip_allowlist.tsv"), "shipped master policy").unwrap();
        assert!(!global.is_empty(), "the existing global projection must survive");
        assert!(
            !scoped.is_empty(),
            "the mirror contract needs its reviewed component policy"
        );
    }

    #[test]
    fn scopes_preserve_prose_and_other_repositories() {
        let (global, scoped) = parse("fixtureword\tTyped selector used only by the executable mirror.\tmirror/types,mirror/parameter/ValidTgts,mirror/parameter/Cost,mirror/keyword/FixtureApi,mirror/keyword/Equip\n", "test").unwrap();
        assert!(global.is_empty());
        let path = "cards/00/00/00/00000001.txt";
        assert!(!scoped
            .mask_line(path, "Types:Creature Fixtureword")
            .to_ascii_lowercase()
            .contains("fixtureword"));
        let mixed = scoped.mask_line(
            path,
            "A:SP$ Pump | ValidTgts$ Fixtureword | SpellDescription$ Fixtureword",
        );
        assert_eq!(mixed.to_ascii_lowercase().matches("fixtureword").count(), 1);
        assert!(scoped
            .mask_line("docs/test.txt", "Types:Fixtureword")
            .contains("Fixtureword"));
        assert!(scoped.mask_line(path, "Name:Fixtureword").contains("Fixtureword"));
        assert_eq!(
            scoped
                .mask_line(path, "A:AB$ Draw | Cost$ Sac<1/Fixtureword/creature named Fixtureword>")
                .to_ascii_lowercase()
                .matches("fixtureword")
                .count(),
            1
        );
        assert!(!scoped
            .mask_line(path, "K:FixtureApi:Fixtureword")
            .to_ascii_lowercase()
            .contains("fixtureword"));
        assert!(scoped
            .mask_line(path, "K:Equip:2:Flavor$ Fixtureword")
            .contains("Fixtureword"));
    }
    #[test]
    fn raw_variable_scope_covers_pipe_delimited_selector() {
        let (_, scoped) = parse("fixtureword\tTyped local selector identifier.\tmirror/svar-value/BuffedBy\n", "test").unwrap();
        assert!(!scoped.mask_line("cards/00/test.txt", "SVar:BuffedBy:Artifact | Fixtureword").to_ascii_lowercase().contains("fixtureword"));
        assert!(scoped.mask_line("cards/00/test.txt", "SVar:Other:Artifact | Fixtureword").contains("Fixtureword"));
    }
    #[test]
    fn invalid_and_duplicate_scopes_are_rejected() {
        for scope in [
            "mirror/parameter/Text",
            "mirror/parameter/SpellDescription",
            "mirror/parameter/Flavor",
            "other/types",
            "mirror/keyword",
            "mirror/keyword/",
            "mirror/keyword/sha256-bad",
            "mirror/unknown",
            "mirror/parameter/",
        ] {
            assert!(parse(
                &format!("fixtureword\tA meaningful test explanation.\t{scope}\n"),
                "test"
            )
            .is_err());
        }
        assert!(parse(
            "fixtureword\tA meaningful test explanation.\tmirror/types,mirror/types",
            "test"
        )
        .is_err());
        assert!(parse("fixtureword\tA meaningful test explanation.\t", "test").is_err());
        assert!(parse("fixtureword\tA meaningful test explanation.\tmirror/types,", "test").is_err());
        assert!(parse("0\tA meaningful test explanation.\tmirror/types", "test").is_err());
        assert!(parse(
            "fixtureword\tA meaningful test explanation.\nfixtureword\tA meaningful scoped reason.\tmirror/types",
            "test"
        )
        .is_err());
    }
}
