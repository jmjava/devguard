//! Backup-audit summary for `devguard audit summary`.
//!
//! Combines repos and dotfiles audit into a one-page health report
//! with a coverage score and top-risk items. Read-only, no sudo.

use serde::{Deserialize, Serialize};

use crate::audit_dotfiles::AuditDotfilesReport;
use crate::audit_repos::AuditReposReport;
use crate::exit::ExitCode;

/// Severity levels for risk items.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RiskSeverity {
    Critical,
    Warning,
    Info,
}

/// A single at-risk item.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RiskItem {
    pub severity: RiskSeverity,
    pub category: String,
    pub description: String,
}

/// Combined repos + dotfiles data for the summary envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReposSummary {
    pub total: usize,
    pub dirty: usize,
    pub local_only: usize,
    pub unpushed: usize,
}

/// Combined dotfiles data for the summary envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DotfilesSummary {
    pub checked: usize,
    pub present: usize,
    pub missing: usize,
    pub coverage_percent: u32,
}

/// Report for `devguard audit summary`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditSummaryReport {
    pub repos: ReposSummary,
    pub dotfiles: DotfilesSummary,
    pub top_risks: Vec<RiskItem>,
    pub overall_score: u32,
    pub uses_sudo: bool,
    pub uses_network: bool,
}

impl AuditSummaryReport {
    pub fn exit_code(&self) -> ExitCode {
        if self
            .top_risks
            .iter()
            .any(|r| r.severity == RiskSeverity::Critical)
        {
            ExitCode::Findings
        } else {
            ExitCode::Success
        }
    }

    pub fn warnings(&self) -> Vec<String> {
        self.top_risks
            .iter()
            .map(|r| format!("[{:?}] {}: {}", r.severity, r.category, r.description))
            .collect()
    }
}

/// Build the summary from repos and dotfiles reports.
pub fn build_audit_summary(
    repos: &AuditReposReport,
    dotfiles: &AuditDotfilesReport,
) -> AuditSummaryReport {
    let repos_summary = ReposSummary {
        total: repos.total,
        dirty: repos.dirty_count,
        local_only: repos.local_only_count,
        unpushed: repos.unpushed_count,
    };

    let dotfiles_summary = DotfilesSummary {
        checked: dotfiles.checked_count,
        present: dotfiles.present_count,
        missing: dotfiles.missing_count,
        coverage_percent: dotfiles.coverage_percent,
    };

    let mut risks: Vec<RiskItem> = Vec::new();

    for path in &repos.flags.local_only {
        risks.push(RiskItem {
            severity: RiskSeverity::Critical,
            category: "repo/no-remote".into(),
            description: format!("No remote configured — local-only, at risk of data loss: {path}"),
        });
    }

    for path in &repos.flags.stale_uncommitted {
        risks.push(RiskItem {
            severity: RiskSeverity::Warning,
            category: "repo/stale-uncommitted".into(),
            description: format!("Uncommitted changes older than 7 days: {path}"),
        });
    }

    for path in &repos.flags.unpushed {
        risks.push(RiskItem {
            severity: RiskSeverity::Warning,
            category: "repo/unpushed".into(),
            description: format!("Unpushed commits: {path}"),
        });
    }

    for df in &dotfiles.dotfiles {
        if df.status == crate::audit_dotfiles::DotfileStatus::Missing {
            risks.push(RiskItem {
                severity: RiskSeverity::Info,
                category: "dotfiles/missing".into(),
                description: format!("Dotfile not found: {}", df.path),
            });
        }
    }

    risks.sort_by(|a, b| a.severity.cmp(&b.severity));
    risks.truncate(5);

    let overall_score = compute_score(&repos_summary, &dotfiles_summary);

    AuditSummaryReport {
        repos: repos_summary,
        dotfiles: dotfiles_summary,
        top_risks: risks,
        overall_score,
        uses_sudo: false,
        uses_network: false,
    }
}

fn compute_score(repos: &ReposSummary, dotfiles: &DotfilesSummary) -> u32 {
    let mut score: f64 = 100.0;

    if repos.total > 0 {
        let local_penalty = (repos.local_only as f64 / repos.total as f64) * 30.0;
        score -= local_penalty;

        let dirty_penalty = (repos.dirty as f64 / repos.total as f64) * 15.0;
        score -= dirty_penalty;

        let unpushed_penalty = (repos.unpushed as f64 / repos.total as f64) * 15.0;
        score -= unpushed_penalty;
    }

    let dotfile_penalty = (100.0 - dotfiles.coverage_percent as f64) * 0.4;
    score -= dotfile_penalty;

    score.clamp(0.0, 100.0).round() as u32
}

pub fn format_audit_summary_human(report: &AuditSummaryReport) -> String {
    let mut out = String::new();
    out.push_str("DevGuard audit summary\n");
    out.push_str(&format!(
        "  overall score: {}/100\n\n",
        report.overall_score
    ));

    out.push_str("Repositories:\n");
    out.push_str(&format!("  total: {}\n", report.repos.total));
    out.push_str(&format!("  dirty: {}\n", report.repos.dirty));
    out.push_str(&format!("  local-only: {}\n", report.repos.local_only));
    out.push_str(&format!("  unpushed: {}\n\n", report.repos.unpushed));

    out.push_str("Dotfiles:\n");
    out.push_str(&format!(
        "  coverage: {}% ({}/{})\n\n",
        report.dotfiles.coverage_percent, report.dotfiles.present, report.dotfiles.checked
    ));

    if report.top_risks.is_empty() {
        out.push_str("Top risks: (none)\n");
    } else {
        out.push_str("Top risks:\n");
        for (i, risk) in report.top_risks.iter().enumerate() {
            let sev = match risk.severity {
                RiskSeverity::Critical => "CRITICAL",
                RiskSeverity::Warning => "WARNING",
                RiskSeverity::Info => "INFO",
            };
            out.push_str(&format!(
                "  {}. [{sev}] {}: {}\n",
                i + 1,
                risk.category,
                risk.description
            ));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_dotfiles::{AuditDotfilesReport, DotfileEntry, DotfileStatus};
    use crate::audit_repos::{
        AuditRepoEntry, AuditReposFlags, AuditReposReport, CoverageStatus as RepoCovStatus,
    };

    fn mock_repos_report(
        total: usize,
        dirty: usize,
        local_only: usize,
        unpushed: usize,
    ) -> AuditReposReport {
        let mut repos = Vec::new();
        for i in 0..total {
            let is_dirty = i < dirty;
            let has_remote = i >= local_only;
            let unpushed_count = if i < unpushed { Some(1u32) } else { None };
            repos.push(AuditRepoEntry {
                path: format!("/tmp/repo{i}"),
                branch: Some("main".into()),
                dirty: is_dirty,
                last_commit_date: Some("2026-10-01T00:00:00+00:00".into()),
                remote_url: if has_remote {
                    Some("https://github.com/test/repo.git".into())
                } else {
                    None
                },
                has_remote,
                uncommitted_age_days: if is_dirty { Some(10) } else { None },
                stale_uncommitted: is_dirty,
                unpushed_commits: unpushed_count,
            });
        }
        let flags = AuditReposFlags {
            local_only: repos
                .iter()
                .filter(|r| !r.has_remote)
                .map(|r| r.path.clone())
                .collect(),
            stale_uncommitted: repos
                .iter()
                .filter(|r| r.stale_uncommitted)
                .map(|r| r.path.clone())
                .collect(),
            unpushed: repos
                .iter()
                .filter(|r| r.unpushed_commits.map_or(false, |c| c > 0))
                .map(|r| r.path.clone())
                .collect(),
        };
        AuditReposReport {
            uses_sudo: false,
            uses_network: false,
            scan_paths: vec!["/tmp".into()],
            total,
            dirty_count: dirty,
            local_only_count: local_only,
            unpushed_count: unpushed,
            repos,
            flags,
            clean: true,
            status: RepoCovStatus::Available,
            detail: None,
        }
    }

    fn mock_dotfiles_report(present: usize, total: usize) -> AuditDotfilesReport {
        let mut dotfiles = Vec::new();
        for i in 0..total {
            dotfiles.push(DotfileEntry {
                path: format!("~/.file{i}"),
                status: if i < present {
                    DotfileStatus::Present
                } else {
                    DotfileStatus::Missing
                },
                last_modified: None,
            });
        }
        AuditDotfilesReport {
            uses_sudo: false,
            reads_content: false,
            checked_count: total,
            present_count: present,
            missing_count: total - present,
            coverage_percent: if total > 0 {
                ((present as f64 / total as f64) * 100.0).round() as u32
            } else {
                0
            },
            dotfiles,
            config_dirs: Vec::new(),
        }
    }

    #[test]
    fn perfect_score_when_all_clean() {
        let repos = mock_repos_report(5, 0, 0, 0);
        let dotfiles = mock_dotfiles_report(4, 4);
        let summary = build_audit_summary(&repos, &dotfiles);
        assert_eq!(summary.overall_score, 100);
        assert!(summary.top_risks.is_empty());
        assert_eq!(summary.exit_code(), ExitCode::Success);
    }

    #[test]
    fn local_only_repos_lower_score() {
        let repos = mock_repos_report(10, 0, 5, 0);
        let dotfiles = mock_dotfiles_report(4, 4);
        let summary = build_audit_summary(&repos, &dotfiles);
        assert!(summary.overall_score < 100);
        assert!(summary
            .top_risks
            .iter()
            .any(|r| r.severity == RiskSeverity::Critical));
        assert_eq!(summary.exit_code(), ExitCode::Findings);
    }

    #[test]
    fn missing_dotfiles_lower_score() {
        let repos = mock_repos_report(5, 0, 0, 0);
        let dotfiles = mock_dotfiles_report(2, 4);
        let summary = build_audit_summary(&repos, &dotfiles);
        assert!(summary.overall_score < 100);
    }

    #[test]
    fn top_risks_truncated_to_five() {
        let repos = mock_repos_report(10, 0, 10, 0);
        let dotfiles = mock_dotfiles_report(0, 4);
        let summary = build_audit_summary(&repos, &dotfiles);
        assert!(summary.top_risks.len() <= 5);
    }

    #[test]
    fn json_envelope_format() {
        let repos = mock_repos_report(3, 1, 1, 1);
        let dotfiles = mock_dotfiles_report(3, 4);
        let summary = build_audit_summary(&repos, &dotfiles);
        let envelope = crate::json::JsonEnvelope::success("audit summary", &summary);
        let value = serde_json::to_value(&envelope).expect("serialize");
        assert_eq!(value["ok"], true);
        assert_eq!(value["command"], "audit summary");
        assert!(value["data"]["overall_score"].is_number());
        assert!(value["data"]["repos"]["total"].is_number());
        assert!(value["data"]["dotfiles"]["coverage_percent"].is_number());
        assert!(value["data"]["top_risks"].is_array());
    }

    #[test]
    fn human_format_contains_key_fields() {
        let repos = mock_repos_report(3, 1, 1, 1);
        let dotfiles = mock_dotfiles_report(2, 4);
        let summary = build_audit_summary(&repos, &dotfiles);
        let human = format_audit_summary_human(&summary);
        assert!(human.contains("overall score:"));
        assert!(human.contains("Repositories:"));
        assert!(human.contains("Dotfiles:"));
        assert!(human.contains("Top risks:"));
        assert!(human.contains("CRITICAL") || human.contains("WARNING"));
    }

    #[test]
    fn score_never_below_zero_or_above_hundred() {
        let repos = mock_repos_report(10, 10, 10, 10);
        let dotfiles = mock_dotfiles_report(0, 4);
        let summary = build_audit_summary(&repos, &dotfiles);
        assert!(summary.overall_score <= 100);
        let repos2 = mock_repos_report(0, 0, 0, 0);
        let dotfiles2 = mock_dotfiles_report(0, 0);
        let summary2 = build_audit_summary(&repos2, &dotfiles2);
        assert!(summary2.overall_score <= 100);
    }
}
