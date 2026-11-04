//! GuardDog, Datadog's open-source scanner: the version byrle runs, and every rule it
//! reports, so a policy weighting a rule it does not have is refused at load.
//! See docs/engineering_decisions/0092-detectors.md.

/// The name the detectors known by [`super::KNOWN`] give GuardDog.
pub const NAME: &str = "guarddog";

/// The release whose rules are listed here.
pub const VERSION: &str = "3.2.0";

/// GuardDog's rules a policy may weigh: its own and the two that say a rule could not run.
pub const WEIGHED: [&str; 66] = super::joined(&RULES, &[super::ERROR_RULE, WHOIS_ERROR_RULE]);

/// The rules that look up maintainers' email domains by WHOIS, on TCP port 43.
pub const WHOIS_RULES: [&str; 2] = [
    "potentially_compromised_email_domain",
    "unclaimed_maintainer_email_domain",
];

/// The rule a run fires, in place of [`super::ERROR_RULE`], for an errored [`WHOIS_RULES`] rule.
pub const WHOIS_ERROR_RULE: &str = "whois_error";

/// The rule a run of the detector `detector` fires for `errored`, a rule in its `errors`.
pub fn error_rule(detector: &str, errored: &str) -> &'static str {
    if detector == NAME && WHOIS_RULES.contains(&errored) {
        WHOIS_ERROR_RULE
    } else {
        super::ERROR_RULE
    }
}

/// Every rule GuardDog 3.2.0 lists for npm or PyPI.
pub const RULES: [&str; 64] = [
    "bundled_binary",
    "capability-filesystem-browser",
    "capability-filesystem-delete",
    "capability-filesystem-read",
    "capability-filesystem-write-executable",
    "capability-network-download",
    "capability-network-lolbas",
    "capability-network-outbound",
    "capability-process-hooks",
    "capability-process-schedule",
    "capability-process-spawn",
    "capability-runtime-clipboard",
    "deceptive_author",
    "direct_url_dependency",
    "metadata_mismatch",
    "potentially_compromised_email_domain",
    "provenance_regression",
    "repository_integrity_mismatch",
    "risky_new_dependency",
    "threat-filesystem-autostart",
    "threat-filesystem-destruction",
    "threat-filesystem-read",
    "threat-network-dns-exfil",
    "threat-network-exfil-messenger",
    "threat-network-exfil-sysinfo",
    "threat-network-exfiltration",
    "threat-network-outbound-shady-links",
    "threat-network-reverse-shell",
    "threat-npm-dependency-confusion",
    "threat-npm-http-dependency",
    "threat-npm-preinstall-script",
    "threat-process-cryptomining",
    "threat-process-download-exec",
    "threat-process-hooks",
    "threat-process-injection-dll",
    "threat-process-memory",
    "threat-process-powershell-encoded",
    "threat-process-spawn-silent",
    "threat-process-sysinfo",
    "threat-runtime-dynamic-loader",
    "threat-runtime-enumeration",
    "threat-runtime-environment-read",
    "threat-runtime-keylogging",
    "threat-runtime-obfuscation",
    "threat-runtime-obfuscation-api",
    "threat-runtime-obfuscation-base64exec",
    "threat-runtime-obfuscation-chr",
    "threat-runtime-obfuscation-dynamic-eval",
    "threat-runtime-obfuscation-general",
    "threat-runtime-obfuscation-hidden-code",
    "threat-runtime-obfuscation-import-exec",
    "threat-runtime-obfuscation-js-mangling",
    "threat-runtime-obfuscation-log-suppress",
    "threat-runtime-obfuscation-pyarmor",
    "threat-runtime-obfuscation-steganography",
    "threat-runtime-obfuscation-unicode",
    "threat-runtime-screencapture",
    "threat-runtime-self-propagation",
    "threat-runtime-system-info",
    "threat-setup-import-aliasing",
    "threat-setup-network-in-install",
    "threat-setup-suspicious-imports",
    "typosquatting",
    "unclaimed_maintainer_email_domain",
];
