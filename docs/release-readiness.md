# Release Readiness

## Completed

- Versioned PowerShell module
- Synthetic and live read-only collection modes
- Defender, Firewall, BitLocker, Secure Boot, PowerShell logging, SMBv1, and RDP NLA checks
- Normalized control findings and security scoring
- JSON, CSV, and HTML reporting
- Baseline comparison and score-delta reporting
- Pester and PSScriptAnalyzer validation
- Windows GitHub Actions artifacts
- Controlled live-validation procedure

## Remaining merge gate

Run the live collector on an authorized Windows endpoint and review sanitized output. A larger control catalog, exception workflow, and fleet aggregation can follow as later releases.
