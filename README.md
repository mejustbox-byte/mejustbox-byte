# Dmitry Kudryavtsev

**Industrial infrastructure security · Kazakhstan**

[Русский](README.ru.md) · [Research](#research) · [Tools](#selected-tools) · [Experience](#professional-experience)

I work as Chief Information Security Specialist in Kazakhstan's chemical industry. My responsibilities include infrastructure protection, vulnerability management, perimeter gateways and firewalls, SIEM, PAM, MFA and EDR/XDR.

I maintain open-source defensive tools and publish reproducible research, from initial assessment of suspicious PE files to Beacon configuration extraction and detection-rule testing. Each analysis records its source, tool version, supporting evidence and limits.

## Research

### [Two Beacon configurations in one file: why the first match is not enough](articles/en/beacon-two-configurations.md)

Two XOR `0x69` blocks share network settings but differ in other fields. I explain why the tool preserves both results as `ambiguous`, and why identifying the active configuration requires additional evidence.

### [WannaCry and one finding: what a bounded static analysis leaves unknown](articles/en/wannacry-analysis-limits.md)

A research sample illustrates the meaning of `partial`: a `WriteFile` import, a high-entropy resource section and an exhausted string budget. Finding counts alone cannot establish whether a file is safe.

## Selected tools

| Project | Defensive purpose | Results and verification |
| --- | --- | --- |
| [Ransomware Triage Lab](https://github.com/mejustbox-byte/ransomware-triage-lab) | Static PE analysis, initial event triage and YARA/Sigma rules | [Release 0.1.0](https://github.com/mejustbox-byte/ransomware-triage-lab/releases/tag/v0.1.0), WannaCry/TeslaCrypt case notes, [release CI](https://github.com/mejustbox-byte/ransomware-triage-lab/actions/runs/40065887802) |
| [C2 Client Analyzer](https://github.com/mejustbox-byte/c2-client-analyzer) | Extract and compare classic Beacon TLV configurations; correlate supplied connection records | [Release 0.1.0](https://github.com/mejustbox-byte/c2-client-analyzer/releases/tag/v0.1.0), two research cases, [release CI](https://github.com/mejustbox-byte/c2-client-analyzer/actions/runs/40065929132) |
| [Detection Engineering Toolkit](https://github.com/mejustbox-byte/detection-engineering-toolkit) | Prepare experimental Sigma/SPL/KQL rules and test scenarios | [Verification record](https://github.com/mejustbox-byte/detection-engineering-toolkit/blob/main/docs/en/VERIFICATION.md); live SIEM validation remains a separate step |
| [Publication OPSEC Guard](https://github.com/mejustbox-byte/publication-opsec-guard) | Inspect prepared material for potential information disclosure | [Implementation and evidence matrix](https://github.com/mejustbox-byte/publication-opsec-guard/blob/main/docs/en/check-matrix.md); bounded inspection scope |

Other work is available in my [repositories](https://github.com/mejustbox-byte?tab=repositories): AD, Azure/Entra, Hyper-V, Linux and VPS assessment, report validation, backup evidence and network-configuration review.

## Professional experience

I have more than 15 years of experience with Windows/Linux, networks, resilient infrastructure and information security. My previous work in Russia included payment infrastructure, distributed organizations and IT/security leadership. I now apply that experience to industrial infrastructure security in Kazakhstan.

My working areas include vulnerability management, monitoring and incident-response processes, access management, network perimeter protection, automation and recovery readiness.

## Working approach

I tie conclusions to specific inputs and test conditions, and distinguish an observed indicator, a hypothesis and verified behavior. Publications use synthetic examples and pinned public research material. Employer configurations, secrets and operational reports remain private.

## Contact and collaboration

I welcome discussions about defensive analysis, infrastructure security, threat detection and automation. Use the profile's public contact channels; for open-source tools, use the relevant repository's Issues. Private vulnerability-reporting instructions are in its SECURITY.md.
