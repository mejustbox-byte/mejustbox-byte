# WannaCry and one finding: what a bounded static analysis leaves unknown

Author: Dmitry Kudryavtsev · 24 October 2026 · Ransomware Triage Lab 0.1.0

[Русский](../ru/wannacry-analysis-limits.md) · [Profile](../../README.md)

On a research sample from a WannaCry collection, Ransomware Triage Lab returned one finding: a `WriteFile` import. Its priority was `review` and its status `partial`. It is easy to misread that report: a known ransomware sample produced very few findings, so perhaps the file is safe or the assessment is complete.

Neither conclusion follows. The tool performed a bounded procedure and reported where its coverage stopped. A small finding count describes the result of particular rules on the available data, not the safety of a file.

## What was examined

The file comes from the public theZoo collection, pinned to commit `48515e492013bc5bb2769249ea539436bb3e733f`. The WannaCry label comes from that research collection; the analyzer does not independently identify the family. The project case ID is `wannacry-loader`.

- File size: **3,514,368 bytes**.
- File SHA-256: `ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa`.
- Source ZIP SHA-256: `707a9f323556179571bc832e34fa592066b1d5f2cac4a7426fe163597e3e618a`.

Sample code was not executed. Embedded material was not unpacked, and function reachability and the encryption algorithm were not investigated. This case addresses only version 0.1.0's results on this particular file.

[Source and report manifest](https://github.com/mejustbox-byte/ransomware-triage-lab/blob/v0.1.0/cases/manifest.json).

## One finding and its broader context

The parser read the PE32 headers, sections and import table. Rule `RT-007` selected `KERNEL32.dll!WriteFile` as a low-confidence, informational finding. Its `thunk_offset: 54868` is a decimal file offset for the import entry, not an address where a function call was confirmed.

File offsets and relative virtual addresses are distinct concepts in [Microsoft's PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format). Preserving that distinction matters when carrying report observations into further analysis.

Legitimate programs also use `WriteFile`. An import establishes neither invocation, bulk document processing nor encryption. Here it is a reference point for further investigation.

The report contains more than its rule matches. The complete import list also includes `FindResourceA`, `LoadResource`, `LockResource` and `SizeofResource`. Those entries support a question about the role of resources; they do not establish that any particular resource was loaded or executed.

Section measurements provide additional context:

| Section | Raw-data start offset | Raw-data size, bytes | Entropy, bits/byte |
| --- | --- | --- | --- |
| `.text` | `4096` | `28672` | `6.4042` |
| `.rdata` | `32768` | `24576` | `6.6636` |
| `.data` | `57344` | `8192` | `4.4557` |
| `.rsrc` | `65536` | `3448832` | `7.9999` |

The high entropy of `.rsrc` is consistent with compressed or encrypted data. It establishes neither the format nor the purpose of that data. The tool therefore adds a coverage gap rather than declaring a section malicious based on that measurement alone.

[Full expected report](https://github.com/mejustbox-byte/ransomware-triage-lab/blob/v0.1.0/cases/wannacry-loader.expected.json).

## Where the procedure stops

The result records five explicit limitations:

| `coverage_gaps` entry | What remains unknown |
| --- | --- |
| `runtime_behavior_not_observed` | Execution behavior was not observed |
| `embedded_payloads_not_unpacked` | Embedded content was not exposed by this procedure |
| `dynamic_imports_not_resolved` | Dynamically resolved functions were not recovered |
| `high_entropy_section_possible_packing_or_compressed_data` | The nature of high-entropy data was not established |
| `string_limit_4096` | The string-processing budget was reached |

The final entry matters particularly when interpreting a negative result. Version 0.1.0 extracts ASCII strings first, followed by supported UTF-16LE sequences within one shared budget. Exhausting the budget in the first pass limits subsequent consideration of the other encoding. That ordering is an implementation property, not evidence that such data is absent from the file.

Increasing the budget might expand the inspected scope. It would not, by itself, expose embedded objects or establish runtime behavior. The published result uses the original limit; no alternative run is claimed here.

## Interpreting `partial` and `review`

`partial` means the declared static procedure did not cover everything that further assessment might require. `review` is this tool's finding-handling category. It is not equivalent to low risk, and it does not authorize execution of the file.

In this run, the high-entropy-section flag and exhausted string budget cause the `partial` status. The other listed limitations describe method boundaries and also appear in some reports marked `complete_static_scope`.

The established observations are the `WriteFile` import, the measured resource-section entropy and the exhausted string budget. A hypothesis for further work is that relevant data may lie outside this procedure's capabilities. Encryption, propagation, backup deletion and the success of any action were not established.

The next analytical step should address the gap: inspect resource structures, examine code references or prepare behavior observation in a separately verified laboratory. Adding more string rules cannot replace those steps. They were not performed in this case.

## Reproducing the result

Use a checkout of tag `v0.1.0` and the [installation instructions](https://github.com/mejustbox-byte/ransomware-triage-lab/blob/v0.1.0/docs/en/user-guide.md). Instructions for obtaining the pinned research archive are in the [release case notes](https://github.com/mejustbox-byte/ransomware-triage-lab/blob/v0.1.0/docs/en/cases.md). Sample binaries are not distributed with this project.

For an archive already obtained, run the following in a separate analysis environment, from the checkout root, with a new output path:

```sh
python scripts/reproduce_case.py --case wannacry-loader --archive work/wannacry-loader.zip --verify --output work/wannacry-loader.json
```

The script checks archive and selected-member hashes, reads sample bytes into memory and compares the result with the recorded JSON. It neither executes sample code nor extracts an executable file to disk. Exit code `0` with `--verify` means the reports match; it does not mean no threat was found. The report remains `status: partial`. The ordinary analysis command returns code `2` for this file.

The value of this case is a verifiable boundary around the result. A useful report shows both the indicators found and why the absence of other findings cannot establish safety.
