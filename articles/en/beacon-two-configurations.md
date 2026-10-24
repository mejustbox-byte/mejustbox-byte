# Two Beacon configurations in one file: why the first match is not enough

Author: Dmitry Kudryavtsev · 24 October 2026 · C2 Client Analyzer 0.1.0

[Русский](../ru/beacon-two-configurations.md) · [Profile](../../README.md)

While examining a research sample, C2 Client Analyzer found two structurally matching Beacon configuration blocks. The address, port and several numeric settings agreed. Other data differed. Selecting the first block and calling it the working configuration would go beyond the evidence available from this static procedure.

This article covers extraction from file bytes. The sample was not executed and no connection was made to the extracted endpoint. Disassembly, control-flow analysis and identification of the active block are outside this case.

## Source material and the question

The sample comes from the public Sentinel-One/CobaltStrikeParser research set, pinned to commit `2703878a74811d047efde815429b78719afed357`. The project case ID is `beacon-xor69-multiple`.

- File size: **408,716 bytes**.
- File SHA-256: `4d1d732125e4d1a3ba0571e0cd892cf8e0dce854387ee405f75df4dcfb0f616b`.
- Source ZIP SHA-256: `2ce0a1fd96fe5073a6ba12bd69e7ccdb36ab97a607fbe17085ae2069d08313eb`.

The question is deliberately narrow: how many blocks pass the parser's supported structural checks, and how do the extracted values differ? Those checks do not establish configuration authenticity, product version or campaign attribution.

[Source references, hashes and expected report](https://github.com/mejustbox-byte/c2-client-analyzer/blob/v0.1.0/cases/manifest.json).

## Finding and validating a block

The parser searches for the six-byte header of the first supported TLV field in plaintext and under fixed XOR `0x69` or `0x2e`. Both accepted blocks in this sample use `0x69`. The key describes an encoding; it does not independently establish a Beacon version.

After decoding a bounded region, the parser reads three big-endian values: setting ID, type and length. It checks supported types, boundaries, duplicate IDs and the presence of required settings `1`, `2`, `3`, `8`. Numeric fields must have the appropriate length; supported text fields must use the accepted representation.

Version 0.1.0 limits processing to 32 candidates per file, 4096 decoded bytes per candidate, 128 settings per block and 2048 bytes per setting. These budgets bound processing of untrusted data; they do not establish support for every configuration variant.

## Results

All offsets below are **decimal file offsets**, not virtual addresses.

| Parameter | Block A | Block B |
| --- | --- | --- |
| Block start | `191016` | `395452` |
| Encoding | XOR `0x69` | XOR `0x69` |
| Bytes consumed, including terminator | `655` | `655` |
| Setting 2: port | `327` | `327` |
| Setting 3: `sleep_ms` | `18272` | `18272` |
| Setting 4: `max_get_bytes` | `1048576` | `1048576` |
| Setting 5: `jitter_percent` | `0` | `0` |
| Setting 8 address, defanged | `185[.]154[.]52[.]207` | `185[.]154[.]52[.]207` |
| Setting 8 URI, defanged | `/GG[.]GG` | `/GG[.]GG` |

Agreement on these values does not make the blocks identical. **The 256-byte setting 7 has different SHA-256 values:**

- Block A: `c3edf49d83e1ea668000f6d9e90490316db58894176c2c332f7eaf397aceaed0`.
- Block B: `2c2c7de1a12e59da75232ddd2cc3edde1142f86c8c42d260f284767bded3646f`.

This release does not interpret setting 7; it records the value's hash. Different hashes establish different bytes, without explaining their purpose.

Setting 9, interpreted as the User-Agent, also differs: one block contains `WGGdGGG`, the other `WGGcGGG`. The unusual content is preserved rather than replaced with a guessed reconstruction of the intended string.

An individual value can be checked using setting 2 in block A: its header starts at `191024`, and its value at `191030`. After XOR decoding, the two value bytes form the big-endian integer `327`. This ties the result to a specific part of the file.

[Full expected report](https://github.com/mejustbox-byte/c2-client-analyzer/blob/v0.1.0/cases/beacon-xor69-multiple.expected.json).

## Why the result is `ambiguous`

The parser established two structural matches. It did not establish which block is read during execution, or whether either is read at all. Multiple blocks can have several explanations; selecting an explanation requires more evidence.

Both blocks, their offsets and their differences are therefore retained. Here, `ambiguous` means the procedure cannot select one configuration. It is not evidence of two active network channels.

For a SOC analyst, the extracted address can support a search of authorized logs. Even exact host/port agreement in a supplied record would not establish that this file initiated the connection: event provenance, process identity and timing would also matter. Further research could examine code references to the blocks or observe their use in a separately prepared laboratory. Those steps were not performed in this case.

## Reproducing the result

Use a checkout of tag `v0.1.0` and the project's [installation instructions](https://github.com/mejustbox-byte/c2-client-analyzer/blob/v0.1.0/docs/en/user-guide.md). Instructions for obtaining the source research ZIP from the pinned commit are in the [release case notes](https://github.com/mejustbox-byte/c2-client-analyzer/blob/v0.1.0/docs/en/cases.md). Hostile files should be handled in a separate analysis environment.

For an archive already obtained, run this from the checkout root with a new output path:

```sh
python scripts/reproduce_case.py --case beacon-xor69-multiple --archive work/beacon-xor69-multiple.zip --verify --output work/beacon-xor69-multiple.json
```

The script verifies the ZIP hash, selects one exact member, verifies its hash and analyzes bytes in memory without extracting a file to disk. `--verify` requires byte-for-byte agreement with the recorded report. Exit code `0` means reproduction succeeded; the report still says `status: ambiguous`. The ordinary extraction CLI returns code `2` for an ambiguous result.

The practical rule from this case is to preserve each field's provenance and the unresolved choice between matching configurations. The first offset is a consequence of search order, not evidence that the block is active.
