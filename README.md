# sbom-license-gate

A software bill of materials tells you what you ship. It does not tell you whether you may ship it. sbom-license-gate reads a CycloneDX SBOM and checks every component licence against a policy, so a copyleft or source-available surprise is caught in CI and not in due diligence.

**Live demo:** https://jvch0512.github.io/sbom-license-gate/ (a report on the synthetic SBOM in `examples/`)

Java 17+, no dependencies, offline. Includes its own strict JSON parser.

## Use

```bash
mkdir -p out && javac -d out src/main/java/gate/*.java
java -cp out gate.Main sbom.json
java -cp out gate.Main sbom.json --html > report.html
java -cp out gate.Main sbom.json --fail-on denied          # exit 1 in CI
java -cp out gate.Main sbom.json --allow "MIT,Apache-2.0" --deny "GPL-3.0-only"
```

Verdicts: `DENIED` (on the deny list), `REVIEW` (copyleft, unknown, or no licence declared), allowed components are not listed. Exit codes: 0 ok, 1 findings at or above `--fail-on`, 2 bad input.

SPDX expressions are evaluated: `A OR B` passes if the best option passes, `A AND B` needs the worst, and `WITH` exceptions are read as their base licence.

See [examples/sbom.json](examples/sbom.json) and [docs/sample-output.txt](docs/sample-output.txt).

## Default policy

Allowed: MIT, Apache-2.0, BSD-2/3-Clause, ISC, 0BSD, Unlicense, CC0-1.0, Zlib and similar permissive licences. Denied: AGPL-3.0, SSPL-1.0, BUSL-1.1, Commons Clause, CPAL-1.0. Review: GPL, LGPL, MPL, EPL, CDDL, anything unknown. Replace any list from the command line.

## Limits

- It checks declared licences. If the SBOM is wrong or incomplete, so is the verdict.
- Copyleft is not forbidden by itself: it depends on how code is linked and distributed. That is why it is `REVIEW`, not `DENIED`.
- `WITH` exceptions (for example the Classpath exception) are not credited, which is conservative.
- A policy check, not legal advice.

## Where it fits

Release gate in CI, supplier and M&A due diligence, and a fixed-price "open source licence audit" for companies preparing a funding round or an acquisition.

## Tests

```bash
java -cp out gate.GateTest   # 23 checks
```

MIT.
