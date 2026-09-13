# Home SOC / SIEM Detection Lab

A working detection engineering lab: Windows and Linux endpoint telemetry forwarded into
Microsoft Sentinel, attacker behaviour emulated with Atomic Red Team, and a Sigma/KQL
detection written, validated and tuned for each technique.

Every detection in this repo has a case file documenting how it was built, what it misses,
and what it got wrong before it got right.

---

## Architecture

```
win-11-SIEM (Windows 11)  ─┐
   Sysmon (SwiftOnSecurity) │
                            ├─→ Azure Arc → Azure Monitor Agent → Log Analytics
Ubuntu-SIEM (Ubuntu 26.04) ─┘        (DCRs)         (Home-soc-workspace)
   Sysmon for Linux (MSTIC)                                  │
                                                             ↓
                                                   Microsoft Sentinel
                                              (scheduled analytics rules)
```

**Stack:** Microsoft Sentinel · Log Analytics · Azure Arc · Azure Monitor Agent · Sysmon ·
Atomic Red Team · KQL · Sigma

---

## Detections

| Tactic                  | Technique                                                         | Telemetry     | Incidents before → after tuning |
| ----------------------- | ----------------------------------------------------------------- | ------------- | ------------------------------- |
| Execution               | [T1059.001](detections/T1059.001.md) — Encoded PowerShell         | Sysmon EID 1  | 7 → 1                           |
| Persistence / Execution | [T1053.005](detections/T1053.005.md) — Scheduled Task             | Sysmon EID 1  | 6 → 1                           |
| Persistence / Priv Esc  | [T1547.001](detections/T1547.001.md) — Registry Run Keys          | Sysmon EID 13 | 3 → 1                           |
| Command & Control       | [T1071.001](detections/T1071.001.md) — Malicious User Agents      | Sysmon EID 1  | 12 → 1                          |
| Collection              | [T1560.001](detections/T1560.001.md) — Password-Protected Archive | Sysmon EID 1  | 3 → 1                           |

Reductions are **duplicate incidents from true positives**, measured with controlled
before/after batches of identical attacker activity. They are not false positive
reductions.

---

## Findings worth reading

Each technique produced a different problem. These are the ones that took real work.

### A detection that fired every time and detected nothing

The first T1059.001 rule matched `whoami.exe` and `hostname.exe` and hit on 100% of test
runs. Process-creation timestamps showed both firing _before_ the payload — they were
emitted by `Invoke-AtomicTest` stamping its own execution log, not by the technique. The
rule was detecting the test harness. Rewritten against the `-EncodedCommand` parameter,
with a regex covering every valid PowerShell parameter prefix (`-e`, `-en`, `-enc` …),
since attackers use the short forms to evade literal matching.

→ [T1059.001](detections/T1059.001.md)

### Legitimate software that matches every malicious heuristic

OneDrive writes `RunOnce\Uninstall → cmd.exe /q /c rmdir /s /q "...\OneDrive\..."`. A Run
key, pointing at a script interpreter, from a user AppData path, executing a delete. Every
heuristic that normally flags malicious persistence fires on it. Filtering on value data or
user paths both fail. What actually separates it from the attack is the _writing process_ —
legitimate installers use the Windows API, the attack shells out to `reg.exe`. Anchoring on
that field took 48 hours of results from 5 matches to 1.

→ [T1547.001](detections/T1547.001.md)

### A sensor blind spot, found by the technique failing to appear

T1071.001 detects C2 beaconing by its user agent string. Running it produced four
process-creation events and **zero network-connection events**. Two stacked blind spots:
user agents live in the HTTP layer that Sysmon does not inspect, and the Sysmon config's
`<NetworkConnect onmatch="include">` allowlist excludes `C:\Windows\System32\`, so
`curl.exe`'s connections were never logged at all. The detection was rebuilt on process
telemetry, and the case file states plainly that this lab can detect the _test_ but not the
_technique_ — closing that needs proxy or network-sensor data, not a better query.

→ [T1071.001](detections/T1071.001.md)

### A signal that cannot be separated from normal behaviour

Password-protected archives defeat DLP content inspection, which is why adversaries create
them before exfiltration. Users create them too, constantly, and the command lines are
identical. No refinement of the query fixes this — the difference is context, not content.
Rated `low` and documented as a contributing signal for correlation rather than a
standalone alert.

→ [T1560.001](detections/T1560.001.md)

### Two tuning levers that get conflated

Sentinel reduces noise at two independent stages: **event grouping** (query results →
alerts) and **alert grouping** (alerts → incidents). Measuring one while the other is
already active produces numbers that look good and mean nothing. Every figure in the table
above comes from disabling both, running a fixed batch, then enabling both and running an
identical batch.

→ [T1053.005](detections/T1053.005.md)

---

## Working with flattened Sysmon telemetry

The Windows DCR uses the Custom XPath collection method, which routes Sysmon data to the
classic **`Event`** table rather than `WindowsEvent`. Every field is flattened into a single
unlabelled `ParameterXml` column as a list of `<Param>` values, so there are no named
fields to query.

Two consequences shaped most of the rules here:

**String matching cannot tell which field a value came from.** A `has_any` filter on
`cmd.exe` matches whether `cmd.exe` was the acting process or merely mentioned in a command
line. The fix is to anchor on position — the acting process image is always the parameter
immediately after the numeric PID:

```kql
| where ParameterXml matches regex @"(?i)<Param>\d+</Param><Param>[^<]*\\(reg|powershell|cmd)\.exe</Param>"
```

`[^<]*` rather than `.*`, because `.*` is greedy and silently crosses `<Param>` boundaries.

**The content is XML-escaped.** `>nul 2>&1` is stored as `&gt;nul 2&gt;&amp;1`. A literal
match on any string containing `<`, `>` or `&` fails silently — which would have broken an
IOC-list version of the T1071.001 rule while leaving its other matches working.

---

## Repo structure

```
home-soc-lab/
├── README.md
├── configs/          Sysmon configurations for both hosts
├── rules/            Sigma rules, one per technique
├── detections/       Case file per technique: attack, telemetry, rule,
│                     design decisions, false positives, tuning, coverage gaps
└── screenshots/      Evidence for each case file
```

---

## Method

Each technique follows the same loop:

1. Select and read the atomic test (`-ShowDetailsBrief`, then `-ShowDetails` on one test)
2. Run it once and confirm the telemetry lands
3. **Validate the artefact belongs to the technique, not the test harness**
4. Write the KQL analytics rule and a matching Sigma rule
5. Measure a baseline with both grouping levers disabled
6. Enable both, re-run an identical batch, measure again
7. Document the design decisions, false positives and coverage gaps
8. Clean up

---

## Scope and limitations

- Two hosts. Volumes and background noise are not representative of an enterprise estate,
  and several false positive findings here would be far larger at scale.
- Endpoint telemetry only. No proxy logs, network sensor or TLS inspection, which is a
  stated limitation for the C2 detection.
- Some ATT&CK tactics are not covered, notably Defense Evasion and Credential Access.
  Credential Access in particular needs `ProcessAccess` (Sysmon EID 10) telemetry that the
  current config does not produce.
- Rules are written against the flattened `Event` table schema. The Sigma equivalents in
  `rules/` target normalised fields and are portable; the KQL is specific to this pipeline.
