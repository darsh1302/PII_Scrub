# Functionality, Prompts and Expected Behaviour

## Capabilities

The agent has six tools. They are deliberately coarse: one call performs a whole
stage, so the pipeline cannot be left half-executed by a reasoning step that
stopped early.

| Tool | Purpose |
|---|---|
| `list_sources` | List scannable files in the scan roots, plus anything loaded this session |
| `scan` | Detect and report. Produces no cleaned copy. |
| `scrub` | Detect, apply policy, verify, and produce a cleaned copy |
| `explain_profile` | Describe what a profile detects and how it handles each type |
| `export` | Confirm a cleaned artifact is available |
| `set_preference` | Remember a profile, destination, threshold, locale or action for the session |

There is deliberately no detokenization tool. `build_registry` raises if any tool
name contains `detokenize`, `reverse`, `unmask`, `reveal` or `decrypt`. Reversal is
an out-of-band operator action, because a reversal capability inside the agent
turns prompt injection into an exfiltration primitive.

## Getting content in

**Upload** — drag a `.txt`, `.log`, `.json`, `.jsonl`, `.csv` or `.xml` file into
the uploader. Uploads bypass the scan-root allowlist because you supplied the
bytes; there is no filesystem to escape. Size and type limits still apply. The
bytes are held in memory and never written to disk.

**By path** — reference a file inside `PII_AGENT_SCAN_ROOTS`. Anything outside is
refused, as are sensitive paths inside a root.

**Paste** — paste text directly into chat, subject to a character limit.

Refer to an upload by the name shown in the confirmation. A bare filename
resolves to session-loaded content first; anything containing a path separator is
treated as an explicit filesystem request and goes through containment, so a label
can never shadow a path.

## Prompts

The agent interprets intent broadly. "Find PII", "is there anything sensitive in
here", "scrub this" and "anonymize it" are the same request.

### Recommended

```
scrub large.txt with DEFAULT_PII for INTERNAL_SIEM
```

One line supplying source, profile and destination. Nothing to ask back.

### Report only

```
scan large.txt with DEFAULT_PII for INTERNAL_SIEM
```

Gives the findings table without producing a cleaned copy.

### Both, in one turn

```
scan large.txt for INTERNAL_SIEM and give me a clean copy
```

### Other useful phrasings

```
what can you scan?
what does DEFAULT_PII cover?
scrub it and redact everything
use BASE_SECURITY on app.log for FILE
scan large.txt for EXTERNAL_LLM
remember that my destination is INTERNAL_SIEM
```

"It" and "that file" resolve to the most recent source in session memory.

### Efficiency note

`scrub` runs the full scan internally. Running `scan` and then `scrub` processes
the file twice and doubles the wait for no additional information. Go straight to
`scrub` when you know you want the output.

## Destination

Where the cleaned data is going. Required whenever a destination-sensitive type is
present, and the agent asks rather than guessing.

| Destination | Meaning |
|---|---|
| `INTERNAL_SIEM` | Staying inside your infrastructure for security analysis |
| `FILE` | A local copy you are keeping |
| `EXTERNAL_ANALYTICS` | A third-party analytics platform |
| `EXTERNAL_LLM` | Pasting into a hosted model |
| `S3` | Object storage, treated as external |

In `DEFAULT_PII`, two types are destination-aware:

- `IP_ADDRESS` — `ALLOW` for `INTERNAL_SIEM`, `REPLACE` for `FILE`, `REDACT` for
  the three external destinations
- `DATE_TIME` — `ALLOW` for `INTERNAL_SIEM`

Nothing else changes. Credentials, SSNs, cards and names are handled identically
regardless of destination, and a destination can only make policy stricter, never
weaker.

The reasoning: a log with every timestamp and source IP stripped cannot be
correlated, which defeats the purpose of keeping logs. Inside your own SIEM those
identifiers are the investigation. Sent to a vendor, the same IP is personal data.
Guessing either way is wrong, so the agent asks.

## Scrub actions

| Action | Output | Preserves correlation | Reversible |
|---|---|---|---|
| `ALLOW` | untouched | yes | n/a |
| `REPLACE` | `[US_SSN]` | no | no |
| `MASK` | `****` | no | no |
| `HASH` | `[US_SSN:a3f9c2e1b7d40856]` | yes | no, but guessable on small domains |
| `TOKENIZE` | stable vault token | yes | out-of-band only |
| `REDACT` | `[REDACTED:US_SSN]` | no | no |
| `BLOCK` | no artifact at all | n/a | n/a |

`MASK` uses a fixed 8 characters for HIGH-severity entities rather than matching
length — a nine-character masked SSN still discloses format and narrows the value.

`BLOCK` is not a synonym for `REDACT`. `REDACT` removes a span and still yields
output; `BLOCK` suppresses the entire artifact and is handled before any
application, so half-sanitized output is never produced.

You do not choose actions per entity — the profile does. Requests for stricter
handling are honoured; requests for weaker handling are discarded and reported as
denied. That is the ratchet.

## Profiles

| Profile | Status |
|---|---|
| `BASE_SECURITY` | Built. Credentials and secrets. Inherited by everything, always applied. |
| `DEFAULT_PII` | Built. Baseline personal identifiers. Applied when no profile is named. |
| `PAYMENT_PCI` | Built. Card data tokenized, authentication data removed, track data blocks the artifact. |
| `FINANCIAL` | Built. Account identifiers tokenized to keep records correlatable; scores, tax ids and wire details removed. |
| `AI_SAAS` | Built. LLM telemetry: prompts, completions, agent memory, tool traffic, retrieval payloads, embeddings. |
| `HEALTHCARE`, `RETAIL`, `EDUCATION`, `HR_PAYROLL`, `LEGAL`, `GOVERNMENT`, `TELECOM`, `AUTOMOTIVE` | Specified in requirements, not yet built |

### PAYMENT_PCI

PCI-DSS separates two categories and the profile follows that split. Cardholder
data may be stored if rendered unreadable, so the PAN is `TOKENIZE` — unreadable,
but the same card is still recognisable across records, which is what makes a
payment log usable for reconciliation. Sensitive authentication data must never be
retained, so CVV and PIN are `REDACT` and can never be tokenized. Full track data
is `BLOCK`: no cleaned copy is produced at all, because a redacted copy would
still evidence that stripe data was written somewhere it should not have been.

### FINANCIAL

Account identifiers are `TOKENIZE` rather than `REDACT`, because fraud and dispute
work depends on telling whether two records concern the same account. Redacting
every account number yields a file that is safe and useless.

Routing numbers and SWIFT codes are `MASK`, not tokenized: they identify an
institution rather than a customer, and there are few enough in circulation that a
per-value token would be re-identifiable by frequency — a token would imply
protection it cannot deliver. Credit scores are `REDACT`, since nobody joins on a
score, so a correlatable form buys nothing.

### AI_SAAS

For LLM application logs and agent traces. An LLM app logs its own traffic, and
that traffic is whatever the user typed — so prompt logs quietly become some of the
most PII-dense artifacts a company holds.

Payload fields are `REDACT` rather than `REPLACE`, because a payload is free text
of unknown composition rather than an identifier with a known shape. Masking it
would imply its contents had been assessed. `SYSTEM_PROMPT` is the exception at
`REPLACE`, since many system prompts are published and the profile shouldn't assert
that every one is a secret.

Embeddings are detected and redacted. A logged vector is not opaque — inversion
attacks recover substantial portions of the source text, so it ranks with the text
it encodes rather than with a hash.

New types: `MODEL_PROVIDER_TOKEN`, `USER_PROMPT`, `SYSTEM_PROMPT`,
`MODEL_COMPLETION`, `AGENT_MEMORY`, `TOOL_ARGUMENTS`, `TOOL_RESPONSE`,
`RETRIEVED_DOCUMENT`, `VECTOR_EMBEDDING`.

**What it does not detect.** Requirement 24.1 also lists proprietary source code
and free-form confidential customer content. Neither has a format, and no
recognizer for them exists. A clean `AI_SAAS` result is not evidence that no
proprietary content is present.

New entity types behind the financial profiles: `ROUTING_NUMBER` (ABA checksum enforced),
`SWIFT_CODE`, `CVV`, `PIN`, `TRACK_DATA`, `CARD_EXPIRY`, `FINANCIAL_ACCOUNT`,
`TAX_IDENTIFIER`, `CREDIT_SCORE`, `WIRE_INSTRUCTIONS`. Every low-entropy numeric
type requires an adjacent field label — matching three bare digits as a CVV would
flag every HTTP status and port number in a log.

Every industry profile resolves to `BASE_SECURITY + DEFAULT_PII + domain-specific`
rules. Naming an unbuilt profile fails at profile resolution rather than silently
falling back — a silent fallback would report coverage the profile did not deliver.

`DEFAULT_PII` covers `PERSON`, `EMAIL_ADDRESS`, `PHONE_NUMBER`, `US_SSN`,
`CREDIT_CARD`, `US_PASSPORT`, `US_DRIVER_LICENSE`, `US_BANK_NUMBER`, `IBAN_CODE`,
`MEDICAL_LICENSE`, `LOCATION`, `IP_ADDRESS`, `DATE_TIME` and `URL`.

`BASE_SECURITY` covers passwords, API keys, AWS keys, access and refresh tokens,
OAuth tokens, JWTs, authorization headers, client secrets, session cookies, PEM
and SSH private keys, database credentials, cloud credentials and
credential-bearing connection strings.

## Results

A completed run produces:

- **Findings table** — entity type, severity, masked preview, confidence, which
  detector found it, and the resolved action. Previews show a type label only for
  HIGH-severity entities, so credentials never render to screen. Confidence from
  spaCy is marked `(heuristic)` because spaCy emits a constant, not a calibrated
  probability.
- **Coverage** — bytes and chunks processed against totals, which detectors were
  healthy, and whether anything was missing.
- **Downloads** — `<name>-cleaned.<ext>` and `<name>-findings.json`. Nothing is
  written to disk; the download is the egress path, and the artifact dies with the
  session.
- **Provenance** — profile version and exact engine versions, so the run can be
  reproduced.
- **Audit record** — appended to the hash-chained JSONL, containing no sensitive
  data.

## Refusals

Refusals are named outcomes, not errors. Findings are still reported in every
case; only the artifact is withheld.

| Refusal | Meaning | What changes it |
|---|---|---|
| `NEEDS_DESTINATION` | Handling depends on where the data is going | Name a destination |
| `DEGRADED_COVERAGE` | Part of the source could not be inspected, or a detector was unavailable | Fix the detector, or scan a smaller scope |
| `BLOCKED_ARTIFACT` | Policy forbids any cleaned copy of this content | Nothing — this is the intended outcome |
| `RESIDUAL_PII_DETECTED` | Verification found something the scrub should have removed | Nothing you can do; this is a defect to report |
| `INVALID_PROFILE` | Profile missing or failed schema validation | Name a built profile |
| `TIMEOUT` | Exceeded the time budget, so coverage is incomplete | Smaller file, or raise the budget |
| `LIMIT_EXCEEDED` | Source is over a configured limit | Split the source |
| `SOURCE_ERROR` | Source could not be read | Check the path and permissions |

If the agent's prose disagrees with the status fields, trust the fields. The model
writes the prose; the core sets `refusal`, `artifact_available` and
`verified_clean`.

## Security findings

If the content contains prompt-injection patterns, they are reported as an
observation about the source. They never block a cleaned copy and never change a
scrub action. The included sample files contain planted payloads on purpose so
this path stays exercised.

Seeing this on a genuine production log is worth investigating upstream: something
is writing attacker-controlled text into your logs.

## Performance

| Input | Time |
|---|---|
| 3.3 KB | ~5 s |
| 260 KB | ~110 s |
| 10 MB | over an hour — not currently practical |

Throughput is roughly 2.4 KB/s. Profiled, Presidio's `analyze` accounts for 79%,
within which its own spaCy pipeline is 19% — duplicating NLP work we already do.
The verification re-scan is a further 39% and is not negotiable. Chunks are
independent by construction, so parallelism is available but not yet implemented.

## What the agent will not do

- Reveal a tokenized value
- Choose a weaker action than policy mandates, even if asked directly
- Produce a cleaned copy when coverage was incomplete
- Certify compliance. It assists with detection; it does not replace a compliance
  programme, and automated detection never catches everything.
