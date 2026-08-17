# Demo Script — PII Scrubbing Agent

Target length **4 minutes**. Record against the **local** app, not the cloud demo:
locally you get the full `en_core_web_lg` model, so `sample.txt` yields 51
entities instead of the reduced count the small model finds. The numbers are the
evidence, so use the better ones.

## Before you record

```bat
venv\Scripts\streamlit run app.py --server.address 127.0.0.1
```

- Browser at 100% zoom, window maximised, no other tabs visible
- Have `sample.txt` ready in an Explorer window for the drag-and-drop
- Do a full dry run first. The scan takes about five seconds and you want to know
  exactly when the table appears
- Sidebar expanded so Component health is visible

Do not show `.env` on screen at any point.

---

## Beat 1 — The problem (0:00–0:25)

*Screen: `sample.txt` open in an editor, scrolling slowly.*

> This is an application log. Buried in it are social security numbers, credit
> cards, an AWS access key, and a private key block. Somebody needs to send this
> to a vendor, or paste it into a model, and none of that can go with it.
>
> Doing this by hand does not scale, and a regex sweep gives you output you cannot
> defend — no record of what was searched for, no evidence the whole file was
> covered.

## Beat 2 — Ask for it in plain language (0:25–0:50)

*Screen: drag `sample.txt` into the uploader. Type the prompt.*

```
scrub sample.txt with DEFAULT_PII for INTERNAL_SIEM
```

> I upload the file and ask in plain English. I named a destination — internal
> SIEM — and that matters in a second.

*Let the status line show EXECUTING.*

## Beat 3 — The findings (0:50–1:35)

*Screen: findings table. Scroll it. Hover the severity column.*

> Fifty-one entities. Type, severity, confidence, which engine found it, and what
> policy decided to do with each one.
>
> Two things to notice. The high-severity rows show a type label instead of a
> preview — a detected credential is never rendered to screen. And the spaCy
> confidences are marked heuristic, because spaCy emits a constant rather than a
> calibrated probability, and presenting those as comparable would be misleading.
>
> Coverage says one hundred percent of 3,319 bytes, all three detectors healthy.
> That claim is what the next part depends on.

## Beat 4 — Destination changes the answer (1:35–2:20)

*Screen: point at the action counts — 31 ALLOW, 11 REDACT, 5 REPLACE, 4 MASK.*

> Thirty-one entities were allowed through. Those are timestamps and internal IP
> addresses, and they were kept on purpose. A log with every timestamp and source
> IP stripped cannot be correlated, which defeats the point of keeping logs.

*Type the same request with a different destination:*

```
scrub sample.txt for EXTERNAL_LLM
```

> Same file, one word different. Now those same IPs are redacted, because sent
> outside your infrastructure an IP address is personal data rather than
> operational data.
>
> Nothing about the file changed. The policy engine reasoned about where the data
> was going.

## Beat 5 — The injection attempt (2:20–3:00)

*Screen: the red security-findings panel.*

> This file also contains text written to manipulate an AI agent. Instructions to
> skip redaction, a false claim that the scan found nothing, a fake assistant turn
> saying the file is clean.
>
> They had no effect, and the reason is architectural. The language model never
> received the file. It got counts, type names and opaque handles. Detection,
> policy and redaction all happen in code that imports no LLM library at all —
> there is a test that proves it by inspecting loaded modules in a subprocess.
>
> An injected instruction cannot pick a weaker action, because the model does not
> pick actions. Policy resolution is a maximum over a strictness ordering, so a
> request can only ever ratchet upward.

## Beat 6 — The output, and what it is not (3:00–3:40)

*Screen: click the download, open the cleaned file side by side with the original.*

> Here is the cleaned copy. The SSN is gone, the card is masked, the key is
> redacted, and the timestamps survived.
>
> It was verified before you were allowed to have it: the output is re-scanned, and
> if anything the scrub was supposed to remove is still present, the file is
> withheld and the run is reported as a defect. Nothing is written to disk — the
> download is the only way out.
>
> Alongside it there is an audit record. Entity counts, a hash of the source name
> rather than the name, the profile version, and the exact engine versions, chained
> by hash so a record cannot be quietly edited.

## Beat 7 — Honest close (3:40–4:00)

*Screen: back to the findings table, or the repo README.*

> Two things it does not do. Name recall is imperfect in terse log syntax, so
> findings are a floor rather than a guarantee. And throughput is about two and a
> half kilobytes a second, because Presidio runs its own NLP pipeline on top of
> ours — that is measured, and it is the next thing to fix.
>
> It assists with detection. It does not certify compliance.

---

## Notes

**Do not** demo `sample_large.txt` live — 260 KB takes about 110 seconds. If you
want to show scale, record it separately and cut to the finished result: 3,339
entities, 7 chunks, verified clean.

If you want a refusal on camera, ask for a scrub with no destination and show the
`NEEDS_DESTINATION` response. It demonstrates that the agent asks rather than
guessing, and it takes ten seconds.

The strongest single moment is Beat 4 — same file, one word changed, different
policy outcome. If you only have ninety seconds, record beats 2, 4 and 6.
