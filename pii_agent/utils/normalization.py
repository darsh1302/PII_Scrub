"""Unicode normalization with reversible offset mapping.

Guardrail G13 (partly), Requirement 33. Addresses SEC-11's sibling problem:
adversarial evasion via character manipulation.

Detection must run over normalized text — otherwise a zero-width space inside an
SSN defeats every pattern. But every offset we report has to refer to the
*original* document, because that is what the applier will modify. Normalizing
without an index map silently shifts offsets, and the scrub lands on the wrong
span.

So ``normalize`` returns an ``IndexMap`` alongside the text. Every normalized
character records which original character it came from, which makes the
transformation reversible for spans even though it is lossy for content.

Deliberately excluded: NFKC normalization. It rewrites too much (ligatures,
full-width digits, superscripts) and its offset behaviour is one-to-many, which
would complicate the map for little detection benefit. Targeted substitutions
are predictable and auditable.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

# Characters that carry no visual meaning but break pattern matching.
# A zero-width space inside "482-71-9053" defeats every SSN regex.
INVISIBLE_CHARS = frozenset(
    {
        "\u200b",  # zero width space
        "\u200c",  # zero width non-joiner
        "\u200d",  # zero width joiner
        "\u2060",  # word joiner
        "\ufeff",  # zero width no-break space / BOM
        "\u00ad",  # soft hyphen
        "\u180e",  # mongolian vowel separator
        "\u200e",  # left-to-right mark
        "\u200f",  # right-to-left mark
        "\u202a",  # left-to-right embedding
        "\u202b",  # right-to-left embedding
        "\u202c",  # pop directional formatting
        "\u202d",  # left-to-right override
        "\u202e",  # right-to-left override
        "\u2066",  # left-to-right isolate
        "\u2067",  # right-to-left isolate
        "\u2068",  # first strong isolate
        "\u2069",  # pop directional isolate
    }
)

# Visually identical characters from other scripts. Cyrillic а/е/о and Greek
# ο/ν are the common ones — they render identically to Latin in most fonts.
HOMOGLYPHS: dict[str, str] = {
    # Cyrillic → Latin
    "\u0430": "a", "\u0410": "A",
    "\u0435": "e", "\u0415": "E",
    "\u043e": "o", "\u041e": "O",
    "\u0440": "p", "\u0420": "P",
    "\u0441": "c", "\u0421": "C",
    "\u0443": "y", "\u0423": "Y",
    "\u0445": "x", "\u0425": "X",
    "\u0456": "i", "\u0406": "I",
    "\u0458": "j", "\u0408": "J",
    "\u04bb": "h", "\u041d": "H",
    "\u0412": "B", "\u041c": "M",
    "\u041a": "K", "\u0422": "T",
    # Greek → Latin
    "\u03bf": "o", "\u039f": "O",
    "\u03b1": "a", "\u0391": "A",
    "\u03b5": "e", "\u0395": "E",
    "\u03c1": "p", "\u03a1": "P",
    "\u03c5": "u", "\u03a5": "Y",
    "\u03bd": "v", "\u039d": "N",
    "\u03ba": "k", "\u039a": "K",
    "\u03b9": "i", "\u0399": "I",
    "\u0392": "B", "\u0397": "H",
    "\u039c": "M", "\u03a4": "T",
    "\u03a7": "X", "\u0396": "Z",
    # Fullwidth digits and letters → ASCII
    "\uff10": "0", "\uff11": "1", "\uff12": "2", "\uff13": "3", "\uff14": "4",
    "\uff15": "5", "\uff16": "6", "\uff17": "7", "\uff18": "8", "\uff19": "9",
    # Mathematical alphanumerics commonly used for evasion
    "\U0001d5ba": "a", "\U0001d5be": "e", "\U0001d5c8": "o",
    # Lookalike punctuation used to break separators
    "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-",
    "\u2014": "-", "\u2212": "-", "\uff0d": "-",
    "\u2044": "/", "\uff0f": "/",
    "\uff1a": ":", "\uff0e": ".",
    "\u02d0": ":",
}


@dataclass
class IndexMap:
    """Maps normalized character offsets back to original ones.

    ``positions[i]`` is the original offset of normalized character ``i``.
    """

    positions: list[int] = field(default_factory=list)
    original_length: int = 0

    def to_original(self, start: int, end: int) -> tuple[int, int]:
        """Translate a normalized span to original coordinates.

        The end is derived from the last included character rather than from
        ``positions[end]``: the normalized span may end at the text boundary,
        and removed characters mean ``positions[end]`` is not simply
        ``positions[end - 1] + 1``.
        """
        if not self.positions:
            return (start, end)

        clamped_start = max(0, min(start, len(self.positions) - 1))
        original_start = self.positions[clamped_start]

        if end <= start:
            return (original_start, original_start)

        last_index = min(end, len(self.positions)) - 1
        if last_index < 0:
            return (original_start, original_start)

        original_end = self.positions[last_index] + 1
        return (original_start, min(original_end, self.original_length))

    @property
    def is_identity(self) -> bool:
        """True when normalization changed nothing positional."""
        return all(i == pos for i, pos in enumerate(self.positions))


@dataclass
class NormalizationResult:
    text: str
    index_map: IndexMap
    invisible_removed: int = 0
    homoglyphs_folded: int = 0

    @property
    def was_modified(self) -> bool:
        return bool(self.invisible_removed or self.homoglyphs_folded)

    @property
    def evasion_signals(self) -> list[str]:
        """Human-readable signals worth reporting to the user.

        Invisible characters inside otherwise-normal text are rarely accidental.
        Their presence is itself a finding (Requirement 33.6).
        """
        signals: list[str] = []
        if self.invisible_removed:
            signals.append(
                f"{self.invisible_removed} zero-width or bidirectional control "
                "character(s) removed before matching — these can split "
                "patterns to evade detection"
            )
        if self.homoglyphs_folded:
            signals.append(
                f"{self.homoglyphs_folded} homoglyph(s) folded to ASCII — "
                "visually identical characters from other scripts"
            )
        return signals


def normalize(text: str) -> NormalizationResult:
    """Normalize for detection, preserving a map back to original offsets.

    Applied transformations:

    * Invisible and bidirectional control characters are removed.
    * Homoglyphs are folded to their ASCII equivalents.
    * Combining marks are stripped from otherwise-ASCII letters (``é`` → ``e``).

    Character count may shrink but never grows, so a normalized offset always
    has exactly one original source.
    """
    if not text:
        return NormalizationResult(text="", index_map=IndexMap(original_length=0))

    out: list[str] = []
    positions: list[int] = []
    invisible = 0
    folded = 0

    for original_index, char in enumerate(text):
        if char in INVISIBLE_CHARS:
            invisible += 1
            continue

        replacement = HOMOGLYPHS.get(char)
        if replacement is not None:
            folded += 1
            out.append(replacement)
            positions.append(original_index)
            continue

        # Decompose accented Latin to its base letter. Only when the base is
        # ASCII, so non-Latin scripts are left intact.
        if ord(char) > 127:
            decomposed = unicodedata.normalize("NFD", char)
            base = decomposed[0]
            if base.isascii() and base.isalnum():
                folded += 1
                out.append(base)
                positions.append(original_index)
                continue

        out.append(char)
        positions.append(original_index)

    return NormalizationResult(
        text="".join(out),
        index_map=IndexMap(positions=positions, original_length=len(text)),
        invisible_removed=invisible,
        homoglyphs_folded=folded,
    )


# A run of single characters separated by single spaces or tabs, four or more
# long: "4 8 2 - 7 1 - 9 0 5 3". Multi-character tokens are excluded by
# construction, which is what keeps ordinary log lines out of scope — "port=443
# id=12" has two-and-three character tokens and never matches.
#
# The lookarounds matter. Without the trailing one the run greedily swallows the
# first character of the next token — "9 0 5 3 status" collapses to
# "9053status", and the SSN pattern then fails its own word boundary, so the
# defence silently does nothing. Without the leading one a run can start
# mid-token.
_SPACED_RUN = re.compile(
    r"(?<![0-9A-Za-z\-])(?:[0-9A-Za-z\-][ \t]){3,}[0-9A-Za-z\-](?![0-9A-Za-z\-])"
)


def collapse_spaced_characters(text: str) -> tuple[str, IndexMap]:
    """Remove the spacing from runs of individually-spaced characters.

    Targeted rather than global. ``strip_whitespace_runs`` below removes *all*
    whitespace, which would join adjacent fields — ``port=443 id=12`` becomes
    ``port=443id=12`` and a nine-digit run appears that was never in the source.
    Manufacturing an SSN out of two unrelated numbers is a worse failure than
    missing a spaced one, because it refuses correct artifacts and destroys real
    data.

    So only runs of single characters are collapsed, which is the shape the attack
    actually takes. Returns the rewritten text and a map from its offsets back to
    the input's.
    """
    if not text:
        return "", IndexMap(original_length=0)

    matches = list(_SPACED_RUN.finditer(text))
    if not matches:
        return text, IndexMap(
            positions=list(range(len(text))), original_length=len(text)
        )

    spans = {(m.start(), m.end()) for m in matches}
    drop: set[int] = set()
    for start, end in spans:
        for index in range(start, end):
            if text[index] in " \t":
                drop.add(index)

    out: list[str] = []
    positions: list[int] = []
    for index, char in enumerate(text):
        if index in drop:
            continue
        out.append(char)
        positions.append(index)

    return "".join(out), IndexMap(positions=positions, original_length=len(text))


def strip_whitespace_runs(text: str) -> tuple[str, IndexMap]:
    """Collapse whitespace inserted to break patterns.

    ``4 8 2 - 7 1 - 9 0 5 3`` should match an SSN pattern. Applied as a separate
    second pass rather than inside ``normalize`` because it changes token
    structure and is only worth running when a first pass found nothing.
    """
    out: list[str] = []
    positions: list[int] = []

    for index, char in enumerate(text):
        if char.isspace():
            continue
        out.append(char)
        positions.append(index)

    return "".join(out), IndexMap(positions=positions, original_length=len(text))
