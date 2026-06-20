"""
filters/input/unicode_firewall.py
==================================
Unified Unicode Attack Firewall — wraps the unified_unicode_firewall module.

Detects:
  • Emoji steganography (Unicode Tags, variation selectors, ZW binary encoding)
  • Homoglyph / visual-spoofing attacks (Cyrillic/Greek lookalikes, fullwidth, Zalgo)

Two modes:
  • "prompt"   — user-typed text, zero tolerance
  • "document" — PDF/DOCX extracted text, strips extractor artifacts first
"""

import re
import math
import collections
import unicodedata
import spacy
from spacy.tokens import Doc
from typing import Dict, Any, Tuple

try:
    import tiktoken
    _ENC = tiktoken.get_encoding("cl100k_base")
except Exception:
    _ENC = None


# ── Confusable table ─────────────────────────────────────────────────────────
CONFUSABLES: dict = {
    'а': 'a', 'А': 'A', 'е': 'e', 'Е': 'E', 'о': 'o', 'О': 'O',
    'р': 'p', 'Р': 'P', 'с': 'c', 'С': 'C', 'і': 'i', 'І': 'I',
    'х': 'x', 'Х': 'X', 'у': 'y', 'У': 'Y', 'В': 'B', 'Ѕ': 'S',
    'ѵ': 'v', 'ԁ': 'd', 'ԍ': 'g', 'ԛ': 'q', 'ԝ': 'w',
    'ο': 'o', 'Ο': 'O', 'ρ': 'p', 'Ρ': 'P', 'ν': 'v', 'υ': 'u',
    'κ': 'k', 'Κ': 'K', 'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z',
    'Η': 'H', 'Ι': 'I', 'Μ': 'M', 'Ν': 'N', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
    'ɑ': 'a', 'ɡ': 'g', 'ℓ': 'l', 'ⅼ': 'l', 'ⅰ': 'i', 'ⅴ': 'v', 'ⅹ': 'x',
    'ո': 'n', 'ս': 'u',
}

# ── Pre-compiled regex patterns ───────────────────────────────────────────────
_TAG_RE        = re.compile(r'[\U000E0020-\U000E007F]')
_VS_EXT_RE     = re.compile(r'[\U000E0100-\U000E01EF]')
_VS_STD_RE     = re.compile(r'[\uFE00-\uFE0F]')
_ZW_ALL_RE     = re.compile(r'[\u200B\u200C\u200D\uFEFF]')
_BIDI_RE       = re.compile(r'[\u202A-\u202E\u2066-\u2069]')
_ZW_RUN_RE     = re.compile(r'[\u200B\u200C]{8,}')
_PUA_RE        = re.compile(r'[\uE000-\uF8FF\U000F0000-\U000FFFFD\U00100000-\U0010FFFD]')
_HIDDEN_RE     = re.compile(r'[\U000E0020-\U000E007F\uFE00-\uFE0F\U000E0100-\U000E01EF\u200B-\u200D\uFEFF]')
_FULLWIDTH_RE  = re.compile(r'[\uFF01-\uFF5E]')
_MATH_ALPHA_RE = re.compile(r'[\U0001D400-\U0001D7FF]')
_ENCLOSED_RE   = re.compile(r'[\u2460-\u24FF\u3200-\u32FF]')
_MODIFIER_RE   = re.compile(r'[\u02B0-\u02FF\u2070-\u209F]')
_SOFT_SEP_RE   = re.compile(r'[\u00AD\u034F\u2060]')
_DOC_ARTIFACTS_RE = re.compile(r'[\u200B\u200C\u00AD\uFEFF\uFB00-\uFB06]')

_EMOJI_RANGES = [
    (0x1F300, 0x1FAFF), (0x2600, 0x27BF), (0x1F000, 0x1F02F),
    (0x231A, 0x231B), (0x23E9, 0x23F3), (0x25AA, 0x25AB),
    (0x25B6, 0x25C0), (0x25FB, 0x25FE), (0x2614, 0x2615),
    (0x2648, 0x2653), (0x267F, 0x267F), (0x2693, 0x2693),
    (0x26A1, 0x26A1), (0x26AA, 0x26AB), (0x26BD, 0x26BE),
    (0x2702, 0x2702), (0x2705, 0x2705), (0x2708, 0x270D),
    (0x2714, 0x2714), (0x2716, 0x2716), (0x2728, 0x2728),
    (0x274C, 0x274C), (0x274E, 0x274E), (0x2757, 0x2757),
    (0x2763, 0x2764), (0x2795, 0x2797), (0x27A1, 0x27A1),
    (0xFE0F, 0xFE0F),
]


# ── Helper functions ──────────────────────────────────────────────────────────

def _is_emoji_cp(ch: str) -> bool:
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi in _EMOJI_RANGES)


def _count_suspicious_zw(text: str) -> int:
    suspicious = 0
    chars = list(text)
    for i, ch in enumerate(chars):
        cp = ord(ch)
        if cp == 0x200D:
            prev_emoji = i > 0 and _is_emoji_cp(chars[i - 1])
            next_emoji = i < len(chars) - 1 and _is_emoji_cp(chars[i + 1])
            if prev_emoji and next_emoji:
                continue
        if cp in (0x200B, 0x200C, 0x200D, 0xFEFF):
            suspicious += 1
    return suspicious


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    length = len(text)
    return sum(
        -(c / length) * math.log2(c / length)
        for c in collections.Counter(text).values()
    )


def _count_visible_emojis(text: str) -> int:
    visible = _HIDDEN_RE.sub('', text)
    return sum(1 for ch in visible if _is_emoji_cp(ch))


def _get_script(char: str) -> str:
    cp = ord(char)
    if 0x0041 <= cp <= 0x007A: return 'LATIN'
    if 0x00C0 <= cp <= 0x024F: return 'LATIN'
    if 0x0400 <= cp <= 0x052F: return 'CYRILLIC'
    if 0x0370 <= cp <= 0x03FF: return 'GREEK'
    if 0x0530 <= cp <= 0x058F: return 'ARMENIAN'
    if 0x0030 <= cp <= 0x0039: return 'COMMON'
    if unicodedata.category(char) in ('Po', 'Ps', 'Pe', 'Pd', 'Zs'): return 'COMMON'
    return 'OTHER'


def _dominant_script(text: str) -> str:
    counts: dict = {}
    for c in text:
        s = _get_script(c)
        if s not in ('COMMON', 'OTHER'):
            counts[s] = counts.get(s, 0) + 1
    if not counts:
        return 'NONE'
    return max(counts, key=counts.__getitem__)


def _count_confusables(text: str) -> int:
    if _dominant_script(text) != 'LATIN':
        return 0
    return sum(1 for c in text if c in CONFUSABLES)


def _has_mixed_script_word(text: str) -> Tuple[bool, str]:
    for word in text.split():
        scripts = {_get_script(ch) for ch in word if _get_script(ch) not in ('COMMON', 'OTHER')}
        if len(scripts) > 1:
            return True, word
    return False, ''


def _count_combining(text: str) -> int:
    return sum(1 for c in text if unicodedata.category(c) in ('Mn', 'Me', 'Mc'))


def _strip_document_artifacts(text: str) -> str:
    text = _DOC_ARTIFACTS_RE.sub('', text)
    bidi_count = len(_BIDI_RE.findall(text))
    if bidi_count > 3:
        text = _BIDI_RE.sub('', text)
    return text


def _normalise_to_ascii(text: str) -> str:
    text = ''.join(CONFUSABLES.get(c, c) for c in text)
    text = ''.join(chr(ord(c) - 0xFEE0) if 0xFF01 <= ord(c) <= 0xFF5E else c for c in text)
    text = _SOFT_SEP_RE.sub('', text)
    return text


# ── spaCy pipeline components ─────────────────────────────────────────────────

_EXTENSIONS = {
    'is_blocked': False, 'block_reason': 'Clean', 'attack_vector': 'none',
    'scan_mode': 'prompt', 'tag_chars': 0, 'var_selectors': 0,
    'zero_width_sus': 0, 'hidden_ratio': 0.0, 'entropy': 0.0,
    'disparity_ratio': 0.0, 'total_tokens': 0, 'confusable_count': 0,
    'confusable_ratio': 0.0, 'mixed_script_word': '', 'fullwidth_count': 0,
    'math_alpha_count': 0, 'enclosed_count': 0, 'modifier_count': 0,
    'combining_count': 0, 'combining_ratio': 0.0, 'soft_sep_count': 0,
    'normalised_text': '',
}
for _ext, _default in _EXTENSIONS.items():
    Doc.set_extension(_ext, default=_default, force=True)


@spacy.Language.component('stego_layer')
def stego_layer(doc: Doc) -> Doc:
    if doc._.is_blocked:
        return doc
    text = doc.text
    if not text or not text.strip():
        return doc

    tag_chars = len(_TAG_RE.findall(text))
    vs_ext = len(_VS_EXT_RE.findall(text))
    vs_std = len(_VS_STD_RE.findall(text))
    emoji_cnt = _count_visible_emojis(text)
    vs_std_sus = max(0, vs_std - (emoji_cnt + 1))
    var_selectors = vs_ext + vs_std_sus
    zw_sus = _count_suspicious_zw(text)
    bidi_chars = len(_BIDI_RE.findall(text))
    confirmed_hidden = tag_chars + vs_ext + zw_sus + bidi_chars
    hidden_ratio = confirmed_hidden / max(1, len(text))
    entropy = _shannon_entropy(text)
    visible_text = _HIDDEN_RE.sub('', text)
    visible_words = max(1, len(visible_text.split()))
    token_count = len(_ENC.encode(text, allowed_special='all')) if _ENC else len(text) // 4
    disparity_ratio = token_count / visible_words
    zw_binary_run = bool(_ZW_RUN_RE.search(text))
    pua_chars = len(_PUA_RE.findall(text))

    doc._.tag_chars = tag_chars
    doc._.var_selectors = var_selectors
    doc._.zero_width_sus = zw_sus
    doc._.hidden_ratio = round(hidden_ratio, 4)
    doc._.entropy = round(entropy, 4)
    doc._.disparity_ratio = round(disparity_ratio, 4)
    doc._.total_tokens = token_count

    if tag_chars >= 2:
        doc._.is_blocked = True
        doc._.block_reason = f'Unicode Tags Detected ({tag_chars} chars)'
        doc._.attack_vector = 'unicode_tags'
        return doc
    if vs_ext >= 2:
        doc._.is_blocked = True
        doc._.block_reason = f'Extended Variation Selectors ({vs_ext} chars)'
        doc._.attack_vector = 'variation_selectors'
        return doc
    if zw_binary_run:
        doc._.is_blocked = True
        doc._.block_reason = 'Zero-Width Binary Encoding Run Detected'
        doc._.attack_vector = 'zero_width_binary'
        return doc
    if bidi_chars > 0:
        doc._.is_blocked = True
        doc._.block_reason = f'Bidirectional Override Attack ({bidi_chars} chars)'
        doc._.attack_vector = 'bidi_override'
        return doc
    if disparity_ratio > 2.5 and confirmed_hidden > 0:
        doc._.is_blocked = True
        doc._.block_reason = f'Steganographic Token Disparity ({disparity_ratio:.1f} tokens/word)'
        doc._.attack_vector = 'token_disparity'
        return doc
    if hidden_ratio > 0.15:
        doc._.is_blocked = True
        doc._.block_reason = f'High Hidden-to-Visible Ratio ({hidden_ratio:.2f})'
        doc._.attack_vector = 'hidden_ratio'
        return doc
    if zw_sus > 4:
        doc._.is_blocked = True
        doc._.block_reason = f'Suspicious Zero-Width Characters ({zw_sus})'
        doc._.attack_vector = 'zero_width_count'
        return doc
    if vs_std_sus > 2:
        doc._.is_blocked = True
        doc._.block_reason = f'Abnormal Variation Selectors ({vs_std} for {emoji_cnt} emoji)'
        doc._.attack_vector = 'variation_selectors_std'
        return doc
    if entropy > 5.0 and (tag_chars + vs_ext + zw_sus) > 0:
        doc._.is_blocked = True
        doc._.block_reason = f'High Entropy Encoded Payload (H={entropy:.2f})'
        doc._.attack_vector = 'entropy_encoded'
        return doc
    if pua_chars > 0:
        doc._.is_blocked = True
        doc._.block_reason = f'Private Use Area Characters ({pua_chars})'
        doc._.attack_vector = 'pua'
        return doc
    return doc


@spacy.Language.component('homoglyph_layer')
def homoglyph_layer(doc: Doc) -> Doc:
    if doc._.is_blocked:
        return doc
    text = doc.text
    if not text or not text.strip():
        return doc

    length = max(1, len(text))
    confusable_cnt = _count_confusables(text)
    confusable_ratio = confusable_cnt / length
    has_mixed, mixed_word = _has_mixed_script_word(text)
    fullwidth_cnt = len(_FULLWIDTH_RE.findall(text))
    math_alpha_cnt = len(_MATH_ALPHA_RE.findall(text))
    enclosed_cnt = len(_ENCLOSED_RE.findall(text))
    modifier_cnt = len(_MODIFIER_RE.findall(text))
    combining_cnt = _count_combining(text)
    combining_ratio = combining_cnt / length
    soft_sep_cnt = len(_SOFT_SEP_RE.findall(text))
    normalised = _normalise_to_ascii(unicodedata.normalize('NFC', text))

    doc._.confusable_count = confusable_cnt
    doc._.confusable_ratio = round(confusable_ratio, 4)
    doc._.mixed_script_word = mixed_word
    doc._.fullwidth_count = fullwidth_cnt
    doc._.math_alpha_count = math_alpha_cnt
    doc._.enclosed_count = enclosed_cnt
    doc._.modifier_count = modifier_cnt
    doc._.combining_count = combining_cnt
    doc._.combining_ratio = round(combining_ratio, 4)
    doc._.soft_sep_count = soft_sep_cnt
    doc._.normalised_text = normalised

    if has_mixed:
        doc._.is_blocked = True
        doc._.block_reason = f'Mixed-Script Word: "{mixed_word}"'
        doc._.attack_vector = 'mixed_script'
        return doc
    if fullwidth_cnt >= 2:
        doc._.is_blocked = True
        doc._.block_reason = f'Fullwidth Latin Characters ({fullwidth_cnt})'
        doc._.attack_vector = 'fullwidth_latin'
        return doc
    if math_alpha_cnt >= 2:
        doc._.is_blocked = True
        doc._.block_reason = f'Mathematical Alphanumeric Symbols ({math_alpha_cnt})'
        doc._.attack_vector = 'math_alphanumerics'
        return doc
    if enclosed_cnt >= 2:
        doc._.is_blocked = True
        doc._.block_reason = f'Enclosed/Circled Letter Substitution ({enclosed_cnt})'
        doc._.attack_vector = 'enclosed_letters'
        return doc
    if soft_sep_cnt > 1:
        doc._.is_blocked = True
        doc._.block_reason = f'Invisible Separator Injection ({soft_sep_cnt})'
        doc._.attack_vector = 'soft_separator'
        return doc
    if combining_ratio > 0.30:
        doc._.is_blocked = True
        doc._.block_reason = f'Diacritic Bombing (ratio={combining_ratio:.2f})'
        doc._.attack_vector = 'diacritic_bombing'
        return doc
    if modifier_cnt >= 3:
        doc._.is_blocked = True
        doc._.block_reason = f'Modifier/Superscript Letter Substitution ({modifier_cnt})'
        doc._.attack_vector = 'modifier_letters'
        return doc
    if confusable_ratio >= 0.08:
        doc._.is_blocked = True
        doc._.block_reason = f'High Confusable Density (ratio={confusable_ratio:.2f})'
        doc._.attack_vector = 'homoglyph_density'
        return doc
    if confusable_cnt >= 1 and modifier_cnt >= 1:
        doc._.is_blocked = True
        doc._.block_reason = f'Combined Homoglyph+Modifier ({confusable_cnt} confusables, {modifier_cnt} modifiers)'
        doc._.attack_vector = 'combined_signal'
        return doc
    return doc


def _build_pipeline() -> spacy.language.Language:
    nlp = spacy.blank('en')
    nlp.add_pipe('stego_layer', last=True)
    nlp.add_pipe('homoglyph_layer', last=True)
    return nlp


class UnicodeFirewall:
    """
    Wraps the unified Unicode attack firewall.
    Detects emoji steganography and homoglyph attacks.
    """

    def __init__(self):
        self._nlp = _build_pipeline()
        print("[UnicodeFirewall] Loaded (stego + homoglyph layers)")

    def scan(self, text: str, mode: str = 'prompt') -> Tuple[bool, str, Dict]:
        """
        Returns (is_blocked, reason, metrics).
        mode: 'prompt' or 'document'
        """
        if not text or not text.strip():
            return False, 'Clean', {}

        if mode == 'document' and bool(_ZW_RUN_RE.search(text)):
            return True, 'Zero-Width Binary Encoding Run Detected', {
                'mode': mode, 'attack_vector': 'zero_width_binary'
            }

        scan_text = _strip_document_artifacts(text) if mode == 'document' else text
        doc = self._nlp(scan_text)
        doc._.scan_mode = mode

        metrics = {
            'mode': mode,
            'tag_chars': doc._.tag_chars,
            'var_selectors': doc._.var_selectors,
            'zero_width_sus': doc._.zero_width_sus,
            'hidden_ratio': doc._.hidden_ratio,
            'entropy': doc._.entropy,
            'disparity_ratio': doc._.disparity_ratio,
            'total_tokens': doc._.total_tokens,
            'confusable_count': doc._.confusable_count,
            'confusable_ratio': doc._.confusable_ratio,
            'mixed_script_word': doc._.mixed_script_word,
            'fullwidth_count': doc._.fullwidth_count,
            'math_alpha_count': doc._.math_alpha_count,
            'enclosed_count': doc._.enclosed_count,
            'modifier_count': doc._.modifier_count,
            'combining_ratio': doc._.combining_ratio,
            'soft_sep_count': doc._.soft_sep_count,
            'attack_vector': doc._.attack_vector,
            'normalised_text': doc._.normalised_text,
        }

        return doc._.is_blocked, doc._.block_reason, metrics

    def clean(self, text: str, mode: str = 'prompt') -> str:
        """Return sanitised text safe for downstream use."""
        if mode == 'document':
            text = _strip_document_artifacts(text)
        text = unicodedata.normalize('NFKC', text)
        text = _HIDDEN_RE.sub('', text)
        text = _BIDI_RE.sub('', text)
        text = _PUA_RE.sub('', text)
        text = _normalise_to_ascii(text)
        return text.strip()
