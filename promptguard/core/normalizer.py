import re
import unicodedata
import urllib.parse
import base64
from typing import Tuple, List


class AdvancedNormalizer:
    """Dekoder obfuskerte, usynlige og maskerte tegn til en kanonisk form."""

    HOMOGLYPH_MAP = {
        'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'ѕ': 's', 'х': 'x', 'у': 'y',
        'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'І': 'I', 'Ј': 'J', 'К': 'K',
        'М': 'M', 'О': 'O', 'Р': 'P', 'Ѕ': 'S', 'Т': 'T', 'Х': 'X', 'Ү': 'Y', 'һ': 'h',
        'α': 'a', 'β': 'b', 'γ': 'g', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o',
        'ρ': 'r', 'τ': 't', 'υ': 'u', 'χ': 'x', 'ω': 'w'
    }

    EVIL_UNICODE_PATTERN = re.compile(
        r"[\u200B-\u200F\uFEFF\u00AD\u2060-\u206F\u202A-\u202E\u180E]"
    )

    @classmethod
    def strip_evil_unicode(cls, text: str) -> Tuple[str, bool]:
        cleaned, count = cls.EVIL_UNICODE_PATTERN.subn("", text)
        return cleaned, count > 0

    @classmethod
    def normalize_homoglyphs(cls, text: str) -> Tuple[str, bool]:
        had_homoglyphs = False
        chars = []
        for ch in text:
            if ch in cls.HOMOGLYPH_MAP:
                chars.append(cls.HOMOGLYPH_MAP[ch])
                had_homoglyphs = True
            else:
                chars.append(ch)
        return "".join(chars), had_homoglyphs

    @classmethod
    def recursive_decode(cls, text: str, max_depth: int = 3) -> List[Tuple[str, str]]:
        decoded_layers = []
        current = text

        for depth in range(1, max_depth + 1):
            changed = False

            # URL Decode
            url_decoded = urllib.parse.unquote(current)
            if url_decoded != current:
                decoded_layers.append((f"url_depth_{depth}", url_decoded))
                current = url_decoded
                changed = True

            # Base64 Decode
            b64_matches = re.findall(r"[A-Za-z0-9+/=]{20,}", current)
            for m in b64_matches:
                try:
                    raw = base64.b64decode(m)
                    for enc in ["utf-8", "utf-16le", "ascii"]:
                        try:
                            dec = raw.decode(enc)
                            if any(k in dec.lower() for k in ["ignore", "system", "http", "curl", "cmd"]):
                                decoded_layers.append((f"base64_{enc}_depth_{depth}", dec))
                                current = current.replace(m, dec)
                                changed = True
                                break
                        except Exception:
                            continue
                except Exception:
                    continue

            if not changed:
                break

        return decoded_layers
