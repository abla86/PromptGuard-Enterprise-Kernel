import { DecodedLayer, HomoglyphMatch, ZeroWidthMatch } from '../types';

export class AdvancedNormalizer {
  // Homoglyph table: Maps common Cyrillic, Greek and confusables to Latin
  public static readonly HOMOGLYPH_MAP: Record<string, string> = {
    // Cyrillic Lowercase
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'ѕ': 's', 'х': 'x', 'у': 'y',
    'і': 'i', 'ј': 'j', 'к': 'k', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'һ': 'h',
    // Cyrillic Uppercase
    'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'І': 'I', 'Ј': 'J', 'К': 'K',
    'М': 'M', 'О': 'O', 'Р': 'P', 'Ѕ': 'S', 'Т': 'T', 'Х': 'X', 'Ү': 'Y', 'Һ': 'H',
    // Greek Lowercase
    'α': 'a', 'β': 'b', 'γ': 'g', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o',
    'ρ': 'r', 'τ': 't', 'υ': 'u', 'χ': 'x', 'ω': 'w',
    // Greek Uppercase
    'Α': 'A', 'Β': 'B', 'Γ': 'G', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K',
    'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
  };

  // Invisible characters, Zero-Width spaces, and BiDi Overrides (Right-to-Left spoofing)
  public static readonly EVIL_UNICODE_PATTERN = /[\u200B-\u200F\uFEFF\u00AD\u2060-\u206F\u202A-\u202E\u180E]/g;

  // Named lookup for evil unicode
  public static readonly EVIL_UNICODE_NAMES: Record<string, string> = {
    '\u200B': 'Zero-Width Space (ZWSP)',
    '\u200C': 'Zero-Width Non-Joiner (ZWNJ)',
    '\u200D': 'Zero-Width Joiner (ZWJ)',
    '\u200E': 'Left-to-Right Mark (LRM)',
    '\u200F': 'Right-to-Left Mark (RLM)',
    '\uFEFF': 'Byte Order Mark (BOM)',
    '\u00AD': 'Soft Hyphen (SHY)',
    '\u202A': 'Left-to-Right Embedding (LRE)',
    '\u202B': 'Right-to-Left Embedding (RLE)',
    '\u202C': 'Pop Directional Formatting (PDF)',
    '\u202D': 'Left-to-Right Override (LRO)',
    '\u202E': 'Right-to-Left Override (RLO - BiDi Spoof)',
    '\u2060': 'Word Joiner',
    '\u2061': 'Function Application',
    '\u2062': 'Invisible Times',
    '\u2063': 'Invisible Separator',
    '\u180E': 'Mongolian Vowel Separator',
  };

  public static stripEvilUnicode(text: string): {
    cleaned: string;
    hadZeroWidth: boolean;
    matches: ZeroWidthMatch[];
  } {
    const matches: ZeroWidthMatch[] = [];
    let match: RegExpExecArray | null;
    const regex = new RegExp(this.EVIL_UNICODE_PATTERN.source, 'g');

    while ((match = regex.exec(text)) !== null) {
      const ch = match[0];
      const codePoint = 'U+' + ch.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0');
      matches.push({
        char: ch,
        codePoint,
        name: this.EVIL_UNICODE_NAMES[ch] || `Invisible Control (${codePoint})`,
        index: match.index,
      });
    }

    const cleaned = text.replace(this.EVIL_UNICODE_PATTERN, '');
    return {
      cleaned,
      hadZeroWidth: matches.length > 0,
      matches,
    };
  }

  public static normalizeHomoglyphs(text: string): {
    normalized: string;
    hadHomoglyphs: boolean;
    matches: HomoglyphMatch[];
  } {
    let hadHomoglyphs = false;
    const matches: HomoglyphMatch[] = [];
    const chars: string[] = [];

    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (this.HOMOGLYPH_MAP[ch]) {
        hadHomoglyphs = true;
        const replacement = this.HOMOGLYPH_MAP[ch];
        matches.push({
          char: ch,
          replacement,
          index: i,
          originalCode: 'U+' + ch.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0'),
        });
        chars.push(replacement);
      } else {
        chars.push(ch);
      }
    }

    return {
      normalized: chars.join(''),
      hadHomoglyphs,
      matches,
    };
  }

  public static normalizeLeetspeak(text: string): string {
    const leetMap: Record<string, string> = {
      '0': 'o',
      '1': 'i',
      '3': 'e',
      '4': 'a',
      '5': 's',
      '7': 't',
      '@': 'a',
      $: 's',
      '!': 'i',
      '+': 't',
    };
    return text
      .split('')
      .map((c) => leetMap[c] || c)
      .join('');
  }

  public static recursiveDecode(
    text: string,
    maxDepth: number = 3
  ): DecodedLayer[] {
    const decodedLayers: DecodedLayer[] = [];
    let current = text;

    for (let depth = 1; depth <= maxDepth; depth++) {
      let changed = false;

      // 1. URL Decode
      try {
        const urlDecoded = decodeURIComponent(current);
        if (urlDecoded !== current) {
          decodedLayers.push({
            layer_type: `url_depth_${depth}`,
            depth,
            content: urlDecoded,
          });
          current = urlDecoded;
          changed = true;
        }
      } catch {
        // malformed URI component, keep going
      }

      // 2. Base64 Decode
      const b64Regex = /[A-Za-z0-9+/=]{16,}/g;
      const b64Matches = current.match(b64Regex) || [];

      for (const m of b64Matches) {
        try {
          // Normalize padding
          let candidate = m;
          while (candidate.length % 4 !== 0) {
            candidate += '=';
          }
          const decoded = atob(candidate);
          // Check if decoded contains meaningful ASCII text
          const isPrintable = /^[\x20-\x7E\r\n\t]+$/.test(decoded);
          const hasThreatKeywords = /(ignore|system|http|curl|cmd|eval|drop|delete|token|secret|admin|bypass|prompt)/i.test(decoded);

          if (isPrintable || hasThreatKeywords) {
            decodedLayers.push({
              layer_type: `base64_depth_${depth}`,
              depth,
              content: decoded,
            });
            current = current.replace(m, decoded);
            changed = true;
          }
        } catch {
          // invalid base64, continue
        }
      }

      // 3. Hex Decode (e.g., 69676e6f7265 or 0x69676e6f7265)
      const hexRegex = /(?:0x)?([0-9a-fA-F]{12,})/g;
      let hexMatch: RegExpExecArray | null;
      while ((hexMatch = hexRegex.exec(current)) !== null) {
        const hexStr = hexMatch[1];
        if (hexStr.length % 2 === 0) {
          try {
            let decodedHex = '';
            for (let i = 0; i < hexStr.length; i += 2) {
              decodedHex += String.fromCharCode(parseInt(hexStr.substring(i, i + 2), 16));
            }
            if (/^[a-zA-Z0-9_\-\s.,:;!?(){}\[\]/\\=]+$/.test(decodedHex) && decodedHex.length > 4) {
              decodedLayers.push({
                layer_type: `hex_depth_${depth}`,
                depth,
                content: decodedHex,
              });
              current = current.replace(hexMatch[0], decodedHex);
              changed = true;
            }
          } catch {
            // invalid hex
          }
        }
      }

      if (!changed) break;
    }

    return decodedLayers;
  }
}
