/* Cipher Lab — 65 pure transform functions + a tiny UI binding. No dependencies. */
(function () {
  'use strict';

  /* ================= byte helpers ================= */
  var TE = new TextEncoder();
  var TD = new TextDecoder('utf-8');
  function utf8(s) { return Array.from(TE.encode(s)); }
  function unutf8(bytes) { return TD.decode(new Uint8Array(bytes)); }
  function fail(msg) { throw new Error(msg); }
  function oneWay() { var e = new Error('one-way function — a digest cannot be decoded back to its input'); e.notice = true; throw e; }
  function hex2(b) { return (b < 16 ? '0' : '') + b.toString(16); }
  function toHex(bytes) { return bytes.map(hex2).join(''); }
  function u32hex(n) { return ('00000000' + (n >>> 0).toString(16)).slice(-8); }
  function tokens(s) { return s.trim() ? s.trim().split(/[\s,]+/) : []; }
  function parseTokens(s, radix, re) {
    return tokens(s).map(function (t) {
      if (!re.test(t)) fail('invalid token "' + t + '"');
      var n = parseInt(t, radix);
      if (n > 255) fail('token "' + t + '" exceeds one byte');
      return n;
    });
  }
  function binStr(bytes) { var s = ''; for (var i = 0; i < bytes.length; i += 8192) s += String.fromCharCode.apply(null, bytes.slice(i, i + 8192)); return s; }
  function fromBinStr(s) { var a = new Array(s.length); for (var i = 0; i < s.length; i++) a[i] = s.charCodeAt(i); return a; }
  function int(p, d) { var n = parseInt(p, 10); return isNaN(n) ? d : n; }
  function mod(a, n) { return ((a % n) + n) % n; }

  /* ================= radix / bases ================= */
  function radixEnc(bytes, radix, width) { return bytes.map(function (b) { var s = b.toString(radix); while (s.length < width) s = '0' + s; return s; }).join(' '); }

  function hexDec(s) {
    var h = s.replace(/0x/gi, '').replace(/[\s:,-]/g, '');
    if (!/^[0-9a-f]*$/i.test(h)) fail('non-hex character in input');
    if (h.length % 2) fail('odd number of hex digits');
    var out = []; for (var i = 0; i < h.length; i += 2) out.push(parseInt(h.substr(i, 2), 16));
    return out;
  }
  function binDec(s) {
    var b = s.replace(/\s+/g, '');
    if (!/^[01]*$/.test(b)) fail('only 0 and 1 are valid binary digits');
    if (b.length % 8) fail('bit count is not a multiple of 8');
    var out = []; for (var i = 0; i < b.length; i += 8) out.push(parseInt(b.substr(i, 8), 2));
    return out;
  }

  var B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  var B32HEX = '0123456789ABCDEFGHIJKLMNOPQRSTUV';
  var B32CROCK = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  function b32enc(bytes, alpha, pad) {
    var out = '', bits = 0, val = 0;
    for (var i = 0; i < bytes.length; i++) {
      val = (val << 8) | bytes[i]; bits += 8;
      while (bits >= 5) { out += alpha[(val >>> (bits - 5)) & 31]; bits -= 5; val &= (1 << bits) - 1; }
    }
    if (bits > 0) out += alpha[(val << (5 - bits)) & 31];
    if (pad) while (out.length % 8) out += '=';
    return out;
  }
  function b32dec(s, alpha) {
    var out = [], bits = 0, val = 0;
    for (var i = 0; i < s.length; i++) {
      var v = alpha.indexOf(s[i]);
      if (v < 0) fail('invalid base32 character "' + s[i] + '"');
      val = (val << 5) | v; bits += 5;
      if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; val &= (1 << bits) - 1; }
    }
    return out;
  }
  function crockNorm(s) { return s.toUpperCase().replace(/[\s-]/g, '').replace(/O/g, '0').replace(/[IL]/g, '1'); }

  function bigEnc(bytes, alpha) {
    var B = BigInt(alpha.length), n = 0n, out = '', i;
    for (i = 0; i < bytes.length; i++) n = n * 256n + BigInt(bytes[i]);
    while (n > 0n) { out = alpha[Number(n % B)] + out; n = n / B; }
    for (i = 0; i < bytes.length && bytes[i] === 0; i++) out = alpha[0] + out;
    return out;
  }
  function bigDec(s, alpha) {
    var B = BigInt(alpha.length), n = 0n, i, zeros = 0, out = [];
    while (zeros < s.length && s[zeros] === alpha[0]) zeros++;
    for (i = 0; i < s.length; i++) {
      var v = alpha.indexOf(s[i]);
      if (v < 0) fail('invalid character "' + s[i] + '"');
      n = n * B + BigInt(v);
    }
    while (n > 0n) { out.unshift(Number(n % 256n)); n = n / 256n; }
    for (i = 0; i < zeros; i++) out.unshift(0);
    return out;
  }
  var B36 = '0123456789abcdefghijklmnopqrstuvwxyz';
  var B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  var B62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

  var B45 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';
  function b45enc(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i += 2) {
      if (i + 1 < bytes.length) {
        var n = bytes[i] * 256 + bytes[i + 1];
        out += B45[n % 45] + B45[Math.floor(n / 45) % 45] + B45[Math.floor(n / 2025)];
      } else {
        out += B45[bytes[i] % 45] + B45[Math.floor(bytes[i] / 45)];
      }
    }
    return out;
  }
  function b45dec(s) {
    s = s.replace(/[\r\n]+$/, '');
    var v = Array.from(s).map(function (c) { var x = B45.indexOf(c); if (x < 0) fail('invalid base45 character "' + c + '"'); return x; });
    if (v.length % 3 === 1) fail('invalid base45 length');
    var out = [];
    for (var i = 0; i < v.length; i += 3) {
      if (i + 2 < v.length) {
        var n = v[i] + v[i + 1] * 45 + v[i + 2] * 2025;
        if (n > 65535) fail('base45 triplet out of range');
        out.push(n >> 8, n & 255);
      } else {
        var m = v[i] + v[i + 1] * 45;
        if (m > 255) fail('base45 pair out of range');
        out.push(m);
      }
    }
    return out;
  }

  function b64enc(bytes) { return btoa(binStr(bytes)); }
  function b64dec(s) {
    var c = s.replace(/\s+/g, '');
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(c)) fail('invalid base64 character');
    while (c.length % 4) c += '=';
    try { return fromBinStr(atob(c)); } catch (e) { fail('malformed base64'); }
  }
  function b64urlEnc(bytes) { return b64enc(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function b64urlDec(s) {
    var c = s.replace(/\s+/g, '');
    if (!/^[A-Za-z0-9_-]*=*$/.test(c)) fail('invalid base64url character');
    return b64dec(c.replace(/=+$/, '').replace(/-/g, '+').replace(/_/g, '/'));
  }

  function a85core(bytes, alpha, zShort) {
    var out = '';
    for (var i = 0; i < bytes.length; i += 4) {
      var n = Math.min(4, bytes.length - i);
      var v = (((bytes[i] || 0) << 24) | ((bytes[i + 1] || 0) << 16) | ((bytes[i + 2] || 0) << 8) | (bytes[i + 3] || 0)) >>> 0;
      if (zShort && n === 4 && v === 0) { out += 'z'; continue; }
      var c = new Array(5);
      for (var k = 4; k >= 0; k--) { c[k] = alpha[v % 85]; v = Math.floor(v / 85); }
      out += c.slice(0, n + 1).join('');
    }
    return out;
  }
  function a85decCore(s, alpha, zShort) {
    var out = [], group = [];
    function flush(n) {
      while (group.length < 5) group.push(84);
      var v = 0;
      for (var k = 0; k < 5; k++) v = v * 85 + group[k];
      if (v > 0xFFFFFFFF) fail('group value exceeds 32 bits');
      var b = [(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255];
      for (var j = 0; j < n; j++) out.push(b[j]);
      group = [];
    }
    for (var i = 0; i < s.length; i++) {
      var ch = s[i];
      if (zShort && ch === 'z') { if (group.length) fail('"z" inside a group'); out.push(0, 0, 0, 0); continue; }
      var x = alpha.indexOf(ch);
      if (x < 0) fail('invalid base85 character "' + ch + '"');
      group.push(x);
      if (group.length === 5) flush(4);
    }
    if (group.length === 1) fail('dangling single character');
    if (group.length) flush(group.length - 1);
    return out;
  }
  var A85 = ''; for (var ai = 33; ai < 118; ai++) A85 += String.fromCharCode(ai);
  var Z85 = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#';

  var B91 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"';
  function b91enc(bytes) {
    var b = 0, n = 0, out = '';
    for (var i = 0; i < bytes.length; i++) {
      b |= bytes[i] << n; n += 8;
      if (n > 13) {
        var v = b & 8191;
        if (v > 88) { b >>= 13; n -= 13; } else { v = b & 16383; b >>= 14; n -= 14; }
        out += B91[v % 91] + B91[Math.floor(v / 91)];
      }
    }
    if (n) { out += B91[b % 91]; if (n > 7 || b > 90) out += B91[Math.floor(b / 91)]; }
    return out;
  }
  function b91dec(s) {
    var v = -1, b = 0, n = 0, out = [];
    for (var i = 0; i < s.length; i++) {
      if (/\s/.test(s[i])) continue;
      var c = B91.indexOf(s[i]);
      if (c < 0) fail('invalid base91 character "' + s[i] + '"');
      if (v < 0) v = c;
      else {
        v += c * 91; b |= v << n; n += (v & 8191) > 88 ? 13 : 14;
        do { out.push(b & 255); b >>= 8; n -= 8; } while (n > 7);
        v = -1;
      }
    }
    if (v > -1) out.push((b | (v << n)) & 255);
    return out;
  }

  /* ================= classical ciphers ================= */
  function mapLetters(s, fn) {
    return s.replace(/[A-Za-z]/g, function (ch) {
      var up = ch <= 'Z', base = up ? 65 : 97;
      return String.fromCharCode(base + fn(ch.charCodeAt(0) - base));
    });
  }
  function shift(s, k) { return mapLetters(s, function (x) { return mod(x + k, 26); }); }
  function rot5(s) { return s.replace(/[0-9]/g, function (d) { return String((+d + 5) % 10); }); }
  function rot47(s) { return s.replace(/[!-~]/g, function (c) { return String.fromCharCode(33 + ((c.charCodeAt(0) - 33 + 47) % 94)); }); }
  function atbash(s) { return mapLetters(s, function (x) { return 25 - x; }); }

  function affineParams(p) {
    var m = String(p).match(/-?\d+/g) || [];
    var a = int(m[0], 5), b = int(m[1], 8);
    var inv = -1; for (var i = 1; i < 26; i++) if (mod(a * i, 26) === 1) inv = i;
    if (inv < 0) fail('a=' + a + ' is not coprime with 26 (use 1,3,5,7,9,11,15,17,19,21,23,25)');
    return { a: a, b: b, inv: inv };
  }

  function keyShifts(key) {
    var k = String(key).toUpperCase().replace(/[^A-Z]/g, '');
    if (!k) fail('key must contain at least one letter');
    return k.split('').map(function (c) { return c.charCodeAt(0) - 65; });
  }
  function vigenere(s, key, dir) {
    var ks = keyShifts(key), j = 0;
    return mapLetters(s, function (x) { var r = mod(x + dir * ks[j % ks.length], 26); j++; return r; });
  }
  function beaufort(s, key) {
    var ks = keyShifts(key), j = 0;
    return mapLetters(s, function (x) { var r = mod(ks[j % ks.length] - x, 26); j++; return r; });
  }
  function autokeyEnc(s, key) {
    var stream = keyShifts(key), j = 0;
    return mapLetters(s, function (x) { stream.push(x); return mod(x + stream[j++], 26); });
  }
  function autokeyDec(s, key) {
    var stream = keyShifts(key), j = 0;
    return mapLetters(s, function (x) { var p = mod(x - stream[j++], 26); stream.push(p); return p; });
  }
  function keyedAlphabet(key, merge) {
    var seen = '', src = String(key).toUpperCase().replace(/[^A-Z]/g, '') + 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    for (var i = 0; i < src.length; i++) {
      var c = src[i];
      if (merge && c === 'J') c = 'I';
      if (merge && c === 'J') continue;
      if (seen.indexOf(c) < 0) seen += c;
    }
    return merge ? seen.replace('J', '') : seen;
  }
  function keywordSub(s, key, dir) {
    var alpha = keyedAlphabet(key, false);
    return mapLetters(s, function (x) { return dir > 0 ? alpha.charCodeAt(x) - 65 : alpha.indexOf(String.fromCharCode(65 + x)); });
  }
  function playfair(s, key, dir) {
    var sq = keyedAlphabet(key, true);
    var t = s.toUpperCase().replace(/[^A-Z]/g, '').replace(/J/g, 'I');
    var pairs = [];
    if (dir > 0) {
      var i = 0;
      while (i < t.length) {
        var a = t[i], b = t[i + 1];
        if (b === undefined) { pairs.push(a + (a === 'X' ? 'Q' : 'X')); i++; }
        else if (a === b) { pairs.push(a + (a === 'X' ? 'Q' : 'X')); i++; }
        else { pairs.push(a + b); i += 2; }
      }
    } else {
      if (t.length % 2) fail('ciphertext must have an even number of letters');
      for (var k = 0; k < t.length; k += 2) {
        if (t[k] === t[k + 1]) fail('invalid digraph "' + t[k] + t[k + 1] + '"');
        pairs.push(t[k] + t[k + 1]);
      }
    }
    return pairs.map(function (pr) {
      var p1 = sq.indexOf(pr[0]), p2 = sq.indexOf(pr[1]);
      var r1 = Math.floor(p1 / 5), c1 = p1 % 5, r2 = Math.floor(p2 / 5), c2 = p2 % 5;
      if (r1 === r2) { c1 = mod(c1 + dir, 5); c2 = mod(c2 + dir, 5); }
      else if (c1 === c2) { r1 = mod(r1 + dir, 5); r2 = mod(r2 + dir, 5); }
      else { var tmp = c1; c1 = c2; c2 = tmp; }
      return sq[r1 * 5 + c1] + sq[r2 * 5 + c2];
    }).join(dir > 0 ? ' ' : '').toLowerCase();
  }
  function railPattern(len, rails) {
    var pat = [], r = 0, d = 1;
    for (var i = 0; i < len; i++) { pat.push(r); if (rails > 1) { if (r === 0) d = 1; else if (r === rails - 1) d = -1; r += d; } }
    return pat;
  }
  function railEnc(s, rails) {
    rails = Math.max(1, rails); var ch = Array.from(s), pat = railPattern(ch.length, rails), out = '';
    for (var r = 0; r < rails; r++) for (var i = 0; i < ch.length; i++) if (pat[i] === r) out += ch[i];
    return out;
  }
  function railDec(s, rails) {
    rails = Math.max(1, rails); var ch = Array.from(s), pat = railPattern(ch.length, rails), res = new Array(ch.length), k = 0;
    for (var r = 0; r < rails; r++) for (var i = 0; i < ch.length; i++) if (pat[i] === r) res[i] = ch[k++];
    return res.join('');
  }
  function columnOrder(key) {
    var k = String(key);
    if (!k.length) fail('key cannot be empty');
    return k.split('').map(function (c, i) { return { c: c.toUpperCase(), i: i }; })
      .sort(function (a, b) { return a.c < b.c ? -1 : a.c > b.c ? 1 : a.i - b.i; })
      .map(function (o) { return o.i; });
  }
  function columnarEnc(s, key) {
    var ch = Array.from(s), order = columnOrder(key), w = order.length, out = '';
    order.forEach(function (col) { for (var i = col; i < ch.length; i += w) out += ch[i]; });
    return out;
  }
  function columnarDec(s, key) {
    var ch = Array.from(s), order = columnOrder(key), w = order.length, res = new Array(ch.length), k = 0;
    order.forEach(function (col) { for (var i = col; i < ch.length; i += w) res[i] = ch[k++]; });
    return res.join('');
  }
  function seqKey(n) { var s = ''; for (var i = 0; i < Math.max(1, n); i++) s += String.fromCharCode(33 + i); return s; }

  function letterIndex(c) { return c.toUpperCase().charCodeAt(0) - 65; }
  function baconEnc(s) {
    return s.trim().split(/\s+/).map(function (w) {
      return w.replace(/[^A-Za-z]/g, '').split('').map(function (c) {
        var n = letterIndex(c), o = '';
        for (var b = 4; b >= 0; b--) o += (n >> b) & 1 ? 'B' : 'A';
        return o;
      }).join(' ');
    }).filter(Boolean).join(' / ');
  }
  function baconDec(s) {
    return s.split('/').map(function (w) {
      var t = w.toUpperCase().replace(/[^AB]/g, '');
      if (t.length % 5) fail('bacon groups must be 5 symbols of A/B');
      var o = '';
      for (var i = 0; i < t.length; i += 5) {
        var n = parseInt(t.substr(i, 5).replace(/A/g, '0').replace(/B/g, '1'), 2);
        if (n > 25) fail('group "' + t.substr(i, 5) + '" is beyond Z');
        o += String.fromCharCode(97 + n);
      }
      return o;
    }).join(' ').trim();
  }
  var POLY = 'ABCDEFGHIKLMNOPQRSTUVWXYZ';
  var TAP = 'ABCDEFGHIJLMNOPQRSTUVWXYZ';
  function gridEnc(s, grid, fmt) {
    return s.trim().split(/\s+/).map(function (w) {
      return w.toUpperCase().replace(/[^A-Z]/g, '').split('').map(function (c) {
        if (grid === POLY && c === 'J') c = 'I';
        if (grid === TAP && c === 'K') c = 'C';
        var p = grid.indexOf(c);
        return fmt(Math.floor(p / 5) + 1, (p % 5) + 1);
      }).join('  ');
    }).filter(Boolean).join(' / ');
  }
  function gridDec(s, grid, parse) {
    return s.split('/').map(function (w) {
      var nums = parse(w), o = '';
      if (nums.length % 2) fail('coordinates must come in row/column pairs');
      for (var i = 0; i < nums.length; i += 2) {
        var r = nums[i], c = nums[i + 1];
        if (r < 1 || r > 5 || c < 1 || c > 5) fail('coordinate out of the 5×5 grid');
        o += grid[(r - 1) * 5 + (c - 1)].toLowerCase();
      }
      return o;
    }).join(' ').trim();
  }

  var MORSE = {
    A: '.-', B: '-...', C: '-.-.', D: '-..', E: '.', F: '..-.', G: '--.', H: '....', I: '..', J: '.---', K: '-.-', L: '.-..', M: '--',
    N: '-.', O: '---', P: '.--.', Q: '--.-', R: '.-.', S: '...', T: '-', U: '..-', V: '...-', W: '.--', X: '-..-', Y: '-.--', Z: '--..',
    '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
    '.': '.-.-.-', ',': '--..--', '?': '..--..', "'": '.----.', '!': '-.-.--', '/': '-..-.', '(': '-.--.', ')': '-.--.-', '&': '.-...',
    ':': '---...', ';': '-.-.-.', '=': '-...-', '+': '.-.-.', '-': '-....-', '_': '..--.-', '"': '.-..-.', '$': '...-..-', '@': '.--.-.'
  };
  var MORSE_REV = {}; Object.keys(MORSE).forEach(function (k) { MORSE_REV[MORSE[k]] = k; });
  function morseEnc(s) {
    return s.trim().split(/\s+/).map(function (w) {
      return Array.from(w.toUpperCase()).map(function (c) { return MORSE[c] || ''; }).filter(Boolean).join(' ');
    }).filter(Boolean).join(' / ');
  }
  function morseDec(s) {
    return s.replace(/[•·]/g, '.').replace(/[—–_]/g, '-').split('/').map(function (w) {
      return tokens(w).map(function (t) { if (!MORSE_REV[t]) fail('unknown morse sequence "' + t + '"'); return MORSE_REV[t]; }).join('');
    }).join(' ').trim().toLowerCase();
  }
  function a1z26Enc(s) {
    return s.trim().split(/\s+/).map(function (w) {
      return w.replace(/[^A-Za-z]/g, '').split('').map(function (c) { return letterIndex(c) + 1; }).join('-');
    }).filter(Boolean).join(' ');
  }
  function a1z26Dec(s) {
    return tokens(s.replace(/,/g, ' ')).map(function (w) {
      return w.split('-').filter(Boolean).map(function (n) {
        var v = parseInt(n, 10);
        if (!/^\d+$/.test(n) || v < 1 || v > 26) fail('"' + n + '" is not in 1–26');
        return String.fromCharCode(96 + v);
      }).join('');
    }).join(' ');
  }
  var NATO = ['alfa', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot', 'golf', 'hotel', 'india', 'juliett', 'kilo', 'lima', 'mike',
    'november', 'oscar', 'papa', 'quebec', 'romeo', 'sierra', 'tango', 'uniform', 'victor', 'whiskey', 'xray', 'yankee', 'zulu'];
  var NATO_NUM = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'niner'];
  function natoEnc(s) {
    return s.trim().split(/\s+/).map(function (w) {
      return Array.from(w).map(function (c) {
        if (/[A-Za-z]/.test(c)) return NATO[letterIndex(c)];
        if (/[0-9]/.test(c)) return NATO_NUM[+c];
        return '';
      }).filter(Boolean).join(' ');
    }).filter(Boolean).join(' / ').toUpperCase();
  }
  function natoDec(s) {
    return s.split('/').map(function (w) {
      return tokens(w).map(function (t) {
        var l = t.toLowerCase().replace(/[^a-z]/g, '');
        if (l === 'alpha') l = 'alfa'; if (l === 'juliet') l = 'juliett'; if (l === 'nine') l = 'niner';
        var i = NATO.indexOf(l); if (i >= 0) return String.fromCharCode(97 + i);
        var j = NATO_NUM.indexOf(l); if (j >= 0) return String(j);
        fail('unknown code word "' + t + '"');
      }).join('');
    }).join(' ').trim();
  }

  /* ================= modern formats ================= */
  function urlAllEnc(s) { return utf8(s).map(function (b) { return '%' + hex2(b).toUpperCase(); }).join(''); }
  function pctDecode(s, plusSpace) {
    var bytes = [], i = 0;
    while (i < s.length) {
      var c = s[i];
      if (c === '%') {
        var h = s.substr(i + 1, 2);
        if (!/^[0-9a-f]{2}$/i.test(h)) fail('malformed escape at position ' + i);
        bytes.push(parseInt(h, 16)); i += 3;
      } else if (plusSpace && c === '+') { bytes.push(32); i++; }
      else { var cp = s.codePointAt(i), ch = String.fromCodePoint(cp); bytes = bytes.concat(utf8(ch)); i += ch.length; }
    }
    return unutf8(bytes);
  }
  var ENT = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: '\u00a0', copy: '©', reg: '®', trade: '™', hellip: '…',
    mdash: '—', ndash: '–', laquo: '«', raquo: '»', euro: '€', pound: '£', yen: '¥', cent: '¢', sect: '§', deg: '°', middot: '·',
    times: '×', divide: '÷', para: '¶', bull: '•', lsquo: '‘', rsquo: '’', ldquo: '“', rdquo: '”' };
  function htmlEnc(s) { return s.replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function htmlNumEnc(s) { return Array.from(s).map(function (c) { return '&#' + c.codePointAt(0) + ';'; }).join(''); }
  function htmlDec(s) {
    return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, function (m, e) {
      if (e[0] === '#') {
        var n = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
        return n <= 0x10FFFF ? String.fromCodePoint(n) : m;
      }
      return Object.prototype.hasOwnProperty.call(ENT, e.toLowerCase()) ? ENT[e.toLowerCase()] : m;
    });
  }
  function uEscEnc(s) { var o = ''; for (var i = 0; i < s.length; i++) o += '\\u' + ('0000' + s.charCodeAt(i).toString(16)).slice(-4); return o; }
  function uEscDec(s) {
    return s.replace(/\\u\{([0-9a-f]{1,6})\}|\\u([0-9a-f]{4})|\\x([0-9a-f]{2})/gi, function (m, a, b, c) {
      return a ? String.fromCodePoint(parseInt(a, 16)) : String.fromCharCode(parseInt(b || c, 16));
    });
  }
  function cpEnc(s) { return Array.from(s).map(function (c) { var h = c.codePointAt(0).toString(16).toUpperCase(); while (h.length < 4) h = '0' + h; return 'U+' + h; }).join(' '); }
  function cpDec(s) {
    return tokens(s).map(function (t) {
      var m = t.match(/^(?:U\+|0x)?([0-9a-f]{1,6})$/i);
      if (!m) fail('invalid code point "' + t + '"');
      var n = parseInt(m[1], 16); if (n > 0x10FFFF) fail('code point out of range');
      return String.fromCodePoint(n);
    }).join('');
  }
  function jsonDec(s) {
    var t = s.trim(); if (t[0] !== '"') t = '"' + t + '"';
    var v; try { v = JSON.parse(t); } catch (e) { fail('invalid json string literal'); }
    if (typeof v !== 'string') fail('not a json string');
    return v;
  }
  function qpEnc(s) {
    var bytes = utf8(s), out = '', line = 0;
    for (var i = 0; i < bytes.length; i++) {
      var b = bytes[i], tok;
      if (b === 10) { out += '\n'; line = 0; continue; }
      var next = bytes[i + 1];
      if ((b >= 33 && b <= 126 && b !== 61) || ((b === 32 || b === 9) && next !== undefined && next !== 10)) tok = String.fromCharCode(b);
      else tok = '=' + hex2(b).toUpperCase();
      if (line + tok.length > 75) { out += '=\n'; line = 0; }
      out += tok; line += tok.length;
    }
    return out;
  }
  function qpDec(s) {
    var t = s.replace(/=\r?\n/g, ''), bytes = [], i = 0;
    while (i < t.length) {
      if (t[i] === '=') {
        var h = t.substr(i + 1, 2);
        if (!/^[0-9A-F]{2}$/i.test(h)) fail('malformed =XX escape at position ' + i);
        bytes.push(parseInt(h, 16)); i += 3;
      } else { var cp = t.codePointAt(i), ch = String.fromCodePoint(cp); bytes = bytes.concat(utf8(ch)); i += ch.length; }
    }
    return unutf8(bytes);
  }
  function uuChar(v) { return v === 0 ? '`' : String.fromCharCode(32 + v); }
  function uuEnc(s) {
    var bytes = utf8(s), lines = ['begin 644 cipher.txt'];
    for (var i = 0; i < bytes.length; i += 45) {
      var chunk = bytes.slice(i, i + 45), l = uuChar(chunk.length);
      for (var j = 0; j < chunk.length; j += 3) {
        var a = chunk[j], b = chunk[j + 1] || 0, c = chunk[j + 2] || 0;
        l += uuChar(a >> 2) + uuChar(((a & 3) << 4) | (b >> 4)) + uuChar(((b & 15) << 2) | (c >> 6)) + uuChar(c & 63);
      }
      lines.push(l);
    }
    lines.push('`', 'end');
    return lines.join('\n');
  }
  function uuDec(s) {
    var lines = s.replace(/\r/g, '').split('\n'), out = [], started = !/^begin /m.test(s);
    for (var i = 0; i < lines.length; i++) {
      var l = lines[i];
      if (!started) { if (/^begin /.test(l)) started = true; continue; }
      if (/^end\s*$/.test(l)) break;
      if (!l.length) continue;
      var n = (l.charCodeAt(0) - 32) & 63;
      if (n === 0) continue;
      var vals = [];
      for (var j = 1; j < l.length; j++) vals.push((l.charCodeAt(j) - 32) & 63);
      var bytes = [];
      for (var k = 0; k + 3 < vals.length + 3 && bytes.length < n; k += 4) {
        var a = vals[k] || 0, b = vals[k + 1] || 0, c = vals[k + 2] || 0, d = vals[k + 3] || 0;
        bytes.push(((a << 2) | (b >> 4)) & 255, ((b << 4) | (c >> 2)) & 255, ((c << 6) | d) & 255);
      }
      out = out.concat(bytes.slice(0, n));
    }
    return unutf8(out);
  }

  /* punycode (RFC 3492) */
  var PB = 36, TMIN = 1, TMAX = 26, SKEW = 38, DAMP = 700, IBIAS = 72, IN = 128;
  function adapt(delta, num, first) {
    delta = first ? Math.floor(delta / DAMP) : delta >> 1;
    delta += Math.floor(delta / num);
    var k = 0;
    while (delta > ((PB - TMIN) * TMAX) >> 1) { delta = Math.floor(delta / (PB - TMIN)); k += PB; }
    return Math.floor(k + ((PB - TMIN + 1) * delta) / (delta + SKEW));
  }
  function pDigit(d) { return String.fromCharCode(d + 22 + 75 * (d < 26)); }
  function pVal(c) { return c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : PB; }
  function pThresh(k, bias) { return k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias; }
  function punyEncodeLabel(input) {
    var cps = Array.from(input).map(function (c) { return c.codePointAt(0); });
    var n = IN, delta = 0, bias = IBIAS;
    var out = cps.filter(function (c) { return c < 128; }).map(function (c) { return String.fromCharCode(c); }).join('');
    var b = out.length, h = b;
    if (b) out += '-';
    while (h < cps.length) {
      var m = Infinity;
      cps.forEach(function (c) { if (c >= n && c < m) m = c; });
      delta += (m - n) * (h + 1); n = m;
      for (var i = 0; i < cps.length; i++) {
        var c = cps[i];
        if (c < n) delta++;
        if (c === n) {
          var q = delta;
          for (var k = PB; ; k += PB) {
            var t = pThresh(k, bias);
            if (q < t) break;
            out += pDigit(t + ((q - t) % (PB - t)));
            q = Math.floor((q - t) / (PB - t));
          }
          out += pDigit(q);
          bias = adapt(delta, h + 1, h === b);
          delta = 0; h++;
        }
      }
      delta++; n++;
    }
    return out;
  }
  function punyDecodeLabel(input) {
    var out = [], basic = input.lastIndexOf('-'), j;
    if (basic < 0) basic = 0;
    for (j = 0; j < basic; j++) { if (input.charCodeAt(j) >= 128) fail('non-basic character before delimiter'); out.push(input.charCodeAt(j)); }
    var n = IN, bias = IBIAS, i = 0;
    for (var idx = basic > 0 ? basic + 1 : 0; idx < input.length;) {
      var oldi = i, w = 1;
      for (var k = PB; ; k += PB) {
        if (idx >= input.length) fail('truncated punycode sequence');
        var d = pVal(input.charCodeAt(idx++));
        if (d >= PB) fail('invalid punycode digit');
        i += d * w;
        var t = pThresh(k, bias);
        if (d < t) break;
        w *= PB - t;
      }
      var len = out.length + 1;
      bias = adapt(i - oldi, len, oldi === 0);
      n += Math.floor(i / len); i %= len;
      out.splice(i++, 0, n);
    }
    return String.fromCodePoint.apply(null, out);
  }
  function punyEnc(s) { return s.split('.').map(function (l) { return /[^\x00-\x7f]/.test(l) ? 'xn--' + punyEncodeLabel(l) : l; }).join('.'); }
  function punyDec(s) { return s.split('.').map(function (l) { return /^xn--/i.test(l) ? punyDecodeLabel(l.slice(4).toLowerCase()) : l; }).join('.'); }

  function jwtEnc(s) {
    var payload; try { payload = JSON.parse(s); } catch (e) { payload = { data: s }; }
    var h = b64urlEnc(utf8(JSON.stringify({ alg: 'none', typ: 'JWT' })));
    return h + '.' + b64urlEnc(utf8(JSON.stringify(payload))) + '.';
  }
  function jwtDec(s) {
    var parts = s.trim().split('.');
    if (parts.length < 2 || parts.length > 3) fail('a jwt has 3 dot-separated segments');
    function seg(p, name) {
      var txt; try { txt = unutf8(b64urlDec(p)); } catch (e) { fail(name + ' is not valid base64url'); }
      try { return JSON.stringify(JSON.parse(txt), null, 2); } catch (e) { fail(name + ' is not valid json'); }
    }
    var out = '// header\n' + seg(parts[0], 'header') + '\n\n// payload\n' + seg(parts[1], 'payload');
    try {
      var p = JSON.parse(unutf8(b64urlDec(parts[1])));
      ['iat', 'nbf', 'exp'].forEach(function (k) { if (typeof p[k] === 'number') out += '\n// ' + k + ' = ' + new Date(p[k] * 1000).toISOString(); });
    } catch (e) { /* already validated */ }
    out += '\n\n// signature (not verified)\n' + (parts[2] || '(none)');
    return out;
  }
  function xorBytes(bytes, key) {
    var k = utf8(String(key)); if (!k.length) fail('key cannot be empty');
    return bytes.map(function (b, i) { return b ^ k[i % k.length]; });
  }
  function dataUriEnc(s) { return 'data:text/plain;charset=utf-8;base64,' + b64enc(utf8(s)); }
  function dataUriDec(s) {
    var m = s.trim().match(/^data:([^,]*?),(.*)$/s);
    if (!m) fail('expected data:[mediatype][;base64],payload');
    return /;base64$/i.test(m[1]) ? unutf8(b64dec(m[2])) : pctDecode(m[2], false);
  }
  function utf16Enc(s) { var o = []; for (var i = 0; i < s.length; i++) o.push(('0000' + s.charCodeAt(i).toString(16)).slice(-4)); return o.join(' '); }
  function utf16Dec(s) {
    var h = s.replace(/0x/gi, '').replace(/\s+/g, '');
    if (!/^[0-9a-f]*$/i.test(h) || h.length % 4) fail('expected 4-digit hex code units');
    var o = ''; for (var i = 0; i < h.length; i += 4) o += String.fromCharCode(parseInt(h.substr(i, 4), 16));
    return o;
  }

  /* ================= hashes & checksums ================= */
  function pad64(bytes, bigEndian, lenBytes) {
    var m = bytes.slice(), bitLen = bytes.length * 8;
    m.push(0x80);
    while (m.length % (lenBytes === 16 ? 128 : 64) !== (lenBytes === 16 ? 112 : 56)) m.push(0);
    var lb = [];
    var big = BigInt(bitLen);
    for (var i = 0; i < lenBytes; i++) { lb.push(Number(big & 255n)); big >>= 8n; }
    if (bigEndian) lb.reverse();
    return m.concat(lb);
  }
  function rotl(x, n) { return (x << n) | (x >>> (32 - n)); }
  function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

  var MD5K = [], MD5S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
  for (var mi = 0; mi < 64; mi++) MD5K[mi] = Math.floor(Math.abs(Math.sin(mi + 1)) * 4294967296) | 0;
  function md5(bytes) {
    var m = pad64(bytes, false, 8), h = [0x67452301, 0xefcdab89 | 0, 0x98badcfe | 0, 0x10325476];
    for (var o = 0; o < m.length; o += 64) {
      var M = [];
      for (var j = 0; j < 16; j++) M[j] = m[o + j * 4] | (m[o + j * 4 + 1] << 8) | (m[o + j * 4 + 2] << 16) | (m[o + j * 4 + 3] << 24);
      var A = h[0], B = h[1], C = h[2], D = h[3];
      for (var i = 0; i < 64; i++) {
        var F, g, r = i >> 4;
        if (r === 0) { F = (B & C) | (~B & D); g = i; }
        else if (r === 1) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
        else if (r === 2) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
        else { F = C ^ (B | ~D); g = (7 * i) % 16; }
        F = (F + A + MD5K[i] + M[g]) | 0;
        A = D; D = C; C = B; B = (B + rotl(F, MD5S[r * 4 + (i % 4)])) | 0;
      }
      h[0] = (h[0] + A) | 0; h[1] = (h[1] + B) | 0; h[2] = (h[2] + C) | 0; h[3] = (h[3] + D) | 0;
    }
    var out = [];
    h.forEach(function (w) { for (var k = 0; k < 4; k++) out.push((w >>> (k * 8)) & 255); });
    return toHex(out);
  }
  function wordsBE(m, o, n) { var W = []; for (var j = 0; j < n; j++) W[j] = (m[o + j * 4] << 24) | (m[o + j * 4 + 1] << 16) | (m[o + j * 4 + 2] << 8) | m[o + j * 4 + 3]; return W; }
  function sha1(bytes) {
    var m = pad64(bytes, true, 8), h = [0x67452301, 0xEFCDAB89 | 0, 0x98BADCFE | 0, 0x10325476, 0xC3D2E1F0 | 0];
    for (var o = 0; o < m.length; o += 64) {
      var W = wordsBE(m, o, 16);
      for (var t = 16; t < 80; t++) W[t] = rotl(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
      var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
      for (t = 0; t < 80; t++) {
        var f, k;
        if (t < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
        else if (t < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
        else if (t < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC | 0; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6 | 0; }
        var tmp = (rotl(a, 5) + f + e + k + W[t]) | 0;
        e = d; d = c; c = rotl(b, 30); b = a; a = tmp;
      }
      h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0; h[4] = (h[4] + e) | 0;
    }
    return h.map(u32hex).join('');
  }

  /* exact SHA-2 constants: fractional bits of square/cube roots of primes, via BigInt integer roots */
  function iroot(n, k) {
    if (n < 2n) return n;
    var K = BigInt(k), approx = BigInt(Math.ceil(Math.pow(Number(n), 1 / k)));
    var x = approx + (approx >> 16n) + 2n;
    for (;;) { var y = ((K - 1n) * x + n / (x ** (K - 1n))) / K; if (y >= x) break; x = y; }
    while (x ** K > n) x -= 1n;
    while ((x + 1n) ** K <= n) x += 1n;
    return x;
  }
  var PRIMES = [];
  for (var pc = 2; PRIMES.length < 80; pc++) { var isP = true; for (var pd = 2; pd * pd <= pc; pd++) if (pc % pd === 0) { isP = false; break; } if (isP) PRIMES.push(pc); }
  var M32 = (1n << 32n) - 1n, M64 = (1n << 64n) - 1n;
  function frac(p, root, bits) { return iroot(BigInt(p) << BigInt(bits * root), root) & ((1n << BigInt(bits)) - 1n); }
  var K256 = PRIMES.slice(0, 64).map(function (p) { return Number(frac(p, 3, 32)) | 0; });
  var H256 = PRIMES.slice(0, 8).map(function (p) { return Number(frac(p, 2, 32)) | 0; });
  var H224 = PRIMES.slice(8, 16).map(function (p) { return Number(frac(p, 2, 64) & M32) | 0; });
  var K512 = PRIMES.map(function (p) { return frac(p, 3, 64); });
  var H512 = PRIMES.slice(0, 8).map(function (p) { return frac(p, 2, 64); });
  var H384 = PRIMES.slice(8, 16).map(function (p) { return frac(p, 2, 64); });

  function sha256core(bytes, iv, outWords) {
    var m = pad64(bytes, true, 8), h = iv.slice(), W = new Array(64);
    for (var o = 0; o < m.length; o += 64) {
      var w16 = wordsBE(m, o, 16), t;
      for (t = 0; t < 16; t++) W[t] = w16[t];
      for (t = 16; t < 64; t++) {
        var s0 = rotr(W[t - 15], 7) ^ rotr(W[t - 15], 18) ^ (W[t - 15] >>> 3);
        var s1 = rotr(W[t - 2], 17) ^ rotr(W[t - 2], 19) ^ (W[t - 2] >>> 10);
        W[t] = (W[t - 16] + s0 + W[t - 7] + s1) | 0;
      }
      var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
      for (t = 0; t < 64; t++) {
        var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25), ch = (e & f) ^ (~e & g);
        var t1 = (hh + S1 + ch + K256[t] + W[t]) | 0;
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22), maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + maj) | 0;
        hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
      h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + hh) | 0;
    }
    return h.slice(0, outWords).map(u32hex).join('');
  }
  function r64(x, n) { return ((x >> n) | (x << (64n - n))) & M64; }
  function sha512core(bytes, iv, outWords) {
    var m = pad64(bytes, true, 16), h = iv.slice(), W = new Array(80);
    for (var o = 0; o < m.length; o += 128) {
      var t;
      for (t = 0; t < 16; t++) { var v = 0n; for (var j = 0; j < 8; j++) v = (v << 8n) | BigInt(m[o + t * 8 + j]); W[t] = v; }
      for (t = 16; t < 80; t++) {
        var s0 = r64(W[t - 15], 1n) ^ r64(W[t - 15], 8n) ^ (W[t - 15] >> 7n);
        var s1 = r64(W[t - 2], 19n) ^ r64(W[t - 2], 61n) ^ (W[t - 2] >> 6n);
        W[t] = (W[t - 16] + s0 + W[t - 7] + s1) & M64;
      }
      var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
      for (t = 0; t < 80; t++) {
        var S1 = r64(e, 14n) ^ r64(e, 18n) ^ r64(e, 41n), ch = (e & f) ^ (~e & M64 & g);
        var t1 = (hh + S1 + ch + K512[t] + W[t]) & M64;
        var S0 = r64(a, 28n) ^ r64(a, 34n) ^ r64(a, 39n), maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + maj) & M64;
        hh = g; g = f; f = e; e = (d + t1) & M64; d = c; c = b; b = a; a = (t1 + t2) & M64;
      }
      h[0] = (h[0] + a) & M64; h[1] = (h[1] + b) & M64; h[2] = (h[2] + c) & M64; h[3] = (h[3] + d) & M64;
      h[4] = (h[4] + e) & M64; h[5] = (h[5] + f) & M64; h[6] = (h[6] + g) & M64; h[7] = (h[7] + hh) & M64;
    }
    return h.slice(0, outWords).map(function (x) { return x.toString(16).padStart(16, '0'); }).join('');
  }

  var CRC32T = (function () { var t = []; for (var n = 0; n < 256; n++) { var c = n; for (var k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
  function crc32(bytes) { var c = 0xFFFFFFFF; for (var i = 0; i < bytes.length; i++) c = CRC32T[(c ^ bytes[i]) & 255] ^ (c >>> 8); return u32hex(c ^ 0xFFFFFFFF); }
  function crc16(bytes) {
    var c = 0xFFFF;
    for (var i = 0; i < bytes.length; i++) { c ^= bytes[i] << 8; for (var k = 0; k < 8; k++) c = c & 0x8000 ? ((c << 1) ^ 0x1021) & 0xFFFF : (c << 1) & 0xFFFF; }
    return ('0000' + c.toString(16)).slice(-4);
  }
  function crc8(bytes) {
    var c = 0;
    for (var i = 0; i < bytes.length; i++) { c ^= bytes[i]; for (var k = 0; k < 8; k++) c = c & 0x80 ? ((c << 1) ^ 0x07) & 0xFF : (c << 1) & 0xFF; }
    return hex2(c);
  }
  function adler32(bytes) { var a = 1, b = 0; for (var i = 0; i < bytes.length; i++) { a = (a + bytes[i]) % 65521; b = (b + a) % 65521; } return u32hex((b << 16) | a); }
  function fnv1a(bytes) { var h = 0x811c9dc5; for (var i = 0; i < bytes.length; i++) { h ^= bytes[i]; h = Math.imul(h, 16777619); } return u32hex(h); }
  function djb2(bytes) { var h = 5381; for (var i = 0; i < bytes.length; i++) h = (Math.imul(h, 33) + bytes[i]) | 0; return u32hex(h); }
  function murmur3(bytes, seed) {
    var h = seed >>> 0, c1 = 0xcc9e2d51, c2 = 0x1b873593, len = bytes.length, nb = len & ~3, k, i;
    for (i = 0; i < nb; i += 4) {
      k = bytes[i] | (bytes[i + 1] << 8) | (bytes[i + 2] << 16) | (bytes[i + 3] << 24);
      k = Math.imul(k, c1); k = rotl(k, 15); k = Math.imul(k, c2);
      h ^= k; h = rotl(h, 13); h = (Math.imul(h, 5) + 0xe6546b64) | 0;
    }
    k = 0;
    switch (len & 3) {
      case 3: k ^= bytes[nb + 2] << 16; // falls through
      case 2: k ^= bytes[nb + 1] << 8; // falls through
      case 1: k ^= bytes[nb]; k = Math.imul(k, c1); k = rotl(k, 15); k = Math.imul(k, c2); h ^= k;
    }
    h ^= len; h ^= h >>> 16; h = Math.imul(h, 0x85ebca6b); h ^= h >>> 13; h = Math.imul(h, 0xc2b2ae35); h ^= h >>> 16;
    return u32hex(h);
  }

  /* ================= registry ================= */
  var RADIX = 'RADIX / BASES', CLASSIC = 'CLASSICAL CIPHERS', MODERN = 'MODERN FORMATS', HASH = 'HASHES & CHECKSUMS';
  function bytesAlgo(id, name, cat, encB, decB, info) {
    return { id: id, name: name, cat: cat, info: info,
      enc: function (s) { return encB(utf8(s)); },
      dec: function (s) { return unutf8(decB(s)); } };
  }
  function hashAlgo(id, name, fn, info) { return { id: id, name: name, cat: HASH, info: info, enc: function (s) { return fn(utf8(s)); }, dec: oneWay }; }
  function self(fn) { return fn; }

  var ALGOS = [
    bytesAlgo('base2', 'Base2 (Binary)', RADIX, function (b) { return radixEnc(b, 2, 8); }, binDec,
      'input is encoded to utf-8 bytes; each byte is written as an 8-bit binary octet, most significant bit first, separated by spaces. decoding strips whitespace and regroups every 8 bits into a byte.'),
    bytesAlgo('base8', 'Base8 (Octal)', RADIX, function (b) { return radixEnc(b, 8, 3); }, function (s) { return parseTokens(s, 8, /^[0-7]{1,3}$/); },
      'each utf-8 byte becomes a zero-padded 3-digit octal number (000–377). tokens are whitespace separated.'),
    bytesAlgo('base10', 'Base10 (Decimal Bytes)', RADIX, function (b) { return b.join(' '); }, function (s) { return parseTokens(s, 10, /^\d{1,3}$/); },
      'each utf-8 byte is printed as its unsigned decimal value 0–255. multi-byte characters expand to several numbers.'),
    bytesAlgo('base16', 'Base16 (Hex)', RADIX, toHex, hexDec,
      'rfc 4648 base16: each utf-8 byte maps to two lowercase hex nibbles. decoding ignores whitespace, colons and 0x prefixes and requires an even digit count.'),
    bytesAlgo('base32', 'Base32', RADIX, function (b) { return b32enc(b, B32, true); }, function (s) { return b32dec(s.toUpperCase().replace(/[\s=]/g, ''), B32); },
      'rfc 4648 base32: bytes are read as a bitstream and cut into 5-bit groups indexed into A–Z2–7. output is padded with "=" to a multiple of 8 characters.'),
    bytesAlgo('base32hex', 'Base32hex', RADIX, function (b) { return b32enc(b, B32HEX, true); }, function (s) { return b32dec(s.toUpperCase().replace(/[\s=]/g, ''), B32HEX); },
      'rfc 4648 §7 "extended hex" alphabet 0–9A–V. same 5-bit grouping as base32 but preserves sort order of the encoded data.'),
    bytesAlgo('crockford', 'Base32 Crockford', RADIX, function (b) { return b32enc(b, B32CROCK, false); }, function (s) { return b32dec(crockNorm(s), B32CROCK); },
      'douglas crockford’s base32 omits I, L, O and U to avoid confusion. no padding; decoding is case-insensitive, maps O→0 and I/L→1 and ignores hyphens.'),
    bytesAlgo('base36', 'Base36', RADIX, function (b) { return bigEnc(b, B36); }, function (s) { return bigDec(s.trim().toLowerCase(), B36); },
      'the byte string is treated as one big-endian integer and repeatedly divided by 36 using 0–9a–z. leading zero bytes are preserved as leading "0" characters.'),
    bytesAlgo('base45', 'Base45', RADIX, b45enc, b45dec,
      'rfc 9285: every 2 bytes form a 16-bit number written as 3 base-45 digits (least significant first); a trailing single byte uses 2 digits. alphabet includes space, so whitespace is significant.'),
    bytesAlgo('base58', 'Base58 (Bitcoin)', RADIX, function (b) { return bigEnc(b, B58); }, function (s) { return bigDec(s.trim(), B58); },
      'big-integer division by 58 using the bitcoin alphabet, which drops 0, O, I and l. each leading zero byte becomes a leading "1".'),
    bytesAlgo('base62', 'Base62', RADIX, function (b) { return bigEnc(b, B62); }, function (s) { return bigDec(s.trim(), B62); },
      'big-integer conversion to radix 62 with alphabet 0–9A–Za–z; url-safe without padding. leading zero bytes map to leading "0".'),
    bytesAlgo('base64', 'Base64', RADIX, b64enc, b64dec,
      'rfc 4648 base64: every 3 bytes (24 bits) become 4 six-bit indices into A–Za–z0–9+/. short tails are padded with "=".'),
    bytesAlgo('base64url', 'Base64url', RADIX, b64urlEnc, b64urlDec,
      'rfc 4648 §5 url and filename safe variant: "+" → "-", "/" → "_" and padding removed. used in jwt and many web tokens.'),
    bytesAlgo('ascii85', 'Base85 (Ascii85)', RADIX, function (b) { return a85core(b, A85, true); }, function (s) { return a85decCore(s.replace(/^\s*<~|~>\s*$/g, '').replace(/\s+/g, ''), A85, true); },
      'adobe ascii85: each 4-byte group is a 32-bit integer written as 5 base-85 digits from "!" to "u". an all-zero group shortens to "z"; a partial tail of n bytes emits n+1 digits.'),
    bytesAlgo('z85', 'Z85 (ZeroMQ)', RADIX, function (b) { return a85core(b, Z85, false); }, function (s) { return a85decCore(s.replace(/\s+/g, ''), Z85, false); },
      'zeromq rfc 32 base85 with a source-code-safe alphabet (no quotes or backslash). 4 bytes → 5 chars, big-endian; partial tails are truncated ascii85-style.'),
    bytesAlgo('base91', 'Base91', RADIX, b91enc, b91dec,
      'basE91 by joachim henke: pulls 13 or 14 bits at a time from the bitstream and writes them as two base-91 symbols, roughly 23% overhead versus 33% for base64.'),

    { id: 'caesar', name: 'Caesar', cat: CLASSIC, param: { label: 'shift', def: '3' },
      enc: function (s, p) { return shift(s, int(p, 3)); }, dec: function (s, p) { return shift(s, -int(p, 3)); },
      info: 'monoalphabetic shift: each latin letter moves n places along the alphabet, wrapping z→a. case is kept; digits, punctuation and non-latin characters pass through untouched.' },
    { id: 'rot13', name: 'ROT13', cat: CLASSIC, enc: function (s) { return shift(s, 13); }, dec: function (s) { return shift(s, 13); },
      info: 'caesar with a fixed shift of 13. because 13 is half of 26, applying it twice returns the original text — encode and decode are identical.' },
    { id: 'rot5', name: 'ROT5', cat: CLASSIC, enc: rot5, dec: rot5,
      info: 'rotates only the digits 0–9 by five positions (0↔5, 1↔6 …). self-inverse; letters are untouched.' },
    { id: 'rot18', name: 'ROT18', cat: CLASSIC, enc: function (s) { return rot5(shift(s, 13)); }, dec: function (s) { return rot5(shift(s, 13)); },
      info: 'rot13 on letters combined with rot5 on digits. self-inverse.' },
    { id: 'rot47', name: 'ROT47', cat: CLASSIC, enc: rot47, dec: rot47,
      info: 'rotates every printable ascii character from "!" (33) to "~" (126) by 47 within that 94-symbol range. self-inverse; spaces and non-ascii pass through.' },
    { id: 'atbash', name: 'Atbash', cat: CLASSIC, enc: atbash, dec: atbash,
      info: 'mirrors the alphabet: a↔z, b↔y, c↔x … originally a hebrew cipher. self-inverse; case preserved.' },
    { id: 'affine', name: 'Affine', cat: CLASSIC, param: { label: 'a,b', def: '5,8' },
      enc: function (s, p) { var k = affineParams(p); return mapLetters(s, function (x) { return mod(k.a * x + k.b, 26); }); },
      dec: function (s, p) { var k = affineParams(p); return mapLetters(s, function (x) { return mod(k.inv * (x - k.b), 26); }); },
      info: 'e(x) = (a·x + b) mod 26, d(y) = a⁻¹·(y − b) mod 26. a must be coprime with 26 so that its modular inverse exists.' },
    { id: 'vigenere', name: 'Vigenère', cat: CLASSIC, param: { label: 'key', def: 'LEMON' },
      enc: function (s, p) { return vigenere(s, p, 1); }, dec: function (s, p) { return vigenere(s, p, -1); },
      info: 'polyalphabetic caesar: the key letters (a=0 … z=25) are repeated across the text and added to each letter. the key only advances on letters, so spacing is preserved.' },
    { id: 'beaufort', name: 'Beaufort', cat: CLASSIC, param: { label: 'key', def: 'FORTIFICATION' },
      enc: function (s, p) { return beaufort(s, p); }, dec: function (s, p) { return beaufort(s, p); },
      info: 'c = (k − p) mod 26 with a repeating key. a reciprocal cipher: the same operation both encrypts and decrypts.' },
    { id: 'autokey', name: 'Autokey', cat: CLASSIC, param: { label: 'key', def: 'QUEEN' },
      enc: function (s, p) { return autokeyEnc(s, p); }, dec: function (s, p) { return autokeyDec(s, p); },
      info: 'vigenère where the keystream is the primer key followed by the plaintext itself, avoiding the short repeating period that breaks classic vigenère.' },
    { id: 'keyword', name: 'Keyword Substitution', cat: CLASSIC, param: { label: 'key', def: 'ZEBRAS' },
      enc: function (s, p) { return keywordSub(s, p, 1); }, dec: function (s, p) { return keywordSub(s, p, -1); },
      info: 'cipher alphabet = unique letters of the keyword followed by the remaining letters in order. each plaintext letter is replaced by the letter at the same index.' },
    { id: 'playfair', name: 'Playfair', cat: CLASSIC, param: { label: 'key', def: 'PLAYFAIR EXAMPLE' },
      enc: function (s, p) { return playfair(s, p, 1); }, dec: function (s, p) { return playfair(s, p, -1); },
      info: 'digraph cipher on a 5×5 keyed square (j merged into i). pairs in a row shift right, in a column shift down, otherwise swap corners of their rectangle. doubles and odd tails get an x filler; non-letters are dropped.' },
    { id: 'railfence', name: 'Rail Fence', cat: CLASSIC, param: { label: 'rails', def: '3' },
      enc: function (s, p) { return railEnc(s, int(p, 3)); }, dec: function (s, p) { return railDec(s, int(p, 3)); },
      info: 'transposition: characters are written in a zigzag across n rails and read off rail by rail. every character, including spaces, takes part.' },
    { id: 'columnar', name: 'Columnar Transposition', cat: CLASSIC, param: { label: 'key', def: 'ZEBRAS' },
      enc: function (s, p) { return columnarEnc(s, p); }, dec: function (s, p) { return columnarDec(s, p); },
      info: 'text is written row by row under the key, then columns are read in the alphabetical order of the key letters (ties left to right). no padding; irregular last row.' },
    { id: 'scytale', name: 'Scytale', cat: CLASSIC, param: { label: 'turns', def: '4' },
      enc: function (s, p) { return columnarEnc(s, seqKey(int(p, 4))); }, dec: function (s, p) { return columnarDec(s, seqKey(int(p, 4))); },
      info: 'spartan rod cipher: the strip is read every n-th character, equivalent to a columnar transposition with columns taken in natural order.' },
    { id: 'bacon', name: 'Bacon', cat: CLASSIC, enc: baconEnc, dec: baconDec,
      info: '26-letter bacon cipher: each letter’s index 0–25 is written as 5 binary symbols with a=0 and b=1. words are separated by " / "; non-letters are dropped.' },
    { id: 'polybius', name: 'Polybius Square', cat: CLASSIC,
      enc: function (s) { return gridEnc(s, POLY, function (r, c) { return '' + r + c; }); },
      dec: function (s) { return gridDec(s, POLY, function (w) { return w.replace(/[^1-5]/g, '').split('').map(Number); }); },
      info: 'letters are placed in a 5×5 grid (i/j share a cell) and replaced by their row and column digits, e.g. h → 23.' },
    { id: 'tapcode', name: 'Tap Code', cat: CLASSIC,
      enc: function (s) { return gridEnc(s, TAP, function (r, c) { return '.'.repeat(r) + ' ' + '.'.repeat(c); }); },
      dec: function (s) { return gridDec(s, TAP, function (w) { return tokens(w).map(function (t) { if (!/^\.+$/.test(t)) fail('tap groups must be dots'); return t.length; }); }); },
      info: 'prison knock code on a 5×5 grid where k shares c’s cell. each letter is two groups of taps (dots): row count, then column count.' },
    { id: 'morse', name: 'Morse Code', cat: CLASSIC, enc: morseEnc, dec: morseDec,
      info: 'itu international morse: letters, digits and common punctuation become dot/dash sequences separated by spaces; words are separated by " / ". unsupported characters are skipped.' },
    { id: 'a1z26', name: 'A1Z26', cat: CLASSIC, enc: a1z26Enc, dec: a1z26Dec,
      info: 'each letter becomes its 1-based alphabet position joined with "-"; words are separated by spaces. non-letters are dropped.' },
    { id: 'nato', name: 'NATO Phonetic', cat: CLASSIC, enc: natoEnc, dec: natoDec,
      info: 'icao spelling alphabet: letters and digits map to code words (alfa, bravo … niner). words are separated by " / ".' },
    { id: 'reverse', name: 'Reverse', cat: CLASSIC, enc: function (s) { return Array.from(s).reverse().join(''); }, dec: function (s) { return Array.from(s).reverse().join(''); },
      info: 'reverses the sequence of unicode code points (surrogate pairs stay intact). self-inverse.' },

    { id: 'url', name: 'URL Encode', cat: MODERN, enc: encodeURIComponent, dec: function (s) { return pctDecode(s, true); },
      info: 'rfc 3986 percent-encoding as in encodeURIComponent: unreserved characters stay, everything else becomes %XX per utf-8 byte. decoding also treats "+" as a space.' },
    { id: 'urlall', name: 'URL Encode (All Bytes)', cat: MODERN, enc: urlAllEnc, dec: function (s) { return pctDecode(s, false); },
      info: 'percent-encodes every utf-8 byte, including letters and digits. useful for obfuscation tests and filter bypass checks.' },
    { id: 'html', name: 'HTML Entities', cat: MODERN, enc: htmlEnc, dec: htmlDec,
      info: 'escapes the five html-significant characters & < > " \' to entities. decoding resolves common named entities plus decimal &#n; and hex &#xh; references.' },
    { id: 'htmlnum', name: 'HTML Numeric Entities', cat: MODERN, enc: htmlNumEnc, dec: htmlDec,
      info: 'every unicode code point is written as a decimal character reference &#n;. astral characters produce a single reference, not surrogate pairs.' },
    { id: 'uescape', name: 'Unicode Escape (\\u)', cat: MODERN, enc: uEscEnc, dec: uEscDec,
      info: 'every utf-16 code unit becomes \\uXXXX as in javascript and java string literals; astral characters become surrogate pairs. decoding also accepts \\u{…} and \\xXX.' },
    { id: 'codepoints', name: 'Unicode Code Points', cat: MODERN, enc: cpEnc, dec: cpDec,
      info: 'lists each code point in U+XXXX notation (at least 4 hex digits). decoding accepts U+, 0x or bare hex tokens.' },
    { id: 'json', name: 'JSON String', cat: MODERN, enc: function (s) { return JSON.stringify(s); }, dec: jsonDec,
      info: 'serialises the input as a json string literal: quotes, backslashes and control characters are escaped per rfc 8259.' },
    { id: 'qp', name: 'Quoted-Printable', cat: MODERN, enc: qpEnc, dec: qpDec,
      info: 'rfc 2045 mime encoding: printable ascii stays literal, other utf-8 bytes and "=" become =XX. lines are soft-wrapped at 76 characters with a trailing "=".' },
    { id: 'uuencode', name: 'Uuencode', cat: MODERN, enc: uuEnc, dec: uuDec,
      info: 'unix-to-unix encoding: lines of up to 45 bytes, prefixed with a length character; every 3 bytes become 4 characters offset from space (zero written as `). wrapped in begin/end.' },
    { id: 'punycode', name: 'Punycode (IDN)', cat: MODERN, enc: punyEnc, dec: punyDec,
      info: 'rfc 3492 bootstring used for internationalised domain names. each dot-separated label with non-ascii characters becomes "xn--" + basic chars + delta-encoded code points.' },
    { id: 'jwt', name: 'JWT', cat: MODERN, enc: jwtEnc, dec: jwtDec,
      info: 'decode splits header.payload.signature, base64url-decodes and pretty-prints the json and converts iat/nbf/exp to iso time. the signature is shown but never verified. encode emits an unsigned alg:none token from json input.' },
    { id: 'xor', name: 'XOR (Hex)', cat: MODERN, param: { label: 'key', def: 'key' },
      enc: function (s, p) { return toHex(xorBytes(utf8(s), p)); }, dec: function (s, p) { return unutf8(xorBytes(hexDec(s), p)); },
      info: 'utf-8 bytes of the input are xored with the repeating utf-8 bytes of the key; output is hex. applying the same key again restores the bytes.' },
    { id: 'datauri', name: 'Data URI', cat: MODERN, enc: dataUriEnc, dec: dataUriDec,
      info: 'rfc 2397 data url with text/plain;charset=utf-8 and a base64 payload. decoding accepts base64 or percent-encoded payloads.' },
    { id: 'utf16', name: 'UTF-16 (Hex)', cat: MODERN, enc: utf16Enc, dec: utf16Dec,
      info: 'shows the raw utf-16 big-endian code units as 4-digit hex. characters outside the bmp appear as a high + low surrogate pair.' },

    hashAlgo('md5', 'MD5', md5, 'rfc 1321 128-bit digest over utf-8 bytes: 64 rounds of 32-bit little-endian mixing. broken for collision resistance; fine for checksums.'),
    hashAlgo('sha1', 'SHA-1', sha1, 'fips 180-4 160-bit digest with 80 rounds over 512-bit blocks. collision attacks are practical (shattered, 2017).'),
    hashAlgo('sha224', 'SHA-224', function (b) { return sha256core(b, H224, 7); }, 'sha-256 compression with a different initial state, truncated to 224 bits.'),
    hashAlgo('sha256', 'SHA-256', function (b) { return sha256core(b, H256, 8); }, 'fips 180-4 merkle–damgård hash: 64 rounds over 512-bit blocks of big-endian 32-bit words, producing a 256-bit digest.'),
    hashAlgo('sha384', 'SHA-384', function (b) { return sha512core(b, H384, 6); }, 'sha-512 compression with distinct initial values, truncated to 384 bits.'),
    hashAlgo('sha512', 'SHA-512', function (b) { return sha512core(b, H512, 8); }, 'fips 180-4 with 64-bit words and 80 rounds over 1024-bit blocks; computed here with bigint arithmetic.'),
    hashAlgo('crc32', 'CRC-32', crc32, 'ieee 802.3 cyclic redundancy check, reflected polynomial 0xedb88320, init and final xor 0xffffffff. used by zip, png and ethernet.'),
    hashAlgo('crc16', 'CRC-16/CCITT-FALSE', crc16, 'polynomial 0x1021, init 0xffff, no reflection, no final xor. check value for "123456789" is 29b1.'),
    hashAlgo('crc8', 'CRC-8', crc8, 'crc-8/smbus: polynomial 0x07, init 0x00, no reflection. check value for "123456789" is f4.'),
    hashAlgo('adler32', 'Adler-32', adler32, 'zlib checksum: two running sums modulo 65521 packed as (b << 16) | a. faster than crc but weaker on short inputs.'),
    hashAlgo('fnv1a', 'FNV-1a (32-bit)', fnv1a, 'fowler–noll–vo: for each byte, xor into the hash then multiply by the fnv prime 16777619, starting from 0x811c9dc5.'),
    hashAlgo('djb2', 'DJB2', djb2, 'dan bernstein’s string hash: h = h × 33 + byte, starting at 5381, kept to 32 bits.'),
    hashAlgo('murmur3', 'MurmurHash3 (32-bit)', function (b) { return murmur3(b, 0); }, 'murmurhash3 x86_32 with seed 0: 4-byte blocks mixed with multiply-rotate constants, then an avalanche finaliser. non-cryptographic.')
  ];

  function transform(id, mode, input, param) {
    var a = ALGOS.filter(function (x) { return x.id === id; })[0];
    if (!a) fail('unknown algorithm ' + id);
    var p = param === undefined || param === null ? (a.param ? a.param.def : '') : param;
    return mode === 'decode' ? a.dec(input, p) : a.enc(input, p);
  }

  var API = { ALGOS: ALGOS, transform: transform, CATEGORIES: [RADIX, CLASSIC, MODERN, HASH] };
  if (typeof module !== 'undefined' && module.exports) module.exports = API;

  /* ================= UI ================= */
  if (typeof document === 'undefined' || !document.getElementById('app')) return;

  var $ = function (id) { return document.getElementById(id); };
  var state = { id: 'base2', mode: 'encode', q: '', params: {} };
  ALGOS.forEach(function (a) { if (a.param) state.params[a.id] = a.param.def; });

  var el = { input: $('input'), output: $('output'), inCount: $('inCount'), outCount: $('outCount'), copy: $('copyBtn'),
    pill: $('algoPillName'), infoTitle: $('infoTitle'), infoText: $('infoText'), list: $('list'), search: $('search'),
    paramWrap: $('paramWrap'), paramLabel: $('paramLabel'), paramInput: $('paramInput'), swap: $('swapBtn'), count: $('algoCount') };

  function current() { return ALGOS.filter(function (a) { return a.id === state.id; })[0]; }
  function chars(s) { var n = Array.from(s).length; return n + (n === 1 ? ' CHAR' : ' CHARS'); }

  function run() {
    var a = current(), out, err = false;
    try { out = state.mode === 'decode' ? a.dec(el.input.value, state.params[a.id]) : a.enc(el.input.value, state.params[a.id]); }
    catch (e) { out = (e.notice ? '— ' : 'ERR · ') + (e.message || String(e)); err = true; }
    el.output.value = out;
    el.output.classList.toggle('is-error', err);
    el.inCount.textContent = chars(el.input.value);
    el.outCount.textContent = err ? '0 CHARS' : chars(out);
  }

  function renderMeta() {
    var a = current();
    el.pill.textContent = a.name;
    el.infoTitle.textContent = 'ABOUT · ' + a.name.toUpperCase();
    el.infoText.textContent = a.info;
    if (a.param) {
      el.paramWrap.hidden = false;
      el.paramLabel.textContent = a.param.label;
      el.paramInput.value = state.params[a.id];
    } else el.paramWrap.hidden = true;
    Array.prototype.forEach.call(el.list.querySelectorAll('.item'), function (b) {
      var on = b.getAttribute('data-id') === a.id;
      b.classList.toggle('is-active', on);
      b.setAttribute('aria-current', on ? 'true' : 'false');
    });
  }

  function renderList() {
    var q = state.q.trim().toLowerCase(), html = '', total = 0;
    API.CATEGORIES.forEach(function (cat) {
      var items = ALGOS.filter(function (a) { return a.cat === cat && (!q || a.name.toLowerCase().indexOf(q) >= 0 || a.id.indexOf(q) >= 0); });
      if (!items.length) return;
      total += items.length;
      html += '<div class="cat-title"><span>' + cat.replace('&', '&amp;') + '</span><span>' + items.length + '</span></div>';
      items.forEach(function (a) { html += '<button type="button" class="item" data-id="' + a.id + '">' + htmlEnc(a.name) + '</button>'; });
    });
    el.list.innerHTML = html || '<div class="empty">no algorithm matches "' + htmlEnc(state.q) + '"</div>';
    el.count.textContent = 'ALGORITHMS · ' + (q ? total + '/' : '') + ALGOS.length;
    renderMeta();
  }

  function select(id) { state.id = id; renderMeta(); run(); }

  function setMode(mode) {
    state.mode = mode;
    Array.prototype.forEach.call(document.querySelectorAll('.seg-btn'), function (b) {
      var on = b.getAttribute('data-mode') === mode;
      b.classList.toggle('is-active', on);
      b.setAttribute('aria-checked', on ? 'true' : 'false');
    });
    run();
  }

  el.input.addEventListener('input', run);
  el.paramInput.addEventListener('input', function () { state.params[state.id] = el.paramInput.value; run(); });
  el.search.addEventListener('input', function () { state.q = el.search.value; renderList(); });
  el.search.addEventListener('keydown', function (e) {
    if (e.key === 'Enter') { var first = el.list.querySelector('.item'); if (first) select(first.getAttribute('data-id')); }
    if (e.key === 'Escape') { el.search.value = ''; state.q = ''; renderList(); }
  });
  el.list.addEventListener('click', function (e) {
    var b = e.target.closest('.item'); if (b) select(b.getAttribute('data-id'));
  });
  Array.prototype.forEach.call(document.querySelectorAll('.seg-btn'), function (b) {
    b.addEventListener('click', function () { setMode(b.getAttribute('data-mode')); });
  });
  el.swap.addEventListener('click', function () {
    if (el.output.classList.contains('is-error')) return;
    el.input.value = el.output.value;
    setMode(state.mode === 'encode' ? 'decode' : 'encode');
  });

  var copyTimer;
  el.copy.addEventListener('click', function () {
    var text = el.output.value;
    function flash() {
      el.copy.textContent = 'COPIED'; el.copy.classList.add('is-copied');
      clearTimeout(copyTimer);
      copyTimer = setTimeout(function () { el.copy.textContent = 'COPY OUTPUT'; el.copy.classList.remove('is-copied'); }, 1200);
    }
    function fallback() { el.output.select(); try { document.execCommand('copy'); } catch (e) { /* ignore */ } flash(); }
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(flash, fallback);
    else fallback();
  });

  renderList();
  run();
})();
