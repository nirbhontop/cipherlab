# Cipher Lab

https://cipher.coolkta.me/

Type on the left. Instant output on the right. **Cipher Lab** is a zero-dependency, client-side encoding, radix conversion, classical cipher, and hashing workbench built in three files (`index.html`, `style.css`, and `app.js`). 

Everything runs strictly in local browser memory—no servers, no analytics, no external fonts, and no network requests. Nothing leaves your machine.

---

## Features

- **65 Local Algorithms:** Instant, zero-debounce transformations across four categories.
- **Strictly 3 Files:** Vanilla HTML, CSS, and ES5/ES6+ JavaScript with zero build steps or external dependencies.
- **Tactile Instrument UI:** Styled with the *Daylight Ultraviolet* 3-color palette (`#F4F2F7` Chalk Violet canvas, `#1A112B` Deep Aubergine ink, and `#7B2CBF` Electric Royal Purple active states).
- **Workflow Utilities:**
  - Live Unicode character counters for both input and output.
  - One-click **⇄ SWAP** to move output back into input and invert the encode/decode mode.
  - Dynamic parameter inputs (keys, shifts, rails, affine coefficients) for ciphers that require them.
  - Instant sidebar search filtering (`Enter` to select top match, `Esc` to clear).
  - Built-in technical reference card explaining how each algorithm processes bytes or characters.

---

## Supported Algorithms (65)

### Radix / Bases (16)
`Base2 (Binary)` · `Base8 (Octal)` · `Base10 (Decimal Bytes)` · `Base16 (Hex)` · `Base32` · `Base32hex` · `Base32 Crockford` · `Base36` · `Base45` · `Base58 (Bitcoin)` · `Base62` · `Base64` · `Base64url` · `Base85 (Ascii85)` · `Z85 (ZeroMQ)` · `Base91`

### Classical Ciphers (22)
`Caesar` · `ROT13` · `ROT5` · `ROT18` · `ROT47` · `Atbash` · `Affine` · `Vigenère` · `Beaufort` · `Autokey` · `Keyword Substitution` · `Playfair` · `Rail Fence` · `Columnar Transposition` · `Scytale` · `Bacon` · `Polybius Square` · `Tap Code` · `Morse Code` · `A1Z26` · `NATO Phonetic` · `Reverse`

### Modern Formats (14)
`URL Encode` · `URL Encode (All Bytes)` · `HTML Entities` · `HTML Numeric Entities` · `Unicode Escape (\u)` · `Unicode Code Points` · `JSON String` · `Quoted-Printable` · `Uuencode` · `Punycode (IDN)` · `JWT` · `XOR (Hex)` · `Data URI` · `UTF-16 (Hex)`

### Hashes & Checksums (13)
`MD5` · `SHA-1` · `SHA-224` · `SHA-256` · `SHA-384` · `SHA-512` · `CRC-32` · `CRC-16/CCITT-FALSE` · `CRC-8` · `Adler-32` · `FNV-1a (32-bit)` · `DJB2` · `MurmurHash3 (32-bit)`

---

## Project Structure

```text
cipher-lab/
├── index.html   # Semantic workspace, split editor panes, and algorithm sidebar
├── style.css    # Grid layout and strict 3-color Daylight Ultraviolet palette
└── app.js       # 65 pure transform implementations and DOM state bindings
```

---

## Usage

### In the Browser
No build tools or local server required. Simply open `index.html` directly in any modern web browser.

### As a Node.js Module
`app.js` exports its transformation engine when loaded in a CommonJS environment:

```js
const { transform, ALGOS, CATEGORIES } = require('./app.js');

const encoded = transform('caesar', 'encode', 'Hello World', '3');
// -> 'Khoor Zruog'

const decoded = transform('base64', 'decode', 'SGVsbG8gV29ybGQ=');
// -> 'Hello World'
```

---

## License

MIT
