/**
 * kopacz.js — Zero-Dependency JavaScript SDK & CLI for Kopacz v3
 *
 * Works in:
 *   - Browser (loaded via kopacz.js -> window.Kopacz)
 *   - Node.js / Bun / Deno (const Kopacz = require("./kopacz.js"))
 *   - CLI (node kopacz.js -d <domain> -k <64-hex-pubkey> [-r host:port] <fetch <url> | echo>)
 *
 * Protocol:
 *   - Handshake : 1-RTT Noise_NK-style X25519 (`es` + `ee`), SYN (56B) / SYN-ACK (48B)
 *   - Data AEAD : ChaCha20-Poly1305 (RFC 7539) + 64-packet anti-replay window + AAD
 *   - KDF       : HKDF-SHA256 (RFC 5869, pure JS — works in file:// & http:// without crypto.subtle)
 *   - Compression: LZ4 Frame (RFC-compliant decompressor + store compressor)
 *   - Carrier   : Base32 DNS QNAME + TXT / DoH / UDP
 */
(function(root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.Kopacz = factory();
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function() {
  "use strict";

  function randomBytes(buf) {
    if (typeof crypto !== "undefined" && crypto.getRandomValues) {
      crypto.getRandomValues(buf);
      return buf;
    }
    if (typeof require === "function") {
      var nodeCrypto = require("crypto");
      var rb = nodeCrypto.randomBytes(buf.length);
      buf.set(rb);
      return buf;
    }
    throw new Error("No CSPRNG available");
  }

  // ══════════════════════════════════════════════════════════════
  // X25519 (TweetNaCl.js v1.0.3 scalarMult subset, Public Domain)
  // ══════════════════════════════════════════════════════════════
  var nacl = (function() {
    var n = function(a, b) { for (var i = 0; i < 16; i++) a[i] = b[i] | 0; };
    var D = new Float64Array([0xdb41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    function A(o, a, b) { for (var i = 0; i < 16; i++) o[i] = a[i] + b[i]; }
    function Z(o, a, b) { for (var i = 0; i < 16; i++) o[i] = a[i] - b[i]; }
    function car25519(o) {
      var i, c;
      for (i = 0; i < 16; i++) {
        o[i] += 65536;
        c = Math.floor(o[i] / 65536);
        o[(i + 1) * (i < 15 ? 1 : 0)] += c - 1 + 37 * (c - 1) * (i === 15 ? 1 : 0);
        o[i] -= c * 65536;
      }
    }
    function M(o, a, b) {
      var i, j, t = new Float64Array(31);
      for (i = 0; i < 31; i++) t[i] = 0;
      for (i = 0; i < 16; i++) for (j = 0; j < 16; j++) t[i + j] += a[i] * b[j];
      for (i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
      for (i = 0; i < 16; i++) o[i] = t[i];
      car25519(o);
      car25519(o);
    }
    function S(o, a) { M(o, a, a); }
    function inv25519(o, a) {
      var c = new Float64Array(16), i;
      for (i = 0; i < 16; i++) c[i] = a[i];
      for (i = 253; i >= 0; i--) { S(c, c); if (i !== 2 && i !== 4) M(c, c, a); }
      for (i = 0; i < 16; i++) o[i] = c[i];
    }
    function pack25519(o, inp) {
      var i, j, b, m = new Float64Array(16), t = new Float64Array(16);
      for (i = 0; i < 16; i++) t[i] = inp[i];
      car25519(t); car25519(t); car25519(t);
      for (j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; i++) { m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1); m[i - 1] &= 0xffff; }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        n(t, b ? t : m);
      }
      for (i = 0; i < 16; i++) { o[2 * i] = t[i] & 0xff; o[2 * i + 1] = t[i] >> 8; }
    }
    function unpack25519(o, n) {
      for (var i = 0; i < 16; i++) o[i] = n[2 * i] + (n[2 * i + 1] << 8);
      o[15] &= 0x7fff;
    }
    function sel25519(p, q, b) {
      var t, c = ~(b - 1);
      for (var i = 0; i < 16; i++) { t = c & (p[i] ^ q[i]); p[i] ^= t; q[i] ^= t; }
    }
    function scalarMult(q, n, p) {
      var z = new Uint8Array(32), x = new Float64Array(80), i, r;
      var a = new Float64Array(16), b = new Float64Array(16), c = new Float64Array(16),
          d = new Float64Array(16), e = new Float64Array(16), f = new Float64Array(16);
      for (i = 0; i < 31; i++) z[i] = n[i];
      z[31] = (n[31] & 127) | 64;
      z[0] &= 248;
      unpack25519(x, p);
      for (i = 0; i < 16; i++) { b[i] = x[i]; a[i] = d[i] = c[i] = 0; }
      a[0] = d[0] = 1;
      for (i = 254; i >= 0; --i) {
        r = (z[i >>> 3] >>> (i & 7)) & 1;
        sel25519(a, b, r); sel25519(c, d, r);
        A(e, a, c); Z(a, a, c); A(c, b, d); Z(b, b, d);
        S(d, e); S(f, a); M(a, c, a); M(c, b,e);
        A(e, a, c); Z(a, a, c); S(b, a); Z(c, d, f);
        M(a, c, D); A(a, a, d); M(c, c, a); M(a, d, f);
        M(d, b, x); S(b, e);
        sel25519(a, b, r); sel25519(c, d, r);
      }
      for (i = 0; i < 16; i++) { x[i + 16] = a[i]; x[i + 32] = c[i]; x[i + 48] = b[i]; x[i + 64] = d[i]; }
      var x32 = x.subarray(32), x16 = x.subarray(16);
      inv25519(x32, x32);
      M(x16, x16, x32);
      pack25519(q, x16);
    }
    var _9 = new Uint8Array(32); _9[0] = 9;
    function scalarMultBase(q, n) { return scalarMult(q, n, _9); }
    function generateKeyPair() {
      var sk = randomBytes(new Uint8Array(32));
      var pk = new Uint8Array(32);
      scalarMultBase(pk, sk);
      return { publicKey: pk, secretKey: sk };
    }
    function sharedKey(mySecret, theirPublic) {
      var q = new Uint8Array(32);
      scalarMult(q, mySecret, theirPublic);
      return q;
    }
    return {
      scalarMult: scalarMult,
      scalarMult_base: scalarMultBase,
      generateKeyPair: generateKeyPair,
      sharedKey: sharedKey
    };
  })();

  // ══════════════════════════════════════════════════════════════
  // SHA-256, HMAC-SHA256, HKDF-SHA256 (Pure JS, synchronous)
  // ══════════════════════════════════════════════════════════════
  var SHA256 = (function() {
    var K = new Uint32Array([
      0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ]);
    function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

    function hash(msg) {
      var h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
      var h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
      var bitLen = msg.length * 8;
      var padLen = ((msg.length + 9 + 63) & ~63);
      var buf = new Uint8Array(padLen);
      buf.set(msg);
      buf[msg.length] = 0x80;
      var dv = new DataView(buf.buffer);
      dv.setUint32(padLen - 8, Math.floor(bitLen / 4294967296), false);
      dv.setUint32(padLen - 4, bitLen >>> 0, false);

      var w = new Uint32Array(64);
      for (var off = 0; off < padLen; off += 64) {
        for (var i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4, false);
        for (var i = 16; i < 64; i++) {
          var s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
          var s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
          w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
        }
        var a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
        for (var i = 0; i < 64; i++) {
          var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
          var ch = (e & f) ^ (~e & g);
          var t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
          var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
          var maj = (a & b) ^ (a & c) ^ (b & c);
          var t2 = (S0 + maj) >>> 0;
          h = g; g = f; f = e; e = (d + t1) >>> 0;
          d = c; c = b; b = a; a = (t1 + t2) >>> 0;
        }
        h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
        h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
      }
      var out = new Uint8Array(32);
      var odv = new DataView(out.buffer);
      odv.setUint32(0, h0, false); odv.setUint32(4, h1, false);
      odv.setUint32(8, h2, false); odv.setUint32(12, h3, false);
      odv.setUint32(16, h4, false); odv.setUint32(20, h5, false);
      odv.setUint32(24, h6, false); odv.setUint32(28, h7, false);
      return out;
    }

    function hmac(key, data) {
      var k = key.length > 64 ? hash(key) : key;
      var ipad = new Uint8Array(64), opad = new Uint8Array(64);
      for (var i = 0; i < 64; i++) {
        var b = i < k.length ? k[i] : 0;
        ipad[i] = b ^ 0x36;
        opad[i] = b ^ 0x5c;
      }
      return hash(concatBytes([opad, hash(concatBytes([ipad, data]))]));
    }

    function hkdf(ikm, salt, info, length) {
      var actualSalt = (salt && salt.length) ? salt : new Uint8Array(32);
      var prk = hmac(actualSalt, ikm);
      var okm = new Uint8Array(length);
      var prev = new Uint8Array(0);
      var pos = 0, counter = 1;
      while (pos < length) {
        prev = hmac(prk, concatBytes([prev, info, new Uint8Array([counter++])]));
        var take = Math.min(32, length - pos);
        okm.set(prev.subarray(0, take), pos);
        pos += take;
      }
      return okm;
    }

    return { hash: hash, hmac: hmac, hkdf: hkdf };
  })();

  // ══════════════════════════════════════════════════════════════
  // ChaCha20-Poly1305 AEAD (RFC 7539)
  // ══════════════════════════════════════════════════════════════
  var ChaCha20 = (function() {
    function rotl32(v, n) { return ((v << n) | (v >>> (32 - n))) | 0; }
    function quarterRound(s, a, b, c, d) {
      s[a] = (s[a] + s[b]) | 0; s[d] = rotl32(s[d] ^ s[a], 16);
      s[c] = (s[c] + s[d]) | 0; s[b] = rotl32(s[b] ^ s[c], 12);
      s[a] = (s[a] + s[b]) | 0; s[d] = rotl32(s[d] ^ s[a], 8);
      s[c] = (s[c] + s[d]) | 0; s[b] = rotl32(s[b] ^ s[c], 7);
    }
    function chacha20Block(key, counter, nonce) {
      var s = new Int32Array(16);
      s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
      var kv = new DataView(key.buffer, key.byteOffset, 32);
      for (var i = 0; i < 8; i++) s[4 + i] = kv.getInt32(i * 4, true);
      s[12] = counter;
      var nv = new DataView(nonce.buffer, nonce.byteOffset, 12);
      s[13] = nv.getInt32(0, true); s[14] = nv.getInt32(4, true); s[15] = nv.getInt32(8, true);
      var ws = new Int32Array(s);
      for (var r = 0; r < 10; r++) {
        quarterRound(ws,0,4,8,12); quarterRound(ws,1,5,9,13);
        quarterRound(ws,2,6,10,14); quarterRound(ws,3,7,11,15);
        quarterRound(ws,0,5,10,15); quarterRound(ws,1,6,11,12);
        quarterRound(ws,2,7,8,13); quarterRound(ws,3,4,9,14);
      }
      var out = new Uint8Array(64);
      var dv = new DataView(out.buffer);
      for (var i = 0; i < 16; i++) dv.setInt32(i * 4, (ws[i] + s[i]) | 0, true);
      return out;
    }
    function encrypt(key, nonce, counter, data) {
      var out = new Uint8Array(data.length);
      var blocks = Math.ceil(data.length / 64);
      for (var i = 0; i < blocks; i++) {
        var ks = chacha20Block(key, counter + i, nonce);
        var off = i * 64;
        var len = Math.min(64, data.length - off);
        for (var j = 0; j < len; j++) out[off + j] = data[off + j] ^ ks[j];
      }
      return out;
    }
    return { block: chacha20Block, encrypt: encrypt };
  })();

  var Poly1305 = (function() {
    function mac(key, data) {
      var r = 0n, s = 0n;
      for (var i = 15; i >= 0; i--) r = (r << 8n) | BigInt(key[i]);
      for (var i = 15; i >= 0; i--) s = (s << 8n) | BigInt(key[16 + i]);
      r &= 0x0ffffffc0ffffffc0ffffffc0fffffffn;
      var p = (1n << 130n) - 5n;
      var acc = 0n;
      for (var i = 0; i < data.length; i += 16) {
        var chunk = Math.min(16, data.length - i);
        var n = 0n;
        for (var j = chunk - 1; j >= 0; j--) n = (n << 8n) | BigInt(data[i + j]);
        n |= (1n << BigInt(chunk * 8));
        acc = ((acc + n) * r) % p;
      }
      acc = acc + s;
      var tag = new Uint8Array(16);
      for (var i = 0; i < 16; i++) { tag[i] = Number(acc & 0xffn); acc >>= 8n; }
      return tag;
    }
    return { mac: mac };
  })();

  var AEAD = (function() {
    function pad16(len) { var r = len % 16; return r === 0 ? new Uint8Array(0) : new Uint8Array(16 - r); }
    function leU64(n) {
      var b = new Uint8Array(8);
      b[0] = n & 0xff; b[1] = (n >> 8) & 0xff; b[2] = (n >> 16) & 0xff; b[3] = (n >> 24) & 0xff;
      return b;
    }
    function seal(key, nonce, plaintext, aad) {
      var polyKey = ChaCha20.block(key, 0, nonce).subarray(0, 32);
      var ct = ChaCha20.encrypt(key, nonce, 1, plaintext);
      var aadBytes = aad || new Uint8Array(0);
      var macData = concatBytes([
        aadBytes, pad16(aadBytes.length),
        ct, pad16(ct.length),
        leU64(aadBytes.length), leU64(ct.length)
      ]);
      var tag = Poly1305.mac(polyKey, macData);
      return concatBytes([ct, tag]);
    }
    function open(key, nonce, blob, aad) {
      if (blob.length < 16) throw new Error("Ciphertext too short");
      var ct = blob.subarray(0, blob.length - 16);
      var tag = blob.subarray(blob.length - 16);
      var polyKey = ChaCha20.block(key, 0, nonce).subarray(0, 32);
      var aadBytes = aad || new Uint8Array(0);
      var macData = concatBytes([
        aadBytes, pad16(aadBytes.length),
        ct, pad16(ct.length),
        leU64(aadBytes.length), leU64(ct.length)
      ]);
      var computed = Poly1305.mac(polyKey, macData);
      var diff = 0;
      for (var i = 0; i < 16; i++) diff |= tag[i] ^ computed[i];
      if (diff !== 0) throw new Error("Authentication failed");
      return ChaCha20.encrypt(key, nonce, 1, ct);
    }
    return { seal: seal, open: open };
  })();

  // ══════════════════════════════════════════════════════════════
  // Utilities & Base32
  // ══════════════════════════════════════════════════════════════
  function concatBytes(arrays) {
    var total = 0;
    for (var i = 0; i < arrays.length; i++) total += arrays[i].length;
    var result = new Uint8Array(total);
    var offset = 0;
    for (var i = 0; i < arrays.length; i++) { result.set(arrays[i], offset); offset += arrays[i].length; }
    return result;
  }

  function hexToBytes(hex) {
    if (hex.length % 2 !== 0) throw new Error("Invalid hex");
    var b = new Uint8Array(hex.length / 2);
    for (var i = 0; i < b.length; i++) b[i] = parseInt(hex.substr(i * 2, 2), 16);
    return b;
  }

  function bytesToHex(bytes) {
    var h = "";
    for (var i = 0; i < bytes.length; i++) h += ("0" + bytes[i].toString(16)).slice(-2);
    return h;
  }

  function textEncode(s) { return new TextEncoder().encode(s); }
  function textDecode(b) { return new TextDecoder().decode(b); }

  var Base32 = (function() {
    var ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";
    var DECODE_MAP = {};
    for (var i = 0; i < 32; i++) {
      DECODE_MAP[ALPHABET[i]] = i;
      DECODE_MAP[ALPHABET[i].toUpperCase()] = i;
    }
    function encode(data) {
      if (!data.length) return "";
      var bits = 0, val = 0, out = "";
      for (var i = 0; i < data.length; i++) {
        val = (val << 8) | data[i];
        bits += 8;
        while (bits >= 5) {
          bits -= 5;
          out += ALPHABET[(val >>> bits) & 31];
        }
      }
      if (bits > 0) out += ALPHABET[(val << (5 - bits)) & 31];
      return out;
    }
    function decode(s) {
      if (!s) return new Uint8Array(0);
      s = s.replace(/=+$/, "");
      var bits = 0, val = 0, bytes = [];
      for (var i = 0; i < s.length; i++) {
        var c = DECODE_MAP[s[i]];
        if (c === undefined) throw new Error("Invalid base32 char: " + s[i]);
        val = (val << 5) | c;
        bits += 5;
        if (bits >= 8) {
          bits -= 8;
          bytes.push((val >>> bits) & 0xff);
        }
      }
      return new Uint8Array(bytes);
    }
    return { encode: encode, decode: decode };
  })();

  // ══════════════════════════════════════════════════════════════
  // Protocol Header (8B) & DNS Carrier
  // ══════════════════════════════════════════════════════════════
  var Flags = { SYN: 0x80, FIN: 0x40, ACK: 0x20, DATA: 0x10, POLL: 0x08, FRAG: 0x04, CFG: 0x02, COMP: 0x01 };
  var HEADER_SIZE = 8;

  var Header = {
    pack: function(flags, streamId, sequence, fragIndex, totalFrags, reserved) {
      var b = new Uint8Array(8);
      var dv = new DataView(b.buffer);
      dv.setUint8(0, flags & 0xff);
      dv.setUint16(1, streamId & 0xffff, false);
      dv.setUint16(3, sequence & 0xffff, false);
      dv.setUint8(5, (fragIndex || 0) & 0xff);
      dv.setUint8(6, (totalFrags || 1) & 0xff);
      dv.setUint8(7, (reserved || 0) & 0xff);
      return b;
    },
    unpack: function(data) {
      if (data.length < 8) throw new Error("Header too short");
      var dv = new DataView(data.buffer, data.byteOffset, 8);
      return {
        flags: dv.getUint8(0),
        streamId: dv.getUint16(1, false),
        sequence: dv.getUint16(3, false),
        fragIndex: dv.getUint8(5),
        totalFrags: dv.getUint8(6),
        reserved: dv.getUint8(7)
      };
    }
  };

  var MAX_LABEL = 63;
  var MAX_FQDN = 253;

  var Carrier = {
    domain: "",
    init: function(domain) { this.domain = domain; },
    packQuery: function(data, sessionTag) {
      var encoded = Base32.encode(data);
      var labels = [];
      for (var i = 0; i < encoded.length; i += MAX_LABEL)
        labels.push(encoded.substring(i, i + MAX_LABEL));
      var fqdn = labels.join(".") + "." + sessionTag + "." + this.domain;
      if (fqdn.length > MAX_FQDN) throw new Error("FQDN too long: " + fqdn.length);
      return fqdn;
    },
    unpackResponse: function(txt) { return Base32.decode(txt); }
  };

  // ══════════════════════════════════════════════════════════════
  // CryptoState (Noise_NK pattern: `es` + `ee`)
  // ══════════════════════════════════════════════════════════════
  var NONCE_SIZE = 12;
  var TAG_SIZE = 16;
  var KEY_SIZE = 32;
  var OVERHEAD = NONCE_SIZE + TAG_SIZE;
  var SYN_SIZE = KEY_SIZE + 8 + TAG_SIZE;    // 56B
  var SYNACK_SIZE = KEY_SIZE + TAG_SIZE;     // 48B
  var ZERO_NONCE = new Uint8Array(NONCE_SIZE);
  var SYN_AAD = textEncode("kopacz-v3-syn");
  var SYNACK_AAD_PREFIX = textEncode("kopacz-v3-synack:");
  var INFO_SYN = textEncode("kopacz-v3-syn");
  var INFO_SESSION = textEncode("kopacz-v3");

  function CryptoState(serverPub) {
    if (!serverPub || serverPub.length !== KEY_SIZE) {
      throw new Error("Server public key must be 32 bytes");
    }
    this._serverPub = serverPub;
    this._sendCtr = 0;
    this._maxRecvCtr = -1;
    this._recvBitmap = 0n;
    this._ephSecret = null;
    this._localPub = null;
    this._es = null;
    this.keys = null; // { clientToServer, serverToClient }
  }

  CryptoState.prototype.established = function() { return this.keys !== null; };

  CryptoState.prototype.clientHello = function() {
    var kp = nacl.generateKeyPair();
    this._ephSecret = kp.secretKey;
    this._localPub = kp.publicKey;
    this._es = nacl.sharedKey(this._ephSecret, this._serverPub);
    var nonZero = 0;
    for (var i = 0; i < KEY_SIZE; i++) nonZero |= this._es[i];
    if (nonZero === 0) throw new Error("Low-order server public key rejected");

    var synSalt = concatBytes([this._localPub, this._serverPub]);
    var synKey = SHA256.hkdf(this._es, synSalt, INFO_SYN, KEY_SIZE);

    var ts = Math.floor(Date.now() / 1000);
    var tsBytes = new Uint8Array(8);
    var dv = new DataView(tsBytes.buffer);
    dv.setUint32(0, Math.floor(ts / 4294967296), false);
    dv.setUint32(4, ts >>> 0, false);

    var aad = concatBytes([SYN_AAD, this._localPub]);
    var sealedTs = AEAD.seal(synKey, ZERO_NONCE, tsBytes, aad);
    return concatBytes([this._localPub, sealedTs]); // 56 bytes
  };

  CryptoState.prototype.clientFinish = async function(synackPayload) {
    if (!this._ephSecret || !this._localPub || !this._es) {
      throw new Error("Handshake not initiated");
    }
    if (!synackPayload || synackPayload.length !== SYNACK_SIZE) {
      throw new Error("Bad SYN-ACK length");
    }
    var sEphPub = synackPayload.subarray(0, KEY_SIZE);
    var tag = synackPayload.subarray(KEY_SIZE);

    var sameLocal = 0, sameStatic = 0;
    for (var i = 0; i < KEY_SIZE; i++) {
      sameLocal |= (sEphPub[i] ^ this._localPub[i]);
      sameStatic |= (sEphPub[i] ^ this._serverPub[i]);
    }
    if (sameLocal === 0 || sameStatic === 0) throw new Error("Reflected public key rejected");

    var ee = nacl.sharedKey(this._ephSecret, sEphPub);
    var nonZero = 0;
    for (var j = 0; j < KEY_SIZE; j++) nonZero |= ee[j];
    if (nonZero === 0) throw new Error("Low-order ephemeral public key rejected");

    var ikm = concatBytes([this._es, ee]);
    var salt = concatBytes([this._localPub, sEphPub]);
    var material = SHA256.hkdf(ikm, salt, INFO_SESSION, KEY_SIZE * 3);
    var synackKey = material.subarray(KEY_SIZE * 2, KEY_SIZE * 3);
    var synackAad = concatBytes([SYNACK_AAD_PREFIX, this._localPub, sEphPub]);

    AEAD.open(synackKey, ZERO_NONCE, tag, synackAad);

    this.keys = {
      clientToServer: material.subarray(0, KEY_SIZE),
      serverToClient: material.subarray(KEY_SIZE, KEY_SIZE * 2)
    };
    this._ephSecret = null;
    this._localPub = null;
    this._es = null;
  };

  CryptoState.prototype.encrypt = function(plaintext, aad) {
    if (!this.keys) throw new Error("Not established");
    var nonce = new Uint8Array(NONCE_SIZE);
    var ctr = this._sendCtr;
    for (var i = NONCE_SIZE - 1; i >= 0 && ctr > 0; i--) {
      nonce[i] = ctr & 0xff;
      ctr = Math.floor(ctr / 256);
    }
    this._sendCtr++;
    var sealed = AEAD.seal(this.keys.clientToServer, nonce, plaintext, aad);
    return concatBytes([nonce, sealed]);
  };

  CryptoState.prototype.decrypt = function(blob, aad) {
    if (!this.keys) throw new Error("Not established");
    if (blob.length < OVERHEAD) throw new Error("Blob too short");
    var nonce = blob.subarray(0, NONCE_SIZE);
    var ctr = 0;
    for (var i = 0; i < NONCE_SIZE; i++) ctr = ctr * 256 + nonce[i];
    if (this._maxRecvCtr >= 0) {
      if (ctr <= this._maxRecvCtr) {
        var diff = this._maxRecvCtr - ctr;
        if (diff >= 64) throw new Error("Expired packet nonce");
        if ((this._recvBitmap & (1n << BigInt(diff))) !== 0n) throw new Error("Replayed packet nonce");
      }
    }
    var pt = AEAD.open(this.keys.serverToClient, nonce, blob.subarray(NONCE_SIZE), aad);
    if (this._maxRecvCtr < 0) {
      this._maxRecvCtr = ctr;
      this._recvBitmap = 1n;
    } else if (ctr > this._maxRecvCtr) {
      var shift = ctr - this._maxRecvCtr;
      this._recvBitmap = shift >= 64 ? 1n : (((this._recvBitmap << BigInt(shift)) | 1n) & ((1n << 64n) - 1n));
      this._maxRecvCtr = ctr;
    } else {
      this._recvBitmap |= (1n << BigInt(this._maxRecvCtr - ctr));
    }
    return pt;
  };

  CryptoState.prototype.signControl = function(headerBytes) {
    if (!this.keys || headerBytes.length !== 8) throw new Error("Cannot sign control");
    var nonce = concatBytes([textEncode("ctrl"), headerBytes]);
    return AEAD.seal(this.keys.clientToServer, nonce, new Uint8Array(0), headerBytes).subarray(0, 8);
  };

  CryptoState.prototype.verifyControl = function(headerBytes, tagBytes) {
    if (!this.keys || headerBytes.length !== 8 || !tagBytes || tagBytes.length !== 8) return false;
    var nonce = concatBytes([textEncode("ctrl"), headerBytes]);
    var expected = AEAD.seal(this.keys.serverToClient, nonce, new Uint8Array(0), headerBytes).subarray(0, 8);
    var diff = 0;
    for (var i = 0; i < 8; i++) diff |= (expected[i] ^ tagBytes[i]);
    return diff === 0;
  };

  // ══════════════════════════════════════════════════════════════
  // LZ4 Frame Decompressor + Store Compressor
  // ══════════════════════════════════════════════════════════════
  var LZ4 = (function() {
    var MAX_DECOMPRESSED_SIZE = 65536;

    function decompress(src, maxSize) {
      if (!src || src.length === 0) return src;
      var limit = maxSize || MAX_DECOMPRESSED_SIZE;
      var dv = new DataView(src.buffer, src.byteOffset, src.length);
      var pos = 0;
      var magic = dv.getUint32(pos, true); pos += 4;
      if (magic !== 0x184D2204) throw new Error("Not LZ4 frame: 0x" + magic.toString(16));
      var flg = src[pos++];
      var bd = src[pos++];
      void bd;
      var blockChecksum = (flg >> 4) & 1;
      var contentSize = (flg >> 3) & 1;
      var dictId = (flg >> 0) & 1;
      if (contentSize) {
        var cLow = dv.getUint32(pos, true);
        var cHigh = dv.getUint32(pos + 4, true);
        if (cHigh > 0 || cLow > limit) throw new Error("LZ4 frame content size exceeds max_size");
        pos += 8;
      }
      if (dictId) pos += 4;
      pos++; // header checksum

      var output = [], totalOut = 0;
      while (pos < src.length) {
        if (pos + 4 > src.length) break;
        var blockSize = dv.getUint32(pos, true); pos += 4;
        if (blockSize === 0) break;
        var isUncompressed = (blockSize & 0x80000000) !== 0;
        blockSize &= 0x7FFFFFFF;
        if (pos + blockSize > src.length) throw new Error("Block overrun");
        if (isUncompressed) {
          if (totalOut + blockSize > limit) throw new Error("Decompressed data exceeds max_size");
          output.push(src.subarray(pos, pos + blockSize));
          totalOut += blockSize;
        } else {
          var decoded = decompressBlock(src, pos, blockSize, output, totalOut, limit - totalOut);
          output.push(decoded);
          totalOut += decoded.length;
        }
        pos += blockSize;
        if (blockChecksum) pos += 4;
      }
      var result = new Uint8Array(totalOut), off = 0;
      for (var i = 0; i < output.length; i++) { result.set(output[i], off); off += output[i].length; }
      return result;
    }

    function flattenOutput(parts, totalLen) {
      var result = new Uint8Array(totalLen), off = 0;
      for (var i = 0; i < parts.length; i++) { result.set(parts[i], off); off += parts[i].length; }
      return result;
    }

    function decompressBlock(src, srcOff, srcLen, prevOutputs, prevTotalLen, maxBlockOut) {
      var end = srcOff + srcLen, out = [], outLen = 0;
      while (srcOff < end) {
        var token = src[srcOff++];
        var litLen = (token >> 4) & 0xf;
        if (litLen === 15) { var b; do { b = src[srcOff++]; litLen += b; } while (b === 255); }
        if (litLen > 0) {
          if (outLen + litLen > maxBlockOut) throw new Error("Decompressed block exceeds max_size");
          out.push(src.subarray(srcOff, srcOff + litLen));
          outLen += litLen;
          srcOff += litLen;
        }
        if (srcOff >= end) break;
        var offset = src[srcOff] | (src[srcOff + 1] << 8);
        srcOff += 2;
        if (offset === 0 || offset > prevTotalLen + outLen) throw new Error("Invalid LZ4 offset");
        var matchLen = (token & 0xf) + 4;
        if (matchLen === 19) { var b2; do { b2 = src[srcOff++]; matchLen += b2; } while (b2 === 255); }
        if (outLen + matchLen > maxBlockOut) throw new Error("Decompressed block exceeds max_size");
        var matchStart = (prevTotalLen + outLen) - offset;
        if (matchStart >= prevTotalLen) {
          var localStart = matchStart - prevTotalLen;
          var tempFlat = flattenOutput(out, outLen);
          var chunk = new Uint8Array(matchLen);
          for (var i = 0; i < matchLen; i++) {
            var srcIdx = localStart + i;
            chunk[i] = srcIdx < tempFlat.length ? tempFlat[srcIdx] : chunk[srcIdx - tempFlat.length];
          }
          out.push(chunk);
          outLen += matchLen;
        } else {
          var allPrev = flattenOutput(prevOutputs, prevTotalLen);
          var flat = flattenOutput(out, outLen);
          var combined = concatBytes([allPrev, flat]);
          var chunk2 = new Uint8Array(matchLen);
          for (var j = 0; j < matchLen; j++) {
            var idx = matchStart + j;
            chunk2[j] = idx < combined.length ? combined[idx] : chunk2[idx - combined.length];
          }
          out.push(chunk2);
          outLen += matchLen;
        }
      }
      return flattenOutput(out, outLen);
    }

    function xxh32(data, seed) {
      var PRIME1 = 0x9E3779B1 | 0, PRIME2 = 0x85EBCA77 | 0, PRIME3 = 0xC2B2AE3D | 0;
      var PRIME4 = 0x27D4EB2F | 0, PRIME5 = 0x165667B1 | 0;
      var h = (seed + PRIME5 + data.length) | 0, i = 0;
      while (i + 4 <= data.length) {
        var k = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24);
        h = (h + Math.imul(k, PRIME3)) | 0;
        h = Math.imul(((h << 17) | (h >>> 15)), PRIME4);
        i += 4;
      }
      while (i < data.length) {
        h = (h + Math.imul(data[i], PRIME5)) | 0;
        h = Math.imul(((h << 11) | (h >>> 21)), PRIME1);
        i++;
      }
      h = Math.imul(h ^ (h >>> 15), PRIME2);
      h = Math.imul(h ^ (h >>> 13), PRIME3);
      return (h ^ (h >>> 16)) >>> 0;
    }

    function storeCompress(data) {
      if (!data || data.length === 0) return data;
      var magic = new Uint8Array([0x04, 0x22, 0x4D, 0x18]);
      var flg = 0x60, bd = 0x70;
      var hc = (xxh32(new Uint8Array([flg, bd]), 0) >>> 8) & 0xff;
      var header = new Uint8Array([flg, bd, hc]);
      var bs = new Uint8Array(4);
      new DataView(bs.buffer).setUint32(0, (data.length | 0x80000000) >>> 0, true);
      var endMark = new Uint8Array([0, 0, 0, 0]);
      return concatBytes([magic, header, bs, data, endMark]);
    }

    return { decompress: decompress, storeCompress: storeCompress };
  })();

  // ══════════════════════════════════════════════════════════════
  // Fragment / Reassembly / ARQ / Session
  // ══════════════════════════════════════════════════════════════
  function dataAad(streamId, sequence, isCompressed) {
    var b = new Uint8Array(5);
    var dv = new DataView(b.buffer);
    dv.setUint8(0, isCompressed ? 1 : 0);
    dv.setUint16(1, streamId & 0xffff, false);
    dv.setUint16(3, sequence & 0xffff, false);
    return b;
  }

  function fragmentData(data, streamId, sequence, maxPayload, extraFlags, reserved) {
    extraFlags = extraFlags || 0;
    reserved = reserved || 0;
    if (!data || data.length === 0) {
      return [Header.pack(Flags.DATA | extraFlags, streamId, sequence, 0, 1, reserved)];
    }
    var chunks = [];
    for (var i = 0; i < data.length; i += maxPayload) {
      chunks.push(data.subarray(i, Math.min(i + maxPayload, data.length)));
    }
    if (chunks.length > 255) throw new Error("Too many fragments: " + chunks.length);
    var baseFlags = Flags.DATA | extraFlags | (chunks.length > 1 ? Flags.FRAG : 0);
    var packets = [];
    for (var idx = 0; idx < chunks.length; idx++) {
      packets.push(concatBytes([
        Header.pack(baseFlags, streamId, sequence, idx, chunks.length, reserved),
        chunks[idx]
      ]));
    }
    return packets;
  }

  function ReassemblyBuffer(maxPending) {
    this._frags = {};
    this._maxPending = maxPending || 256;
    this._pendingOrder = [];
  }
  ReassemblyBuffer.MAX_REASSEMBLED_SIZE = 65536;
  ReassemblyBuffer.prototype.add = function(hdr, payload) {
    if (hdr.totalFrags < 1 || hdr.fragIndex >= hdr.totalFrags) throw new Error("Invalid fragment header");
    if (payload.length > ReassemblyBuffer.MAX_REASSEMBLED_SIZE) throw new Error("Fragment exceeds max size");
    var key = hdr.streamId + ":" + hdr.sequence;
    if (this._frags[key] && this._frags[key].total !== hdr.totalFrags) {
      delete this._frags[key];
      var sIdx = this._pendingOrder.indexOf(key);
      if (sIdx !== -1) this._pendingOrder.splice(sIdx, 1);
    }
    if (!this._frags[key]) {
      if (this._pendingOrder.length >= this._maxPending) {
        var oldest = this._pendingOrder.shift();
        delete this._frags[oldest];
      }
      this._frags[key] = { parts: {}, total: hdr.totalFrags, bytes: 0 };
      this._pendingOrder.push(key);
    }
    var entry = this._frags[key];
    var prevLen = entry.parts[hdr.fragIndex] ? entry.parts[hdr.fragIndex].length : 0;
    if (entry.bytes - prevLen + payload.length > ReassemblyBuffer.MAX_REASSEMBLED_SIZE) {
      delete this._frags[key];
      var idx = this._pendingOrder.indexOf(key);
      if (idx !== -1) this._pendingOrder.splice(idx, 1);
      throw new Error("Reassembled message exceeds max size");
    }
    entry.bytes = entry.bytes - prevLen + payload.length;
    entry.parts[hdr.fragIndex] = payload;
    if (Object.keys(entry.parts).length === entry.total) {
      delete this._frags[key];
      var rIdx = this._pendingOrder.indexOf(key);
      if (rIdx !== -1) this._pendingOrder.splice(rIdx, 1);
      var result = [];
      for (var i = 0; i < entry.total; i++) result.push(entry.parts[i]);
      return concatBytes(result);
    }
    return null;
  };

  function seqLe(a, b) { return a === b || ((b - a) & 0xFFFF) < 0x8000; }

  function SendWindow(cwnd, rto) {
    this.cwnd = cwnd || 10;
    this.rto = rto || 500;
    this._entries = {};
    this._count = 0;
  }
  SendWindow.prototype.track = function(seq, packets) {
    this._entries[seq] = { seq: seq, packets: packets, sentAt: Date.now(), retries: 0 };
    this._count++;
  };
  SendWindow.prototype.ack = function(ackSeq) {
    var removed = 0;
    for (var s in this._entries) {
      if (seqLe(parseInt(s), ackSeq)) { delete this._entries[s]; this._count--; removed++; }
    }
    return removed;
  };
  SendWindow.prototype.ackLow8 = function(low8) {
    var matches = [];
    for (var s in this._entries) {
      var sn = parseInt(s);
      if ((sn & 0xff) === (low8 & 0xff)) matches.push(sn);
    }
    if (!matches.length) return 0;
    var target = matches[0];
    for (var i = 1; i < matches.length; i++) if (seqLe(target, matches[i])) target = matches[i];
    return this.ack(target);
  };
  SendWindow.prototype.full = function() { return this._count >= this.cwnd; };

  function RecvWindow(maxOoo) {
    this._ooo = new Set();
    this._oooData = {};
    this._readyData = [];
    this._nextExpected = 0;
    this._hasContiguous = false;
    this._maxOoo = maxOoo || 128;
  }
  RecvWindow.prototype.isDuplicate = function(seq) {
    if (this._hasContiguous && seqLe(seq, (this._nextExpected - 1) & 0xFFFF)) return true;
    return this._ooo.has(seq);
  };
  RecvWindow.prototype.record = function(seq, data) {
    if (this.isDuplicate(seq)) return false;
    if (seq !== this._nextExpected) {
      var dist = (seq - this._nextExpected) & 0xFFFF;
      if (dist >= this._maxOoo || this._ooo.size >= this._maxOoo) return false;
    }
    this._ooo.add(seq);
    if (data !== undefined && data !== null) this._oooData[seq] = data;
    while (this._ooo.has(this._nextExpected)) {
      this._ooo.delete(this._nextExpected);
      if (this._oooData[this._nextExpected] !== undefined) {
        this._readyData.push(this._oooData[this._nextExpected]);
        delete this._oooData[this._nextExpected];
      }
      this._nextExpected = (this._nextExpected + 1) & 0xFFFF;
      this._hasContiguous = true;
    }
    return true;
  };
  RecvWindow.prototype.popReady = function() {
    if (!this._readyData.length) return [];
    var out = this._readyData.slice();
    this._readyData.length = 0;
    return out;
  };
  RecvWindow.prototype.ackNumber = function() {
    if (!this._hasContiguous) return null;
    return (this._nextExpected - 1) & 0xFFFF;
  };

  var SessionState = { IDLE: 0, HANDSHAKE_SENT: 1, ESTABLISHED: 2, CLOSED: 3 };

  function Session(serverPub, maxFragPayload) {
    this.crypto = new CryptoState(serverPub);
    this.state = SessionState.IDLE;
    this._seq = 0;
    this._pollSeq = 0;
    this._streamId = 0;
    this._maxFrag = maxFragPayload || 100;
    this._reassembly = new ReassemblyBuffer();
    this._sendWindow = new SendWindow(10, 500);
    this._recvWindow = new RecvWindow();
    this._pendingReady = [];
  }
  Session.prototype._nextSeq = function() { var s = this._seq; this._seq = (this._seq + 1) & 0xFFFF; return s; };
  Session.prototype._nextPollSeq = function() { var s = this._pollSeq; this._pollSeq = (this._pollSeq + 1) & 0xFFFF; return s; };
  Session.prototype.initiate = function(downMtu) {
    var payload = this.crypto.clientHello();
    var rsv = downMtu ? Math.min(128, Math.max(4, Math.floor(downMtu / 8))) : 60;
    var hdr = Header.pack(Flags.SYN, this._streamId, 0, 0, 1, rsv);
    this.state = SessionState.HANDSHAKE_SENT;
    this.peerHasMore = false;
    this.peerPendingFrags = 0;
    return [concatBytes([hdr, payload])];
  };
  Session.prototype.handlePacket = async function(raw) {
    if (raw.length < HEADER_SIZE) return null;
    var hdr = Header.unpack(raw);
    var hdrBytes = raw.subarray(0, HEADER_SIZE);
    var payload = raw.subarray(HEADER_SIZE);

    if ((hdr.flags & Flags.SYN) && (hdr.flags & Flags.FIN)) return null;
    if ((hdr.flags & (Flags.SYN | Flags.FIN)) && (hdr.flags & Flags.DATA)) return null;

    if ((hdr.flags & Flags.SYN) && (hdr.flags & Flags.ACK)) {
      if (this.state !== SessionState.HANDSHAKE_SENT) return null;
      if (hdr.fragIndex !== 0 || hdr.totalFrags !== 1) return null;
      await this.crypto.clientFinish(payload);
      this.state = SessionState.ESTABLISHED;
      return null;
    }

    if ((hdr.flags & Flags.DATA) && this.state === SessionState.ESTABLISHED) {
      this.peerHasMore = (hdr.flags & Flags.CFG) !== 0;
      if (this._recvWindow.isDuplicate(hdr.sequence)) return null;
      var encrypted = this._reassembly.add(hdr, payload);
      if (encrypted === null) {
        this.peerPendingFrags = Math.max(0, hdr.totalFrags - hdr.fragIndex - 1);
        return null;
      }
      this.peerPendingFrags = 0;
      var isComp = (hdr.flags & Flags.COMP) !== 0;
      var aad = dataAad(hdr.streamId, hdr.sequence, isComp);
      var decrypted = this.crypto.decrypt(encrypted, aad);
      if (hdr.flags & Flags.ACK) this._sendWindow.ackLow8(hdr.reserved);
      var data = isComp ? LZ4.decompress(decrypted) : decrypted;
      if (!this._recvWindow.record(hdr.sequence, data)) return null;
      var ready = this._recvWindow.popReady();
      if (!ready.length) return null;
      for (var i = 1; i < ready.length; i++) this._pendingReady.push(ready[i]);
      return ready[0];
    }

    if (this.state === SessionState.ESTABLISHED && this.crypto.established()) {
      var altHdr = new Uint8Array(hdrBytes);
      altHdr[0] &= ~Flags.CFG;
      if (!this.crypto.verifyControl(hdrBytes, payload) && !this.crypto.verifyControl(altHdr, payload)) return null;
      this.peerHasMore = (hdr.flags & Flags.CFG) !== 0;
      if (hdr.flags & Flags.ACK) {
        this._sendWindow.ack(hdr.sequence);
        this.peerPendingFrags = 0;
        if (!(hdr.flags & Flags.FIN)) return null;
      }
      if (hdr.flags & Flags.FIN) {
        this.state = SessionState.CLOSED;
        return null;
      }
    }
    return null;
  };

  Session.prototype.send = function(data) {
    if (this.state !== SessionState.ESTABLISHED) throw new Error("Not established");
    var seq = this._nextSeq();
    var aad = dataAad(this._streamId, seq, false);
    var encrypted = this.crypto.encrypt(data, aad);
    var ackNum = this._recvWindow.ackNumber();
    var extraFlags = ackNum !== null ? Flags.ACK : 0;
    var reserved = ackNum !== null ? (ackNum & 0xff) : 0;
    var pkts = fragmentData(encrypted, this._streamId, seq, this._maxFrag, extraFlags, reserved);
    this._sendWindow.track(seq, pkts);
    return pkts;
  };

  Session.prototype.makeAck = function() {
    var ackNum = this._recvWindow.ackNumber();
    if (ackNum === null) return null;
    var hdr = Header.pack(Flags.ACK, this._streamId, ackNum);
    return this.crypto.established() ? concatBytes([hdr, this.crypto.signControl(hdr)]) : hdr;
  };

  Session.prototype.makePoll = function() {
    var pollSeq = this._nextPollSeq();
    var ackNum = this._recvWindow.ackNumber();
    var hdr = ackNum !== null
      ? Header.pack(Flags.POLL | Flags.ACK, this._streamId, ackNum, (pollSeq >> 8) & 0xff, 1, pollSeq & 0xff)
      : Header.pack(Flags.POLL, this._streamId, pollSeq);
    return this.crypto.established() ? concatBytes([hdr, this.crypto.signControl(hdr)]) : hdr;
  };

  Session.prototype.makeFin = function() {
    var pollSeq = this._nextPollSeq();
    this.state = SessionState.CLOSED;
    var hdr = Header.pack(Flags.FIN, this._streamId, pollSeq);
    return this.crypto.established() ? concatBytes([hdr, this.crypto.signControl(hdr)]) : hdr;
  };

  Session.prototype.drainReceived = function() {
    if (!this._pendingReady.length) return [];
    var out = this._pendingReady.slice();
    this._pendingReady.length = 0;
    return out;
  };

  // ══════════════════════════════════════════════════════════════
  // Resolvers: DoHResolver (Browser/Fetch) & UDPResolver (Node dgram)
  // ══════════════════════════════════════════════════════════════
  var DOH_PROVIDERS = {
    google: "https://dns.google/resolve",
    cloudflare: "https://cloudflare-dns.com/dns-query",
    quad9: "https://dns.quad9.net:5053/dns-query"
  };

  function DoHResolver(providerList, customUrl, onError) {
    this.providers = (providerList && providerList.length) ? providerList : ["cloudflare"];
    this.customUrl = customUrl || "";
    this._idx = 0;
    this._queryCount = 0;
    this._timeout = 5000;
    this._onError = onError || null;
  }

  DoHResolver.prototype.query = async function(qname) {
    var maxRetries = this.providers.length;
    for (var attempt = 0; attempt < maxRetries; attempt++) {
      var providerIdx = (this._idx + attempt) % this.providers.length;
      var provider = this.providers[providerIdx];
      var url = provider === "custom" ? this.customUrl : DOH_PROVIDERS[provider];
      if (!url) continue;
      try {
        var result = await this._doQuery(url, qname);
        this._idx = providerIdx;
        this._queryCount++;
        return result;
      } catch (e) {
        if (this._onError) this._onError("DoH " + provider + " failed: " + e.message);
      }
    }
    return null;
  };

  DoHResolver.prototype._doQuery = async function(url, qname) {
    var controller = new AbortController();
    var timeoutId = setTimeout(function() { controller.abort(); }, this._timeout);
    try {
      var fetchUrl = url + "?name=" + encodeURIComponent(qname) + "&type=TXT";
      var resp = await fetch(fetchUrl, {
        signal: controller.signal,
        headers: { "Accept": "application/dns-json" }
      });
      if (!resp.ok) throw new Error("HTTP " + resp.status);
      var json = await resp.json();
      if (json.Answer) {
        for (var i = 0; i < json.Answer.length; i++) {
          if (json.Answer[i].type === 16) {
            return (json.Answer[i].data || "").replace(/["\s]+/g, "");
          }
        }
      }
      return null;
    } finally {
      clearTimeout(timeoutId);
    }
  };

  function UDPResolver(host, port, timeoutMs) {
    this.host = host || "127.0.0.1";
    this.port = port || 53;
    this.timeoutMs = timeoutMs || 3000;
    this._queryCount = 0;
  }

  UDPResolver.prototype.query = function(qname) {
    var self = this;
    var dgram = require("dgram");
    return new Promise(function(resolve) {
      var sock = dgram.createSocket("udp4");
      var txid = randomBytes(new Uint8Array(2));
      var parts = qname.split(".");
      var qlen = 12 + 1 + 4;
      for (var i = 0; i < parts.length; i++) if (parts[i]) qlen += 1 + parts[i].length;
      var pkt = Buffer.alloc(qlen + 11);
      pkt[0] = txid[0]; pkt[1] = txid[1];
      pkt[2] = 0x01; pkt[3] = 0x00;
      pkt[5] = 0x01; // QDCOUNT=1
      pkt[11] = 0x01; // ARCOUNT=1 (EDNS0)
      var off = 12;
      for (var p = 0; p < parts.length; p++) {
        if (!parts[p]) continue;
        pkt[off++] = parts[p].length;
        pkt.write(parts[p], off, "ascii");
        off += parts[p].length;
      }
      pkt[off++] = 0;
      pkt.writeUInt16BE(16, off); off += 2; // QTYPE=TXT
      pkt.writeUInt16BE(1, off); off += 2;  // QCLASS=IN
      // EDNS0 OPT RR (4096B UDP payload)
      pkt[off++] = 0;
      pkt.writeUInt16BE(41, off); off += 2;
      pkt.writeUInt16BE(4096, off); off += 2;
      pkt.writeUInt32BE(0, off); off += 4;
      pkt.writeUInt16BE(0, off); off += 2;

      var timer = setTimeout(function() {
        try { sock.close(); } catch (_) {}
        resolve(null);
      }, self.timeoutMs);

      sock.once("message", function(msg) {
        clearTimeout(timer);
        try { sock.close(); } catch (_) {}
        self._queryCount++;
        if (msg.length < 12 || msg[0] !== txid[0] || msg[1] !== txid[1]) return resolve("");
        var qd = msg.readUInt16BE(4), an = msg.readUInt16BE(6);
        if (an === 0) return resolve("");
        var roff = 12;
        for (var q = 0; q < qd && roff < msg.length; q++) {
          while (roff < msg.length && msg[roff] !== 0) {
            if ((msg[roff] & 0xc0) === 0xc0) { roff += 2; break; }
            roff += 1 + msg[roff];
          }
          if (roff < msg.length && msg[roff] === 0) roff++;
          roff += 4;
        }
        for (var a = 0; a < an && roff < msg.length; a++) {
          while (roff < msg.length && msg[roff] !== 0) {
            if ((msg[roff] & 0xc0) === 0xc0) { roff += 2; break; }
            roff += 1 + msg[roff];
          }
          if (roff < msg.length && msg[roff] === 0) roff++;
          if (roff + 10 > msg.length) break;
          var rtype = msg.readUInt16BE(roff);
          var rdlen = msg.readUInt16BE(roff + 8);
          roff += 10;
          if (roff + rdlen > msg.length) break;
          if (rtype === 16) {
            var end = roff + rdlen, txt = "";
            while (roff < end) {
              var slen = msg[roff++];
              if (roff + slen > end) break;
              txt += msg.toString("ascii", roff, roff + slen);
              roff += slen;
            }
            return resolve(txt);
          }
          roff += rdlen;
        }
        resolve("");
      });
      sock.send(pkt, 0, off, self.port, self.host);
    });
  };

  // ══════════════════════════════════════════════════════════════
  // TunnelClient
  // ══════════════════════════════════════════════════════════════
  function randomTag(len) {
    var alpha = "0123456789abcdefghijklmnopqrstuvwxyz";
    var raw = randomBytes(new Uint8Array(len));
    var s = "";
    for (var i = 0; i < len; i++) s += alpha[raw[i] % 36];
    return s;
  }

  function TunnelClient(domain, serverPub, resolver, tag) {
    Carrier.init(domain);
    this.session = new Session(serverPub, 100);
    this.resolver = resolver;
    this.tag = tag || randomTag(8);
  }

  TunnelClient.prototype.connected = function() {
    return this.session.state === SessionState.ESTABLISHED;
  };

  TunnelClient.prototype._ingestRaw = async function(raw, outList) {
    var r = await this.session.handlePacket(raw);
    if (r !== null) outList.push(r);
    var extra = this.session.drainReceived();
    for (var i = 0; i < extra.length; i++) outList.push(extra[i]);
  };

  TunnelClient.prototype.connect = async function() {
    var synPkts = this.session.initiate();
    var qname = Carrier.packQuery(synPkts[0], this.tag);
    var txt = await this.resolver.query(qname);
    if (!txt) throw new Error("No response to SYN");
    var raw = Carrier.unpackResponse(txt);
    await this.session.handlePacket(raw);
    if (this.session.state !== SessionState.ESTABLISHED) throw new Error("Handshake failed");
  };

  TunnelClient.prototype.send = async function(data) {
    var pkts = this.session.send(data);
    var downstream = [];
    for (var i = 0; i < pkts.length; i++) {
      var qname = Carrier.packQuery(pkts[i], this.tag);
      var txt = await this.resolver.query(qname);
      if (txt) {
        await this._ingestRaw(Carrier.unpackResponse(txt), downstream);
      }
    }
    return downstream;
  };

  TunnelClient.prototype.poll = async function() {
    var qname = Carrier.packQuery(this.session.makePoll(), this.tag);
    var txt = await this.resolver.query(qname);
    if (!txt) return null;
    return await this.session.handlePacket(Carrier.unpackResponse(txt));
  };

  TunnelClient.prototype.pollAll = async function(maxPolls, retryDelay, deadlineMs, shouldCancel) {
    maxPolls = maxPolls || 100;
    retryDelay = retryDelay || 0;
    var results = [], emptyCount = 0, gotData = false;
    var maxEmpty = retryDelay > 0 ? 50 : 0;
    var pollsSent = 0, self = this;

    while (pollsSent < maxPolls) {
      if (deadlineMs && Date.now() >= deadlineMs) break;
      if (shouldCancel && shouldCancel()) break;

      var pendingHint = this.session.peerPendingFrags || 0;
      if (this.session.peerHasMore && pendingHint < 2) pendingHint = 3;
      var batchSize = pendingHint > 1 ? Math.min(4, pendingHint, maxPolls - pollsSent) : 1;

      var qnames = [];
      for (var b = 0; b < batchSize; b++) {
        qnames.push(Carrier.packQuery(this.session.makePoll(), this.tag));
      }
      pollsSent += batchSize;

      var txts = await Promise.all(qnames.map(function(q) { return self.resolver.query(q); }));
      if (deadlineMs && Date.now() >= deadlineMs) break;
      if (shouldCancel && shouldCancel()) break;

      var batchGotData = false, resolverFailed = false;
      for (var t = 0; t < txts.length; t++) {
        var txt = txts[t];
        if (txt === null) { resolverFailed = true; break; }
        if (!txt || txt === "") continue;
        var raw = Carrier.unpackResponse(txt);
        if (raw.length >= HEADER_SIZE) {
          var hdr = Header.unpack(raw);
          if ((hdr.flags & Flags.ACK) && !(hdr.flags & Flags.DATA)) {
            await this._ingestRaw(raw, results);
            continue;
          }
        }
        batchGotData = true;
        await this._ingestRaw(raw, results);
      }

      if (resolverFailed) break;
      if (!batchGotData) {
        var limit = gotData ? 2 : maxEmpty;
        if (retryDelay > 0 && emptyCount < limit) {
          emptyCount++;
          await new Promise(function(r) { setTimeout(r, retryDelay); });
          continue;
        }
        break;
      }
      emptyCount = 0;
      gotData = true;
    }
    return results;
  };

  TunnelClient.prototype.close = async function() {
    if (this.session.state !== SessionState.ESTABLISHED) return;
    var fin = this.session.makeFin();
    var qname = Carrier.packQuery(fin, this.tag);
    await this.resolver.query(qname);
  };

  // ══════════════════════════════════════════════════════════════
  // Node.js CLI Entrypoint (fetch / echo / keygen)
  // ══════════════════════════════════════════════════════════════
  if (typeof require === "function" && typeof module === "object" && require.main === module) {
    (async function() {
      var argv = process.argv.slice(2);
      var domain = process.env.KOPACZ_DOMAIN || "";
      var pubHex = process.env.KOPACZ_PUBKEY || process.env.KOPACZ_PSK || "";
      var resolverSpec = process.env.KOPACZ_RESOLVER || "1.1.1.1:53";
      var tag = "";
      var i = 0;
      while (i < argv.length && argv[i][0] === "-") {
        if ((argv[i] === "-d" || argv[i] === "--domain") && i + 1 < argv.length) domain = argv[++i];
        else if ((argv[i] === "-k" || argv[i] === "--pubkey" || argv[i] === "--psk") && i + 1 < argv.length) pubHex = argv[++i];
        else if ((argv[i] === "-r" || argv[i] === "--resolver") && i + 1 < argv.length) resolverSpec = argv[++i];
        else if ((argv[i] === "-t" || argv[i] === "--tag") && i + 1 < argv.length) tag = argv[++i];
        else break;
        i++;
      }
      var cmd = argv[i++];
      if (cmd === "keygen") {
        var kp = nacl.generateKeyPair();
        process.stdout.write("KOPACZ_PRIVKEY=" + bytesToHex(kp.secretKey) + "\n");
        process.stdout.write("KOPACZ_PUBKEY=" + bytesToHex(kp.publicKey) + "\n");
        process.exit(0);
      }
      if (!domain || !pubHex || pubHex.length !== 64 || !cmd) {
        process.stderr.write("Usage: node kopacz.js -d <domain> -k <64-hex-pubkey> [-r host:port] <fetch <url> | echo | keygen>\n");
        process.exit(1);
      }
      var parts = resolverSpec.split(":");
      var resolver = new UDPResolver(parts[0], parts[1] ? parseInt(parts[1], 10) : 53, 4000);
      var client = new TunnelClient(domain, hexToBytes(pubHex), resolver, tag);
      await client.connect();

      if (cmd === "echo") {
        var chunks = [];
        for await (var chunk of process.stdin) chunks.push(chunk);
        var input = new Uint8Array(Buffer.concat(chunks));
        for (var off = 0; off < input.length; off += 4096) {
          var slice = input.subarray(off, Math.min(off + 4096, input.length));
          var down = await client.send(slice);
          var got = 0;
          for (var d = 0; d < down.length; d++) {
            process.stdout.write(Buffer.from(down[d]));
            got += down[d].length;
          }
          while (got < slice.length) {
            var polled = await client.pollAll(32, 20);
            for (var p = 0; p < polled.length; p++) {
              process.stdout.write(Buffer.from(polled[p]));
              got += polled[p].length;
            }
          }
        }
      } else if (cmd === "fetch" && i < argv.length) {
        var urlBytes = textEncode(argv[i]);
        var req = concatBytes([new Uint8Array([0x04, 0x03]), urlBytes]);
        var msgs = await client.send(req);
        var done = false;
        function consume(list) {
          for (var m = 0; m < list.length; m++) {
            var msg = list[m];
            if (!msg || !msg.length) continue;
            if (msg[0] === 0x02 && msg.length > 1) process.stdout.write(Buffer.from(msg.subarray(1)));
            else if (msg[0] === 0x03) done = true;
          }
        }
        consume(msgs);
        while (!done) {
          var more = await client.pollAll(64, 50);
          consume(more);
          if (!more.length && !done) await new Promise(function(r) { setTimeout(r, 80); });
        }
      }
      await client.close();
      process.exit(0);
    })().catch(function(err) {
      process.stderr.write("Error: " + err.message + "\n");
      process.exit(1);
    });
  }

  return {
    nacl: nacl,
    SHA256: SHA256,
    ChaCha20: ChaCha20,
    Poly1305: Poly1305,
    AEAD: AEAD,
    Base32: Base32,
    Flags: Flags,
    HEADER_SIZE: HEADER_SIZE,
    Header: Header,
    Carrier: Carrier,
    NONCE_SIZE: NONCE_SIZE,
    TAG_SIZE: TAG_SIZE,
    KEY_SIZE: KEY_SIZE,
    OVERHEAD: OVERHEAD,
    SYN_SIZE: SYN_SIZE,
    SYNACK_SIZE: SYNACK_SIZE,
    SYN_AAD: SYN_AAD,
    SYNACK_AAD_PREFIX: SYNACK_AAD_PREFIX,
    CryptoState: CryptoState,
    LZ4: LZ4,
    dataAad: dataAad,
    fragmentData: fragmentData,
    ReassemblyBuffer: ReassemblyBuffer,
    SendWindow: SendWindow,
    RecvWindow: RecvWindow,
    SessionState: SessionState,
    Session: Session,
    DOH_PROVIDERS: DOH_PROVIDERS,
    DoHResolver: DoHResolver,
    UDPResolver: UDPResolver,
    TunnelClient: TunnelClient,
    concatBytes: concatBytes,
    hexToBytes: hexToBytes,
    bytesToHex: bytesToHex,
    textEncode: textEncode,
    textDecode: textDecode,
    randomTag: randomTag
  };
});
