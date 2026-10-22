/* 성적 입력 도우미 v1.4.5 - 나이스 교과평가·학기말종합의견 화면에서 실행 */
(function(){
var NGH_VER="1.4.5";var _h=document.getElementById("ngh-host");if(_h){var _t=(_h.shadowRoot&&_h.shadowRoot.querySelector(".hd")&&_h.shadowRoot.querySelector(".hd").innerText)||"";if(_t.indexOf("v"+NGH_VER)>=0){if(window.__ngh&&window.__ngh.wake){window.__ngh.wake();}else{_h.style.display="";}return;}_h.remove();window.__ngh=null;}
/* ===== core: bytes, crypto, CFB, ZIP, XLSX (no external libs) ===== */
var NGH = (function () {
  'use strict';
  var subtle = crypto.subtle;
  var te = new TextEncoder(), td = new TextDecoder('utf-8');

  // ---------- bytes ----------
  function concat(arrs) {
    var n = 0; arrs.forEach(function (a) { n += a.length; });
    var out = new Uint8Array(n), o = 0;
    arrs.forEach(function (a) { out.set(a, o); o += a.length; });
    return out;
  }
  function u32(v) { var b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, v >>> 0, true); return b; }
  function u64(v) { var b = new Uint8Array(8); var d = new DataView(b.buffer); d.setUint32(0, v >>> 0, true); d.setUint32(4, Math.floor(v / 4294967296), true); return b; }
  function hex(h) { var b = new Uint8Array(h.length / 2); for (var i = 0; i < b.length; i++) b[i] = parseInt(h.substr(i * 2, 2), 16); return b; }
  function b64d(s) { var bin = atob(s); var b = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i); return b; }
  function b64e(b) { var s = ''; for (var i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000)); return btoa(s); }
  function rand(n) { var b = new Uint8Array(n); crypto.getRandomValues(b); return b; }
  function utf16le(s) { var b = new Uint8Array(s.length * 2); for (var i = 0; i < s.length; i++) { var c = s.charCodeAt(i); b[i * 2] = c & 255; b[i * 2 + 1] = c >> 8; } return b; }
  function eq(a, b) { if (a.length !== b.length) return false; for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false; return true; }

  // ---------- crypto (ECMA-376 Agile) ----------
  async function sha(alg, data) { return new Uint8Array(await subtle.digest(alg, data)); }
  function fix(b, n, padByte) { if (b.length >= n) return b.slice(0, n); var o = new Uint8Array(n).fill(padByte); o.set(b); return o; }
  async function aesKey(raw) { return subtle.importKey('raw', raw, { name: 'AES-CBC' }, false, ['encrypt', 'decrypt']); }
  // AES-CBC without padding (WebCrypto always uses PKCS7, so work around it)
  async function aesDec(raw, iv, data) {
    var k = await aesKey(raw);
    var last = data.slice(data.length - 16);
    var padBlk = new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv: last }, k, new Uint8Array(0)));
    return new Uint8Array(await subtle.decrypt({ name: 'AES-CBC', iv: iv }, k, concat([data, padBlk])));
  }
  async function aesEnc(raw, iv, data) {
    var k = await aesKey(raw);
    var out = new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv: iv }, k, data));
    return out.slice(0, data.length); // data is block aligned → drop pure padding block
  }
  var BK = {
    verIn: hex('fea7d2763b4b9e79'), verVal: hex('d7aa0f6d3061344e'), key: hex('146e0be7abacd0d6'),
    hmacKey: hex('5fb2ad010cb9e1f6'), hmacVal: hex('a0677f02b8ebf1ea')
  };
  function algName(h) { return { SHA512: 'SHA-512', SHA384: 'SHA-384', SHA256: 'SHA-256', SHA1: 'SHA-1' }[h] || 'SHA-512'; }
  async function pwHash(alg, salt, pw, spin) {
    var h = await sha(alg, concat([salt, utf16le(pw)]));
    var buf = new Uint8Array(4 + h.length), dv = new DataView(buf.buffer);
    for (var i = 0; i < spin; i++) { dv.setUint32(0, i, true); buf.set(h, 4); h = await sha(alg, buf); }
    return h;
  }
  async function deriveKey(alg, h, bk, bytes) { return fix(await sha(alg, concat([h, bk])), bytes, 0x36); }

  function parseEncInfo(buf) {
    var dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    var vMaj = dv.getUint16(0, true), vMin = dv.getUint16(2, true);
    if (!(vMaj === 4 && vMin === 4)) throw new Error('지원하지 않는 엑셀 암호 방식입니다 (버전 ' + vMaj + '.' + vMin + '). 엑셀 2010 이후 "암호로 보호"만 지원합니다.');
    var xml = td.decode(buf.subarray(8));
    var doc = new DOMParser().parseFromString(xml, 'application/xml');
    var kd = doc.getElementsByTagName('keyData')[0];
    var di = doc.getElementsByTagName('dataIntegrity')[0];
    var ek = doc.getElementsByTagNameNS('http://schemas.microsoft.com/office/2006/keyEncryptor/password', 'encryptedKey')[0];
    function a(el, n) { return el.getAttribute(n); }
    return {
      keyData: { salt: b64d(a(kd, 'saltValue')), blockSize: +a(kd, 'blockSize'), keyBits: +a(kd, 'keyBits'), hash: algName(a(kd, 'hashAlgorithm')) },
      pw: {
        spin: +a(ek, 'spinCount'), salt: b64d(a(ek, 'saltValue')), keyBits: +a(ek, 'keyBits'), hash: algName(a(ek, 'hashAlgorithm')),
        verIn: b64d(a(ek, 'encryptedVerifierHashInput')), verVal: b64d(a(ek, 'encryptedVerifierHashValue')), keyVal: b64d(a(ek, 'encryptedKeyValue'))
      },
      integrity: di ? { key: b64d(a(di, 'encryptedHmacKey')), val: b64d(a(di, 'encryptedHmacValue')) } : null
    };
  }

  async function decryptAgile(encInfoBuf, pkgBuf, password) {
    var info = parseEncInfo(encInfoBuf), p = info.pw, kb = p.keyBits / 8;
    var h = await pwHash(p.hash, p.salt, password, p.spin);
    var vin = await aesDec(await deriveKey(p.hash, h, BK.verIn, kb), p.salt, p.verIn);
    var vval = await aesDec(await deriveKey(p.hash, h, BK.verVal, kb), p.salt, p.verVal);
    var vh = await sha(p.hash, vin.slice(0, p.salt.length));
    if (!eq(vh, vval.slice(0, vh.length))) { var e = new Error('비밀번호가 맞지 않습니다.'); e.code = 'BADPW'; throw e; }
    var secret = (await aesDec(await deriveKey(p.hash, h, BK.key, kb), p.salt, p.keyVal)).slice(0, info.keyData.keyBits / 8);
    var size = new DataView(pkgBuf.buffer, pkgBuf.byteOffset, 8).getUint32(0, true);
    var data = pkgBuf.subarray(8), parts = [], seg = 0;
    for (var off = 0; off < data.length; off += 4096, seg++) {
      var chunk = data.subarray(off, Math.min(off + 4096, data.length));
      chunk = chunk.subarray(0, chunk.length - (chunk.length % 16));
      if (!chunk.length) break;
      var iv = fix(await sha(info.keyData.hash, concat([info.keyData.salt, u32(seg)])), info.keyData.blockSize, 0x36);
      parts.push(await aesDec(secret, iv, chunk));
    }
    return concat(parts).slice(0, size);
  }

  async function encryptAgile(plain, password) {
    var HA = 'SHA-512', spin = 100000;
    var secret = rand(32), kdSalt = rand(16), pwSalt = rand(16);
    // package
    var segs = [u64(plain.length)];
    for (var off = 0, seg = 0; off < plain.length; off += 4096, seg++) {
      var chunk = plain.subarray(off, Math.min(off + 4096, plain.length));
      if (chunk.length % 16) { var c2 = new Uint8Array(chunk.length + 16 - (chunk.length % 16)); c2.set(chunk); chunk = c2; }
      var iv = fix(await sha(HA, concat([kdSalt, u32(seg)])), 16, 0x36);
      segs.push(await aesEnc(secret, iv, chunk));
    }
    var pkg = concat(segs);
    // integrity
    var hmacKey = rand(64);
    var ivK = fix(await sha(HA, concat([kdSalt, BK.hmacKey])), 16, 0x36);
    var ivV = fix(await sha(HA, concat([kdSalt, BK.hmacVal])), 16, 0x36);
    var hk = await subtle.importKey('raw', hmacKey, { name: 'HMAC', hash: HA }, false, ['sign']);
    var hmac = new Uint8Array(await subtle.sign('HMAC', hk, pkg));
    var encHK = await aesEnc(secret, ivK, hmacKey), encHV = await aesEnc(secret, ivV, hmac);
    // password key encryptor
    var h = await pwHash(HA, pwSalt, password, spin);
    var vin = rand(16);
    var encVin = await aesEnc(await deriveKey(HA, h, BK.verIn, 32), pwSalt, vin);
    var encVval = await aesEnc(await deriveKey(HA, h, BK.verVal, 32), pwSalt, await sha(HA, vin));
    var encKey = await aesEnc(await deriveKey(HA, h, BK.key, 32), pwSalt, secret);
    var common = 'saltSize="16" blockSize="16" keyBits="256" hashSize="64" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512"';
    var xml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n' +
      '<encryption xmlns="http://schemas.microsoft.com/office/2006/encryption" xmlns:p="http://schemas.microsoft.com/office/2006/keyEncryptor/password" xmlns:c="http://schemas.microsoft.com/office/2006/keyEncryptor/certificate">' +
      '<keyData ' + common + ' saltValue="' + b64e(kdSalt) + '"/>' +
      '<dataIntegrity encryptedHmacKey="' + b64e(encHK) + '" encryptedHmacValue="' + b64e(encHV) + '"/>' +
      '<keyEncryptors><keyEncryptor uri="http://schemas.microsoft.com/office/2006/keyEncryptor/password">' +
      '<p:encryptedKey spinCount="' + spin + '" ' + common + ' saltValue="' + b64e(pwSalt) + '" encryptedVerifierHashInput="' + b64e(encVin) +
      '" encryptedVerifierHashValue="' + b64e(encVval) + '" encryptedKeyValue="' + b64e(encKey) + '"/>' +
      '</keyEncryptor></keyEncryptors></encryption>';
    var info = concat([new Uint8Array([4, 0, 4, 0, 0x40, 0, 0, 0]), te.encode(xml)]);
    return { encryptionInfo: info, encryptedPackage: pkg };
  }

  // ---------- CFB (compound file) ----------
  var ENDC = 0xFFFFFFFE, FREE = 0xFFFFFFFF, FATSECT = 0xFFFFFFFD, NOS = 0xFFFFFFFF;
  function isCFB(b) { return b.length > 8 && b[0] === 0xD0 && b[1] === 0xCF && b[2] === 0x11 && b[3] === 0xE0; }
  function cfbRead(buf) {
    var dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    var ss = 1 << dv.getUint16(0x1E, true), mss = 1 << dv.getUint16(0x20, true);
    var nFat = dv.getUint32(0x2C, true), dirStart = dv.getUint32(0x30, true), cutoff = dv.getUint32(0x38, true);
    var mfStart = dv.getUint32(0x3C, true), difStart = dv.getUint32(0x44, true);
    function so(s) { return (s + 1) * ss; }
    var fatSecs = [];
    for (var i = 0; i < 109 && fatSecs.length < nFat; i++) fatSecs.push(dv.getUint32(0x4C + i * 4, true));
    var d = difStart;
    while (fatSecs.length < nFat && d !== ENDC && d !== FREE) {
      for (var j = 0; j < ss / 4 - 1 && fatSecs.length < nFat; j++) fatSecs.push(dv.getUint32(so(d) + j * 4, true));
      d = dv.getUint32(so(d) + ss - 4, true);
    }
    var fat = [];
    fatSecs.forEach(function (s) { for (var k = 0; k < ss / 4; k++) fat.push(dv.getUint32(so(s) + k * 4, true)); });
    function chain(start) { var out = [], s = start, g = 0; while (s !== ENDC && s !== FREE && s < fat.length && g++ < 1e6) { out.push(s); s = fat[s]; } return out; }
    function readBig(start, size) { var parts = chain(start).map(function (s) { return buf.subarray(so(s), so(s) + ss); }); return concat(parts).slice(0, size); }
    var dirBytes = readBig(dirStart, chain(dirStart).length * ss);
    var ents = [];
    for (var e = 0; e < dirBytes.length / 128; e++) {
      var o = e * 128, ddv = new DataView(dirBytes.buffer, dirBytes.byteOffset + o, 128);
      var nl = ddv.getUint16(0x40, true), name = '';
      for (var c = 0; c < nl / 2 - 1; c++) name += String.fromCharCode(ddv.getUint16(c * 2, true));
      ents.push({ name: name, type: ddv.getUint8(0x42), left: ddv.getUint32(0x44, true), right: ddv.getUint32(0x48, true), child: ddv.getUint32(0x4C, true), start: ddv.getUint32(0x74, true), size: ddv.getUint32(0x78, true) });
    }
    var root = ents[0];
    var miniStream = readBig(root.start, root.size);
    var minifat = [];
    if (mfStart !== ENDC) { var mfb = readBig(mfStart, chain(mfStart).length * ss); for (var m = 0; m < mfb.length / 4; m++) minifat.push(new DataView(mfb.buffer, mfb.byteOffset).getUint32(m * 4, true)); }
    function readMini(start, size) { var parts = [], s = start, g = 0; while (s !== ENDC && s !== FREE && g++ < 1e6) { parts.push(miniStream.subarray(s * mss, s * mss + mss)); s = minifat[s]; } return concat(parts).slice(0, size); }
    var files = {};
    function walk(idx, prefix) {
      if (idx === NOS || idx >= ents.length) return;
      var en = ents[idx];
      walk(en.left, prefix); walk(en.right, prefix);
      var path = prefix + en.name;
      if (en.type === 2) files[path] = en.size < cutoff ? readMini(en.start, en.size) : readBig(en.start, en.size);
      else if (en.type === 1) walk(en.child, path + '/');
    }
    walk(root.child, '');
    return files; // { 'EncryptionInfo': Uint8Array, '\u0006DataSpaces/Version': ... }
  }

  function cfbCmp(a, b) { if (a.length !== b.length) return a.length - b.length; var A = a.toUpperCase(), B = b.toUpperCase(); return A < B ? -1 : A > B ? 1 : 0; }
  function cfbWrite(files) {
    var SS = 512, MSS = 64, CUT = 4096;
    // build tree
    var nodes = [{ name: 'Root Entry', type: 5, kids: {} }];
    Object.keys(files).forEach(function (p) {
      var parts = p.split('/'), cur = nodes[0];
      parts.forEach(function (nm, i) {
        if (!cur.kids[nm]) { var n = { name: nm, type: i === parts.length - 1 ? 2 : 1, kids: {} }; if (n.type === 2) n.data = files[p]; nodes.push(n); cur.kids[nm] = n; }
        cur = cur.kids[nm];
      });
    });
    nodes.forEach(function (n, i) { n.id = i; n.left = n.right = n.child = NOS; n.start = ENDC; n.size = 0; });
    function bal(arr) { if (!arr.length) return NOS; var m = arr.length >> 1; arr[m].left = bal(arr.slice(0, m)); arr[m].right = bal(arr.slice(m + 1)); return arr[m].id; }
    nodes.forEach(function (n) { var ks = Object.keys(n.kids).sort(cfbCmp).map(function (k) { return n.kids[k]; }); n.child = bal(ks); });
    // mini stream
    var mini = [], minifat = [];
    nodes.forEach(function (n) {
      if (n.type !== 2 || n.data.length >= CUT) return;
      n.size = n.data.length;
      if (!n.data.length) { n.start = ENDC; return; }
      var cnt = Math.ceil(n.data.length / MSS), first = minifat.length;
      for (var i = 0; i < cnt; i++) minifat.push(i === cnt - 1 ? ENDC : first + i + 1);
      var padded = new Uint8Array(cnt * MSS); padded.set(n.data); mini.push(padded); n.start = first;
    });
    var miniBytes = concat(mini);
    var bigs = nodes.filter(function (n) { return n.type === 2 && n.data.length >= CUT; });
    var nDir = Math.ceil(nodes.length * 128 / SS);
    var nMF = Math.ceil(minifat.length * 4 / SS);
    var nMS = Math.ceil(miniBytes.length / SS);
    var nBig = bigs.reduce(function (s, n) { return s + Math.ceil(n.data.length / SS); }, 0);
    var nFat = 1;
    while (Math.ceil((nFat + nDir + nMF + nMS + nBig) / (SS / 4)) > nFat) nFat++;
    if (nFat > 109) throw new Error('파일이 너무 큽니다.');
    var total = nFat + nDir + nMF + nMS + nBig;
    var fat = new Array(nFat * SS / 4).fill(FREE), cur = 0;
    function alloc(cnt) { var st = cur; for (var i = 0; i < cnt; i++) fat[cur + i] = i === cnt - 1 ? ENDC : cur + i + 1; cur += cnt; return cnt ? st : ENDC; }
    for (var f = 0; f < nFat; f++) fat[cur++] = FATSECT;
    var dirStart = alloc(nDir), mfStart = alloc(nMF), msStart = alloc(nMS);
    nodes[0].start = nMS ? msStart : ENDC; nodes[0].size = miniBytes.length;
    bigs.forEach(function (n) { n.size = n.data.length; n.start = alloc(Math.ceil(n.data.length / SS)); });
    var out = new Uint8Array(SS * (1 + total)), dv = new DataView(out.buffer);
    out.set(hex('d0cf11e0a1b11ae1'), 0);
    dv.setUint16(0x18, 0x3E, true); dv.setUint16(0x1A, 3, true); dv.setUint16(0x1C, 0xFFFE, true);
    dv.setUint16(0x1E, 9, true); dv.setUint16(0x20, 6, true);
    dv.setUint32(0x2C, nFat, true); dv.setUint32(0x30, dirStart, true); dv.setUint32(0x38, CUT, true);
    dv.setUint32(0x3C, nMF ? mfStart : ENDC, true); dv.setUint32(0x40, nMF, true);
    dv.setUint32(0x44, ENDC, true); dv.setUint32(0x48, 0, true);
    for (var i = 0; i < 109; i++) dv.setUint32(0x4C + i * 4, i < nFat ? i : FREE, true);
    function sec(s) { return SS * (s + 1); }
    fat.forEach(function (v, k) { dv.setUint32(sec(0) + k * 4, v, true); });
    // directory
    var dirBuf = new Uint8Array(nDir * SS), ddv = new DataView(dirBuf.buffer);
    for (var e = 0; e < nDir * SS / 128; e++) {
      var o = e * 128, n = nodes[e];
      if (!n) { ddv.setUint32(o + 0x44, NOS, true); ddv.setUint32(o + 0x48, NOS, true); ddv.setUint32(o + 0x4C, NOS, true); continue; }
      for (var c = 0; c < n.name.length; c++) ddv.setUint16(o + c * 2, n.name.charCodeAt(c), true);
      ddv.setUint16(o + 0x40, (n.name.length + 1) * 2, true);
      ddv.setUint8(o + 0x42, n.type); ddv.setUint8(o + 0x43, 1);
      ddv.setUint32(o + 0x44, n.left, true); ddv.setUint32(o + 0x48, n.right, true); ddv.setUint32(o + 0x4C, n.child, true);
      ddv.setUint32(o + 0x74, n.type === 1 ? 0 : n.start, true); ddv.setUint32(o + 0x78, n.size, true);
    }
    out.set(dirBuf, sec(dirStart));
    if (nMF) { var mfb = new Uint8Array(nMF * SS).fill(0xFF), mdv = new DataView(mfb.buffer); minifat.forEach(function (v, k) { mdv.setUint32(k * 4, v, true); }); out.set(mfb, sec(mfStart)); }
    if (nMS) out.set(miniBytes, sec(msStart));
    bigs.forEach(function (n) { out.set(n.data, sec(n.start)); });
    return out;
  }

  // ---------- ZIP ----------
  var CRC = (function () { var t = new Uint32Array(256); for (var n = 0; n < 256; n++) { var c = n; for (var k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
  function crc32(b) { var c = 0xFFFFFFFF; for (var i = 0; i < b.length; i++) c = CRC[(c ^ b[i]) & 255] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; }
  async function pipe(data, stream) { var r = new Response(new Blob([data]).stream().pipeThrough(stream)); return new Uint8Array(await r.arrayBuffer()); }
  async function unzip(buf) {
    var dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength), eo = -1;
    for (var i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) if (dv.getUint32(i, true) === 0x06054b50) { eo = i; break; }
    if (eo < 0) throw new Error('엑셀(xlsx) 파일이 아닙니다.');
    var cnt = dv.getUint16(eo + 10, true), off = dv.getUint32(eo + 16, true), files = {}, order = [];
    for (var n = 0; n < cnt; n++) {
      var method = dv.getUint16(off + 10, true), csize = dv.getUint32(off + 20, true);
      var nl = dv.getUint16(off + 28, true), xl = dv.getUint16(off + 30, true), cl = dv.getUint16(off + 32, true), lo = dv.getUint32(off + 42, true);
      var name = td.decode(buf.subarray(off + 46, off + 46 + nl));
      var ds = lo + 30 + dv.getUint16(lo + 26, true) + dv.getUint16(lo + 28, true);
      var raw = buf.subarray(ds, ds + csize);
      files[name] = method === 0 ? raw.slice() : await pipe(raw, new DecompressionStream('deflate-raw'));
      order.push(name);
      off += 46 + nl + xl + cl;
    }
    return { files: files, order: order };
  }
  async function zip(files, order) {
    var locals = [], cents = [], off = 0;
    for (var i = 0; i < order.length; i++) {
      var name = order[i], data = files[name]; if (!data) continue;
      var nb = te.encode(name), comp = await pipe(data, new CompressionStream('deflate-raw')), crc = crc32(data);
      var lh = new Uint8Array(30), l = new DataView(lh.buffer);
      l.setUint32(0, 0x04034b50, true); l.setUint16(4, 20, true); l.setUint16(6, 0x0800, true); l.setUint16(8, 8, true);
      l.setUint16(12, 0x21, true); l.setUint32(14, crc, true); l.setUint32(18, comp.length, true); l.setUint32(22, data.length, true); l.setUint16(26, nb.length, true);
      var ch = new Uint8Array(46), c = new DataView(ch.buffer);
      c.setUint32(0, 0x02014b50, true); c.setUint16(4, 20, true); c.setUint16(6, 20, true); c.setUint16(8, 0x0800, true); c.setUint16(10, 8, true);
      c.setUint16(14, 0x21, true); c.setUint32(16, crc, true); c.setUint32(20, comp.length, true); c.setUint32(24, data.length, true); c.setUint16(28, nb.length, true); c.setUint32(42, off, true);
      locals.push(lh, nb, comp); cents.push(ch, nb);
      off += 30 + nb.length + comp.length;
    }
    var cd = concat(cents), eocd = new Uint8Array(22), e = new DataView(eocd.buffer);
    var n = cents.length / 2;
    e.setUint32(0, 0x06054b50, true); e.setUint16(8, n, true); e.setUint16(10, n, true); e.setUint32(12, cd.length, true); e.setUint32(16, off, true);
    return concat(locals.concat([cd, eocd]));
  }

  // ---------- open / save (with optional password) ----------
  async function openWorkbookBytes(bytes, password) {
    if (isCFB(bytes)) {
      var cfb = cfbRead(bytes);
      if (!cfb.EncryptionInfo || !cfb.EncryptedPackage) throw new Error('예전 형식(xls) 파일은 지원하지 않습니다. xlsx로 저장해 주세요.');
      if (!password) { var e = new Error('암호가 걸린 파일입니다. 비밀번호를 입력하세요.'); e.code = 'NEEDPW'; throw e; }
      var plain = await decryptAgile(cfb.EncryptionInfo, cfb.EncryptedPackage, password);
      return { zip: await unzip(plain), encrypted: true, cfbExtra: cfb };
    }
    return { zip: await unzip(bytes), encrypted: false };
  }
  async function saveWorkbookBytes(wb, password) {
    var plain = await zip(wb.zip.files, wb.zip.order);
    if (!password) return plain;
    var enc = await encryptAgile(plain, password);
    var files = {};
    Object.keys(wb.cfbExtra || {}).forEach(function (k) { if (k !== 'EncryptionInfo' && k !== 'EncryptedPackage') files[k] = wb.cfbExtra[k]; });
    if (!Object.keys(files).length) files = defaultDataSpaces();
    files.EncryptionInfo = enc.encryptionInfo;
    files.EncryptedPackage = enc.encryptedPackage;
    return cfbWrite(files);
  }
  function defaultDataSpaces() {
    // minimal DataSpaces streams for Agile encryption (MS-OFFCRYPTO 2.1)
    function lps(s) { var b = utf16le(s); var pad = (4 - b.length % 4) % 4; return concat([u32(b.length), b, new Uint8Array(pad)]); }
    var D = '\u0006DataSpaces/';
    var ver = concat([lps('Microsoft.Container.DataSpaces'), u32(0x10001), u32(0x10001), u32(0x10001)]);
    var mapEntryBody = concat([u32(1), u32(0), lps('EncryptedPackage'), lps('StrongEncryptionDataSpace')]);
    var map = concat([u32(8), u32(1), u32(mapEntryBody.length + 4), mapEntryBody]);
    var dsd = concat([u32(8), u32(1), lps('StrongEncryptionTransform')]);
    var trBody = concat([u32(1), lps('{FF9A3F03-56EF-4613-BDD5-5A41C1D07246}'), lps('Microsoft.Container.EncryptionTransform'), u32(0x10001), u32(0x10001), u32(0x10001)]);
    var tr = concat([u32(trBody.length + 4), trBody, u32(0), u32(0)]);
    var f = {}; f[D + 'Version'] = ver; f[D + 'DataSpaceMap'] = map; f[D + 'DataSpaceInfo/StrongEncryptionDataSpace'] = dsd; f[D + 'TransformInfo/StrongEncryptionTransform/\u0006Primary'] = tr;
    return f;
  }

  // ---------- XLSX helpers ----------
  function xmlDoc(bytes) { return new DOMParser().parseFromString(td.decode(bytes), 'application/xml'); }
  function colNum(s) { var n = 0; for (var i = 0; i < s.length; i++) n = n * 26 + s.charCodeAt(i) - 64; return n; }
  function colName(n) { var s = ''; while (n > 0) { var m = (n - 1) % 26; s = String.fromCharCode(65 + m) + s; n = Math.floor((n - 1) / 26); } return s; }
  function splitRef(r) { var m = /^([A-Z]+)(\d+)$/.exec(r); return { c: colNum(m[1]), r: +m[2] }; }
  function resolvePath(base, target) {
    if (target[0] === '/') return target.slice(1);
    var parts = base.split('/'); parts.pop();
    target.split('/').forEach(function (p) { if (p === '..') parts.pop(); else if (p !== '.') parts.push(p); });
    return parts.join('/');
  }
  function sheetList(wb) {
    var f = wb.zip.files, w = xmlDoc(f['xl/workbook.xml']), rels = xmlDoc(f['xl/_rels/workbook.xml.rels']);
    var map = {}; Array.prototype.forEach.call(rels.getElementsByTagName('Relationship'), function (r) { map[r.getAttribute('Id')] = resolvePath('xl/workbook.xml', r.getAttribute('Target')); });
    return Array.prototype.map.call(w.getElementsByTagName('sheet'), function (s) {
      return { name: s.getAttribute('name'), path: map[s.getAttributeNS('http://schemas.openxmlformats.org/officeDocument/2006/relationships', 'id') || s.getAttribute('r:id')] };
    });
  }
  function sharedStrings(wb) {
    var b = wb.zip.files['xl/sharedStrings.xml']; if (!b) return [];
    var d = xmlDoc(b);
    return Array.prototype.map.call(d.getElementsByTagName('si'), function (si) {
      return Array.prototype.map.call(si.getElementsByTagName('t'), function (t) {
        var p = t.parentNode; if (p && p.localName === 'rPh') return ''; return t.textContent;
      }).join('');
    });
  }
  // returns { cells: { 'F7': {v, t} }, grid: Map row -> Map col -> value }
  function readSheet(wb, path, sst) {
    var d = xmlDoc(wb.zip.files[path]), grid = {};
    Array.prototype.forEach.call(d.getElementsByTagName('c'), function (c) {
      var ref = c.getAttribute('r'); if (!ref) return;
      var t = c.getAttribute('t'), vEl = c.getElementsByTagName('v')[0], v = vEl ? vEl.textContent : null;
      if (t === 's') v = v == null ? null : sst[+v];
      else if (t === 'inlineStr') v = Array.prototype.map.call(c.getElementsByTagName('t'), function (x) { return x.textContent; }).join('');
      else if (t === 'b') v = v === '1';
      else if (t === 'e') v = null;
      else if (t !== 'str' && v != null && v !== '') v = +v;
      var rc = splitRef(ref);
      (grid[rc.r] = grid[rc.r] || {})[rc.c] = v;
    });
    return grid;
  }

  function escXml(s) { return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }

  // write string values into an existing sheet xml (string-level edit to preserve everything else)
  // writes: [{ r: rowNum, c: colNum, v: 'text' }]
  function writeCells(wb, path, writes) {
    var xml = td.decode(wb.zip.files[path]);
    var byRow = {};
    writes.forEach(function (w) { (byRow[w.r] = byRow[w.r] || []).push(w); });
    var maxCol = 0, maxRow = 0;
    Object.keys(byRow).forEach(function (rn) {
      rn = +rn; var ws = byRow[rn];
      var rowRe = new RegExp('<row\\b[^>]*\\br="' + rn + '"[^>]*?(?:/>|>([\\s\\S]*?)</row>)');
      var m = rowRe.exec(xml);
      var cells = [];
      var openTag;
      if (m) {
        openTag = /^<row\b[^>]*?(?=\/?>)/.exec(m[0])[0].replace(/\sspans="[^"]*"/, '');
        var inner = m[1] || '', cre = /<c\b[^>]*?(?:\/>|>[\s\S]*?<\/c>)/g, cm;
        while ((cm = cre.exec(inner))) { var rr = /\br="([A-Z]+)\d+"/.exec(cm[0]); cells.push({ c: colNum(rr[1]), x: cm[0] }); }
      } else openTag = '<row r="' + rn + '"';
      ws.forEach(function (w) {
        var ex = cells.filter(function (c) { return c.c === w.c; })[0];
        var sm = ex ? /\ss="(\d+)"/.exec(ex.x) : null;
        if (!sm && w.styleFrom) { var src = cells.filter(function (c) { return c.c === w.styleFrom; })[0]; sm = src ? /\ss="(\d+)"/.exec(src.x) : null; }
        var x = '<c r="' + colName(w.c) + rn + '"' + (sm ? ' s="' + sm[1] + '"' : '') + ' t="inlineStr"><is><t>' + escXml(w.v) + '</t></is></c>';
        cells = cells.filter(function (c) { return c.c !== w.c; });
        cells.push({ c: w.c, x: x });
        maxCol = Math.max(maxCol, w.c); maxRow = Math.max(maxRow, rn);
      });
      cells.sort(function (a, b) { return a.c - b.c; });
      var newRow = openTag + '>' + cells.map(function (c) { return c.x; }).join('') + '</row>';
      if (m) xml = xml.slice(0, m.index) + newRow + xml.slice(m.index + m[0].length);
      else {
        // insert in order
        var rows = [], rre = /<row\b[^>]*\br="(\d+)"/g, rm;
        while ((rm = rre.exec(xml))) rows.push({ n: +rm[1], i: rm.index });
        var after = rows.filter(function (r) { return r.n > rn; })[0];
        if (after) xml = xml.slice(0, after.i) + newRow + xml.slice(after.i);
        else xml = xml.replace('</sheetData>', newRow + '</sheetData>').replace('<sheetData/>', '<sheetData>' + newRow + '</sheetData>');
      }
    });
    // widen dimension
    xml = xml.replace(/<dimension ref="([A-Z]+)(\d+)(?::([A-Z]+)(\d+))?"\/>/, function (all, c1, r1, c2, r2) {
      var mc = Math.max(colNum(c2 || c1), maxCol), mr = Math.max(+(r2 || r1), maxRow);
      return '<dimension ref="' + c1 + r1 + ':' + colName(mc) + mr + '"/>';
    });
    wb.zip.files[path] = te.encode(xml);
  }

  function removeCalcChain(wb) {
    var f = wb.zip.files;
    if (!f['xl/calcChain.xml']) return;
    delete f['xl/calcChain.xml'];
    wb.zip.order = wb.zip.order.filter(function (n) { return n !== 'xl/calcChain.xml'; });
    f['xl/_rels/workbook.xml.rels'] = te.encode(td.decode(f['xl/_rels/workbook.xml.rels']).replace(/<Relationship\b[^>]*calcChain[^>]*\/>/g, ''));
    f['[Content_Types].xml'] = te.encode(td.decode(f['[Content_Types].xml']).replace(/<Override\b[^>]*calcChain[^>]*\/>/g, ''));
  }

  function addSheet(wb, name, rows /* array of arrays of strings/numbers */) {
    var f = wb.zip.files, existing = sheetList(wb).map(function (s) { return s.name; });
    var nm = name, k = 2; while (existing.indexOf(nm) >= 0) nm = name + '(' + (k++) + ')';
    var idx = 1; while (f['xl/worksheets/sheet' + idx + '.xml']) idx++;
    var path = 'xl/worksheets/sheet' + idx + '.xml';
    var sd = rows.map(function (row, ri) {
      return '<row r="' + (ri + 1) + '">' + row.map(function (v, ci) {
        if (v === null || v === undefined || v === '') return '';
        var ref = colName(ci + 1) + (ri + 1);
        return typeof v === 'number' ? '<c r="' + ref + '"><v>' + v + '</v></c>' : '<c r="' + ref + '" t="inlineStr"><is><t>' + escXml(v) + '</t></is></c>';
      }).join('') + '</row>';
    }).join('');
    f[path] = te.encode('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><cols><col min="1" max="1" width="16" customWidth="1"/><col min="2" max="8" width="11" customWidth="1"/></cols><sheetData>' + sd + '</sheetData></worksheet>');
    wb.zip.order.push(path);
    var rels = td.decode(f['xl/_rels/workbook.xml.rels']), rid = 1; while (rels.indexOf('Id="rId' + rid + '"') >= 0) rid++;
    f['xl/_rels/workbook.xml.rels'] = te.encode(rels.replace('</Relationships>', '<Relationship Id="rId' + rid + '" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet' + idx + '.xml"/></Relationships>'));
    var w = td.decode(f['xl/workbook.xml']), sid = 1, sm, sre = /sheetId="(\d+)"/g; while ((sm = sre.exec(w))) sid = Math.max(sid, +sm[1] + 1);
    var rPrefix = /xmlns:(\w+)="http:\/\/schemas\.openxmlformats\.org\/officeDocument\/2006\/relationships"/.exec(w);
    var rp = rPrefix ? rPrefix[1] : 'r';
    f['xl/workbook.xml'] = te.encode(w.replace('</sheets>', '<sheet xmlns:' + rp + '="http://schemas.openxmlformats.org/officeDocument/2006/relationships" name="' + escXml(nm) + '" sheetId="' + sid + '" ' + rp + ':id="rId' + rid + '"/></sheets>'));
    var ct = td.decode(f['[Content_Types].xml']);
    f['[Content_Types].xml'] = te.encode(ct.replace('</Types>', '<Override PartName="/' + path + '" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>'));
    return nm;
  }

  return {
    openWorkbookBytes: openWorkbookBytes, saveWorkbookBytes: saveWorkbookBytes,
    sheetList: sheetList, sharedStrings: sharedStrings, readSheet: readSheet,
    writeCells: writeCells, removeCalcChain: removeCalcChain, addSheet: addSheet,
    colName: colName, colNum: colNum, b64e: b64e, b64d: b64d,
    _cfbRead: cfbRead, _cfbWrite: cfbWrite, _unzip: unzip, _zip: zip, _decryptAgile: decryptAgile
  };
})();

/* ===== app: 성적 입력 도우미 (점수 → 단계 → 나이스 dsMain / 결과 엑셀) ===== */
(function () {
  'use strict';
  var VERSION = '1.4.5';

  // ── 영역별 계산 방식 (학교 양식에 맞춰 한 번만 정해두는 곳) ──
  // cols: 점수 열 제목(소제목 줄)과 맞출 패턴, 여러 개면 평균
  // neis: 나이스 평가요소(평가요소 문구)에서 이 영역을 알아볼 단어
  var RECIPE = [
    { area: 'Reading',   cols: [/^final\s*exam\s*\(100\)$/i], neis: ['읽'] },
    { area: 'Speaking',  cols: [/^speaking\s*\(100\)$/i],     neis: ['말하', '말 하', '활동'] },
    { area: 'Writing',   cols: [/^wr?iting\s*\(100\)$/i],     neis: ['쓰기', '쓰'] },
    { area: 'Listening', cols: [/^listening\s*\(100\)$/i],    neis: ['듣'] }
  ];
  var DEFAULT_LEVELS = ['잘함', '보통', '노력요함'];
  var LS_CUT = 'ngh.cutoffs.v1', LS_MAP = 'ngh.map.v1.', LS_WIN = 'ngh.win.v1';

  // 이미 떠 있으면 다시 보이게 하고 나이스 화면을 다시 확인
  var old = document.getElementById('ngh-host');
  if (old) { if (window.__ngh && window.__ngh.wake) window.__ngh.wake(); else old.style.display = ''; return; }

  // ───────────────────────── 엑셀에서 점수 읽기 ─────────────────────────
  function norm(s) { return String(s == null ? '' : s).replace(/\s+/g, ' ').trim(); }
  function nameKey(s) { return norm(s).replace(/\(.*?\)/g, '').replace(/\s/g, ''); }

  function sheetFormulas(wb, path) {
    var d = new DOMParser().parseFromString(new TextDecoder().decode(wb.zip.files[path]), 'application/xml'), out = {};
    Array.prototype.forEach.call(d.getElementsByTagName('c'), function (c) { var f = c.getElementsByTagName('f')[0]; if (f) out[c.getAttribute('r')] = f.textContent; });
    return out;
  }
  function headerMap(row) { var m = {}; Object.keys(row || {}).forEach(function (c) { m[norm(row[c]).toLowerCase()] = +c; }); return m; }
  function extractIntegrated(wb) {
    var sst = NGH.sharedStrings(wb), sheets = NGH.sheetList(wb);
    var ts = sheets.filter(function (s) { return norm(s.name) === '통합성적표'; })[0];
    var rs = sheets.filter(function (s) { return norm(s.name) === '정규 반배정'; })[0];
    if (!ts || !rs) return null;
    var g = NGH.readSheet(wb, ts.path, sst), rg = NGH.readSheet(wb, rs.path, sst), formulas = sheetFormulas(wb, ts.path);
    var hr = Object.keys(g).map(Number).filter(function (r) { var h = headerMap(g[r]); return h['한국어 이름'] && h['반'] && h.speaking && h.reading; })[0];
    var rr = Object.keys(rg).map(Number).filter(function (r) { var h = headerMap(rg[r]); return h['한국어 이름'] && h['새 반'] && h['새 번호']; })[0];
    if (!hr || !rr) throw new Error('통합성적표 또는 정규 반배정의 제목 줄을 찾지 못했습니다.');
    var h = headerMap(g[hr]), rh = headerMap(rg[rr]);
    var cols = { Speaking: [h.speaking], Writing: [h.writing], Listening: [h.listening], Reading: [h.reading] };
    if (RECIPE.some(function (rc) { return !cols[rc.area][0]; })) throw new Error('통합성적표에 Speaking/Writing/Listening/Reading 점수 열이 모두 있어야 합니다.');
    var regular = {}, regularRows = [];
    Object.keys(rg).map(Number).filter(function (r) { return r > rr; }).forEach(function (r) {
      var nm = norm(rg[r][rh['한국어 이름']]); if (!nm) return;
      var x = { name: nm, eng: norm(rg[r][rh['영어 이름']]), oldCls: norm(rg[r][rh['이전 반']]), cls: norm(rg[r][rh['새 반']]), no: +rg[r][rh['새 번호']], engClass: norm(rg[r][rh['영어반']]) };
      regularRows.push(x); regular[[nameKey(x.name), x.eng.toLowerCase(), x.oldCls].join('|')] = x;
    });
    var students = [], unmatched = [];
    Object.keys(g).map(Number).filter(function (r) { return r > hr; }).sort(function (a, b) { return a - b; }).forEach(function (r) {
      var nm = norm(g[r][h['한국어 이름']]); if (!nm) return;
      var eng = norm(g[r][h['영어 이름']]), oldCls = norm(g[r][h['반']]);
      var reg = regular[[nameKey(nm), eng.toLowerCase(), oldCls].join('|')];
      if (!reg) { unmatched.push(nm + ' ' + oldCls); return; }
      var sc = {}; RECIPE.forEach(function (rc) { var v = g[r][cols[rc.area][0]]; sc[rc.area] = typeof v === 'number' ? v : null; });
      var m = /^(\d+)\s*-\s*(\d+)$/.exec(reg.cls);
      students.push({ key: reg.cls + '-' + reg.no, no: reg.no, cls: reg.cls, grd: m ? m[1] : '', classNo: m ? m[2] : '', name: nm, eng: eng, oldEngClass: norm(g[r][h['영어반']]), engClass: reg.engClass, row: r, scores: sc });
    });
    var cutoffs = {};
    Object.keys(g).map(Number).filter(function (r) { return r < hr; }).forEach(function (r) {
      var area = norm(g[r][1]), rc = RECIPE.filter(function (x) { return x.area === area; })[0]; if (!rc) return;
      var avg = students.map(function (s) { return s.scores[area]; }).filter(function (v) { return typeof v === 'number'; });
      var avgV = avg.length ? Math.round(avg.reduce(function (a, b) { return a + b; }, 0) / avg.length * 100) / 100 : '';
      var good = g[r][3], low = g[r][4];
      if (typeof good !== 'number' && /^B\d+$/i.test(String(formulas['C' + r] || '').trim())) good = avgV;
      if (typeof low !== 'number') low = 0;
      cutoffs[area] = [good, low];
    });
    return { integrated: true, sheet: ts, regularSheet: rs, heads: [{ r: hr, cols: cols }], students: students, emptyNos: [], cutoffs: cutoffs, unmatched: unmatched,
      noScore: regularRows.filter(function (x) { return !students.some(function (s) { return s.key === x.cls + '-' + x.no; }); }).map(function (x) { return x.cls + ' ' + x.no + '번 ' + x.name; }) };
  }

  function extract(wb) {
    var integrated = extractIntegrated(wb); if (integrated) return integrated;
    var sst = NGH.sharedStrings(wb), sheets = NGH.sheetList(wb);
    for (var si = 0; si < sheets.length; si++) {
      var g = NGH.readSheet(wb, sheets[si].path, sst);
      var rows = Object.keys(g).map(Number).sort(function (a, b) { return a - b; });
      // 점수 소제목 줄 찾기
      var heads = [];
      rows.forEach(function (r) {
        var cols = {}, hit = 0;
        RECIPE.forEach(function (rc) {
          cols[rc.area] = [];
          Object.keys(g[r]).forEach(function (c) {
            var t = norm(g[r][c]);
            if (rc.cols.some(function (re) { return re.test(t); })) { cols[rc.area].push(+c); }
          });
          if (cols[rc.area].length) hit++;
        });
        if (hit >= 2) heads.push({ r: r, cols: cols });
      });
      if (!heads.length) continue;
      heads.forEach(function (h) {
        // 번호/이름 열: 소제목 줄 또는 바로 윗줄에서 찾기
        [h.r, h.r - 1, h.r - 2].forEach(function (rr) {
          Object.keys(g[rr] || {}).forEach(function (c) {
            var t = norm(g[rr][c]);
            if (h.numCol == null && /^번\s*호$/.test(t)) h.numCol = +c;
            if (h.nameCol == null && /korean\s*name|^이\s*름$|^성\s*명$/i.test(t)) h.nameCol = +c;
          });
        });
        // 결과 열 위치: 이미 Reading/Speaking.. 제목이 있으면 그 자리, 없으면 제목 줄 마지막 칸 다음
        var maxScoreCol = 0; RECIPE.forEach(function (rc) { h.cols[rc.area].forEach(function (c) { maxScoreCol = Math.max(maxScoreCol, c); }); });
        var lastHead = 0;
        [h.r, h.r - 1].forEach(function (rr) { Object.keys(g[rr] || {}).forEach(function (c) { if (norm(g[rr][c])) lastHead = Math.max(lastHead, +c); }); });
        h.outCols = {};
        RECIPE.forEach(function (rc, i) {
          var found = Object.keys(g[h.r]).filter(function (c) { return +c > maxScoreCol && norm(g[h.r][c]).toLowerCase() === rc.area.toLowerCase(); })[0];
          h.outCols[rc.area] = found ? +found : null;
        });
        var allFound = RECIPE.every(function (rc) { return h.outCols[rc.area]; });
        if (!allFound) RECIPE.forEach(function (rc, i) { h.outCols[rc.area] = lastHead + 1 + i; });
      });
      if (heads.some(function (h) { return h.numCol == null || h.nameCol == null; })) continue;
      var students = [], blanks = [];
      rows.forEach(function (r) {
        var h = heads.filter(function (x) { return x.r < r; }).pop();
        if (!h || heads.some(function (x) { return x.r === r || x.r - 1 === r; })) return;
        var no = g[r][h.numCol], nm = norm(g[r][h.nameCol]);
        if (typeof no !== 'number' || !nm) { if (typeof no === 'number') blanks.push(no); return; }
        var sc = {};
        RECIPE.forEach(function (rc) {
          var vals = h.cols[rc.area].map(function (c) { return g[r][c]; });
          sc[rc.area] = vals.length && vals.every(function (v) { return typeof v === 'number'; })
            ? Math.round(vals.reduce(function (a, b) { return a + b; }, 0) / vals.length * 100) / 100 : null;
        });
        students.push({ no: no, name: nm, row: r, head: h, scores: sc });
      });
      return { sheet: sheets[si], heads: heads, students: students, emptyNos: blanks };
    }
    throw new Error('점수 표를 찾지 못했습니다. (Speaking(100), Final exam(100) 같은 제목 줄이 있어야 합니다)');
  }

  // ───────────────────────── 나이스 화면 읽기/쓰기 ─────────────────────────
  // 지금 화면에 보이는 영역별/교과별 평가 탭만 대상으로 한다 (숨겨진 탭에 잘못 넣지 않도록)
  function neisFind() {
    var P = window.cpr && cpr.core && cpr.core.Platform && cpr.core.Platform.INSTANCE;
    if (!P) return { reason: '이 탭은 나이스 화면이 아닙니다. 나이스 교과평가 화면이 열린 탭에서 실행하세요.' };
    var apps = P.getAllRunningAppInstances();
    var all = apps.filter(function (a) { return /els_scres00_m0[12]/.test(a.id); }).map(function (a) {
      var ds = null, show = true;
      try { ds = a.lookup('dsMain'); } catch (e) {}
      try { show = a.getContainer().isShowing(); } catch (e) {}
      return { app: a, ds: ds, n: ds ? ds.getRowCount() : 0, show: show, tab: /m01/.test(a.id) ? '영역별 평가' : '교과별 평가' };
    });
    var shown = all.filter(function (x) { return x.show; });
    var c = shown.filter(function (x) { return x.n > 0; })[0];
    if (c) return { ctx: { app: c.app, ds: c.ds, ev: c.app.lookup('dsEvlCn'), tab: c.tab } };
    if (shown.length) return { reason: shown[0].tab + ' 탭의 조회 결과가 없습니다(0명). 학년·반·교과를 확인하고 조회하세요.' };
    var onSubject = apps.some(function (a) { return /els_scres00_m00/.test(a.id); });
    if (onSubject) return { reason: '영역별 평가 또는 교과별 평가 탭을 열고 조회하세요. (성취기준별 평가 탭은 지원하지 않습니다)' };
    return { reason: '나이스 학생평가 > 교과평가 화면이 열려 있지 않습니다.' };
  }
  function neisCtx() { return neisFind().ctx || null; }
  function neisInfo() {
    var c = neisCtx(); if (!c) return null;
    var ds = c.ds, ev = c.ev, els = {}, order = [], studs = {};
    for (var i = 0; i < ds.getRowCount(); i++) {
      var key = ds.getValue(i, 'sccesCtrCd') + '|' + ds.getValue(i, 'sccesCtrSn');
      if (!els[key]) { els[key] = { key: key, relm: ds.getValue(i, 'relmNm'), goal: norm(ds.getValue(i, 'lrnGoalCn')), levels: [] }; order.push(key); }
      studs[ds.getValue(i, 'clsNo')] = ds.getValue(i, 'stuFlnm');
    }
    for (var j = 0; j < ev.getRowCount(); j++) {
      var k = ev.getValue(j, 'sccesCtrCd') + '|' + ev.getValue(j, 'sccesCtrSn');
      var nm = ev.getValue(j, 'evlCtrNm'), cd = ev.getValue(j, 'evlCtrCd');
      if (els[k] && String(cd).trim() !== '99' && nm !== '임의입력') els[k].levels.push({ name: nm, code: cd });
    }
    order.forEach(function (k) { els[k].levels.sort(function (a, b) { return String(a.code).localeCompare(String(b.code)); }); });
    var r0 = ds.getRowData(0);
    return { screen: c.app.id, tab: c.tab, grd: r0.grd, cls: String(r0.clsCd).replace(/^0+/, ''), sbjt: r0.sbjtNm, sbjtCd: r0.sbjtCd, elements: order.map(function (k) { return els[k]; }), students: studs };
  }
  function neisApply(map, finalOf) {
    var c = neisCtx(); if (!c) throw new Error('조회된 교과평가 화면이 없습니다.');
    var ds = c.ds, ev = c.ev, done = 0, skipped = [];
    ds.setEventActivation(false);
    try {
      for (var i = 0; i < ds.getRowCount(); i++) {
        var key = ds.getValue(i, 'sccesCtrCd') + '|' + ds.getValue(i, 'sccesCtrSn'), area = map[key];
        if (!area) continue;
        var no = ds.getValue(i, 'clsNo'), lv = finalOf(no, area);
        if (!lv) { skipped.push(no + '번 ' + ds.getValue(i, 'stuFlnm')); continue; }
        var hit = null;
        for (var j = 0; j < ev.getRowCount(); j++) {
          if (ev.getValue(j, 'sccesCtrCd') + '|' + ev.getValue(j, 'sccesCtrSn') === key && ev.getValue(j, 'evlCtrNm') === lv) { hit = j; break; }
        }
        if (hit == null) { skipped.push(no + '번 (' + lv + ' 단계 없음)'); continue; }
        ds.setValue(i, 'evlCtrCd', ev.getValue(hit, 'evlCtrCd'));
        ds.setValue(i, 'evlCtrNm', ev.getValue(hit, 'evlCtrNm'));
        ds.setValue(i, 'evlCtrCn', ev.getValue(hit, 'evlCtrCn'));
        done++;
      }
    } finally {
      ds.setEventActivation(true);
      try { ds.refresh(); } catch (e) {}
      try { var gr = c.app.lookup('grdMain'); if (gr) gr.redraw(); } catch (e) {}
    }
    var mod = 0; for (var k = 0; k < ds.getRowCount(); k++) if (ds.getRowStateString(k) === 'U') mod++;
    return { done: done, modified: mod, skipped: skipped };
  }

  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
  function visibleTextClick(text) {
    var el = Array.prototype.filter.call(document.querySelectorAll('a,div,span,li'), function (e) { var r = e.getBoundingClientRect(); return e.childElementCount === 0 && norm(e.textContent) === text && r.width > 0 && r.height > 0; })[0];
    if (!el) return false;
    ['mousedown', 'mouseup', 'click'].forEach(function (t) { el.dispatchEvent(new MouseEvent(t, { bubbles: true })); });
    return true;
  }
  function menuClick(selector, re) {
    var el = Array.prototype.filter.call(document.querySelectorAll(selector), function (e) { var r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0 && re.test(norm(e.innerText || e.textContent)); })[0];
    if (!el) return false;
    el.click(); return true;
  }
  function neisAlertText() {
    return Array.prototype.map.call(document.querySelectorAll('.cl-dialog.modal-msg'), function (e) { var r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0 ? norm(e.innerText) : ''; }).filter(Boolean)[0] || '';
  }
  function dismissNeisAlert() {
    var a = cpr.core.Platform.INSTANCE.getAllRunningAppInstances().filter(function (x) { return /^app\/cmn\/alert/.test(x.id); })[0];
    var b = a && a.lookup('btnConfirm'); if (!b) return false; b.click(); return true;
  }
  async function dismissInitialPermissionAlert() {
    var t = neisAlertText();
    if (!/자료권한이 존재하지 않습니다/.test(t) || !/CM000/.test(t)) return false;
    if (!dismissNeisAlert()) return false;
    for (var i = 0; i < 15 && neisAlertText(); i++) await sleep(200);
    return !neisAlertText();
  }
  function checkNeisAlert(step) {
    var t = neisAlertText();
    if (t) throw new Error('나이스 알림이 떠서 멈췄습니다' + (step ? ' (' + step + ')' : '') + ': ' + t.replace(/^알림\s*/, '').replace(/\s*확인$/, '') + ' — 알림을 닫고 다시 눌러주세요.');
  }
  function authCombos() {
    var P = cpr.core.Platform.INSTANCE;
    var cs = P.getAllRunningAppInstances().filter(function (a) { if (!/udcSwcAuth/.test(a.id)) return false; try { return a.getContainer().isShowing(); } catch (e) { return false; } })
      .map(function (a) { var c = null; try { c = a.lookup('cmbUdcAuth'); } catch (e) {} return c ? { c: c, items: c.getItems().map(function (x) { return { label: String(x.label), value: String(x.value) }; }) } : null; }).filter(Boolean);
    return {
      year: cs.filter(function (x) { return x.items.some(function (i) { return /^\d{4}$/.test(i.value); }); })[0],
      sem: cs.filter(function (x) { return x.items.length && x.items.every(function (i) { return /^[12]$/.test(i.value); }); })[0],
      grade: cs.filter(function (x) { return x.items.length && x.items.every(function (i) { return /^[1-6]$/.test(i.value); }) && !x.items.every(function (i) { return /^[12]$/.test(i.value); }); })[0],
      cls: cs.filter(function (x) { return x.items.length && x.items.every(function (i) { return /^\d{2}$/.test(i.value); }); })[0],
      sbjt: cs.filter(function (x) { return x.items.some(function (i) { return /:/.test(i.value); }); })[0]
    };
  }
  async function ensureSubjectScreen() {
    function m02() { return cpr.core.Platform.INSTANCE.getAllRunningAppInstances().filter(function (a) { if (!/els_scres00_m02/.test(a.id)) return false; try { return a.getContainer().isShowing() && a.lookup('dsMain') && a.lookup('btnSearch'); } catch (e) { return false; } })[0]; }
    if (m02()) return m02();
    function m00Showing() { return cpr.core.Platform.INSTANCE.getAllRunningAppInstances().some(function (a) { if (!/els_scres00_m00/.test(a.id)) return false; try { return a.getContainer().isShowing(); } catch (e) { return false; } }); }
    var openTab = Array.prototype.filter.call(document.querySelectorAll('[role=tab]'), function (e) { return /^교과평가(?:\s|$)/.test(norm(e.innerText)); })[0];
    if (openTab && !m00Showing()) { openTab.click(); for (var t = 0; t < 20 && !m00Showing(); t++) await sleep(250); }
    if (!m00Showing()) {
      if (!menuClick('a.cl-sidenavigation-item', /^교과평가(?:\s|$)/) && !visibleTextClick('교과평가')) {
        menuClick('a.cl-navigationbar-content', /영어교육-성적/); await sleep(700);
        menuClick('a.cl-navigationbar-listitem', /^학생평가(?:\s|$)/); await sleep(900);
        if (!menuClick('a.cl-sidenavigation-item', /^교과평가(?:\s|$)/)) visibleTextClick('교과평가');
      }
      for (var i = 0; i < 30 && !m00Showing(); i++) await sleep(300);
      checkNeisAlert('교과평가 열기');
    }
    visibleTextClick('교과별 평가');
    for (var j = 0; j < 30 && !m02(); j++) await sleep(300);
    await sleep(500);
    await dismissInitialPermissionAlert();
    checkNeisAlert('교과별 평가 탭');
    if (!m02()) throw new Error('교과평가 > 교과별 평가 화면을 열지 못했습니다. 메뉴에서 직접 연 뒤 다시 눌러주세요.');
    return m02();
  }
  function modifiedRows() { var c = neisCtx(); if (!c) return 0; var n = 0; for (var i = 0; i < c.ds.getRowCount(); i++) if (c.ds.getRowStateString(i) === 'U') n++; return n; }
  async function goClass(cls) {
    var m = /^(\d+)-(\d+)$/.exec(cls); if (!m) throw new Error('반 표기를 읽지 못했습니다: ' + cls);
    if (modifiedRows() && !confirm('지금 화면에 저장하지 않은 입력값이 있습니다. 다른 반을 조회하면 사라집니다.\n계속할까요?')) return false;
    await dismissInitialPermissionAlert();
    checkNeisAlert('시작 전');
    var app = await ensureSubjectScreen(), f = authCombos();
    if (!f.grade || !f.cls || !f.sbjt) throw new Error('학년·반·교과 선택칸을 찾지 못했습니다.');
    if (!f.grade.items.some(function (i) { return i.value === m[1]; })) throw new Error('나이스에서 ' + m[1] + '학년을 선택할 수 없습니다.');
    f.grade.c.selectItemByValue(m[1]); await sleep(1200); checkNeisAlert('학년 선택'); f = authCombos();
    var clsCode = ('0' + m[2]).slice(-2);
    if (!f.cls || !f.cls.items.some(function (i) { return i.value === clsCode; })) throw new Error('나이스에서 ' + cls + '반을 선택할 수 없습니다.');
    f.cls.c.selectItemByValue(clsCode); await sleep(900); checkNeisAlert('반 선택'); f = authCombos();
    var eng = f.sbjt.items.filter(function (i) { return /영어/.test(i.label); })[0]; if (!eng) throw new Error(cls + '반 교과 목록에 영어가 없습니다.');
    f.sbjt.c.selectItemByValue(eng.value); await sleep(700); checkNeisAlert('교과 선택');
    var ds = app.lookup('dsMain');
    function loaded() { return ds.getRowCount() && String(ds.getValue(0, 'grd')) === m[1] && String(ds.getValue(0, 'clsCd')) === clsCode && /영어/.test(ds.getValue(0, 'sbjtNm')); }
    app.lookup('btnSearch').click();
    for (var i = 0; i < 70 && !loaded() && !neisAlertText(); i++) await sleep(300);
    await sleep(500); checkNeisAlert('조회');
    if (!ds.getRowCount()) throw new Error(cls + '반 조회 결과가 없습니다.');
    if (!loaded()) throw new Error('조회 후 화면이 ' + cls + '반 영어로 바뀌지 않았습니다. 나이스 알림창이 떠 있는지 확인하세요.');
    return true;
  }
  function validationReport(ms) {
    var n = S.neis, errs = [], warns = [], d = S.data;
    if (!n) return { errs: ['나이스 화면을 찾지 못했습니다.'], warns: warns };
    var vals = Object.keys(S.map).map(function (k) { return S.map[k]; }).filter(Boolean);
    RECIPE.forEach(function (rc) { var c = vals.filter(function (v) { return v === rc.area; }).length; if (c !== 1) errs.push(rc.area + ' 연결이 ' + c + '개입니다.'); });
    n.elements.forEach(function (el) { var want = inferArea(el), got = S.map[el.key]; if (!want) errs.push('평가요소 영역을 판단할 수 없습니다: ' + el.goal); else if (got !== want) errs.push('평가요소 연결 오류: "' + el.goal + '"은(는) ' + want + '여야 하는데 ' + (got || '연결 없음') + '입니다.'); });
    if (vals.length !== n.elements.length) errs.push('연결되지 않은 나이스 평가요소가 있습니다.');
    ms.forEach(function (m) {
      var ek = 'excel:' + (m.s.key || m.s.no);
      if (m.st === 'nameDiff') errs.push(m.s.cls + ' ' + m.s.no + '번 이름 불일치: 엑셀 ' + m.s.name + ', 나이스 ' + n.students[m.s.no]);
      else if (m.st === 'notInNeis') { if (S.exceptions[ek] === 'exclude') warns.push('입력 제외: ' + m.s.cls + ' ' + m.s.no + '번 ' + m.s.name + ' (엑셀에만 있음)'); else errs.push(m.s.cls + ' ' + m.s.no + '번 ' + m.s.name + '이(가) 나이스에 없습니다.'); }
    });
    var inX = {}; ms.forEach(function (m) { inX[m.s.no] = 1; });
    var noScore = d.integrated ? d.noScore.filter(function (x) { return x.indexOf(n.grd + '-' + n.cls + ' ') === 0; }) : [];
    Object.keys(n.students).forEach(function (no) {
      if (inX[no]) return;
      var txt = n.grd + '-' + n.cls + ' ' + no + '번 ' + n.students[no], nk = 'neis:' + n.grd + '-' + n.cls + '-' + no;
      if (noScore.some(function (x) { return x.indexOf(n.grd + '-' + n.cls + ' ' + no + '번 ') === 0; })) warns.push('점수 없음(입력 안 함): ' + txt);
      else if (S.exceptions[nk] === 'skip') warns.push('입력 안 함: ' + txt + ' (나이스에만 있음)');
      else errs.push('엑셀에 없는 나이스 학생: ' + txt);
    });
    ms.forEach(function (m) { RECIPE.forEach(function (rc) { if (m.s.scores[rc.area] == null) errs.push(m.s.cls + ' ' + m.s.no + '번 ' + rc.area + ' 점수 없음'); }); });
    if (!cutsReady()) errs.push('기준값이 비어 있거나 순서가 맞지 않습니다.');
    return { errs: errs, warns: warns };
  }
  function verifyNeis(map, finalOf) {
    var c = neisCtx(), ds = c.ds, bad = [], expected = 0, ok = 0;
    for (var i = 0; i < ds.getRowCount(); i++) {
      var key = ds.getValue(i, 'sccesCtrCd') + '|' + ds.getValue(i, 'sccesCtrSn'), area = map[key]; if (!area) continue;
      var want = finalOf(ds.getValue(i, 'clsNo'), area); if (!want) continue; expected++;
      if (ds.getValue(i, 'evlCtrNm') === want && ds.getValue(i, 'evlCtrCd') && ds.getValue(i, 'evlCtrCn')) ok++; else bad.push(ds.getValue(i, 'clsNo') + '번 ' + ds.getValue(i, 'stuFlnm') + ' ' + area);
    }
    return { expected: expected, ok: ok, bad: bad };
  }

  // ───────────────────────── 상태 ─────────────────────────
  var S = {
    file: null, bytes: null, password: '', wb: null, data: null, neis: null,
    map: {}, levels: {}, cut: {}, cutTouched: {}, override: {}, classProgress: {}, exceptions: {}
  };
  function loadJSON(k, d) { try { return JSON.parse(localStorage.getItem(k)) || d; } catch (e) { return d; } }
  function saveJSON(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} }

  function levelsFor(area) {
    if (S.neis) {
      var el = S.neis.elements.filter(function (e) { return S.map[e.key] === area; })[0];
      if (el && el.levels.length) return el.levels.map(function (l) { return l.name; });
    }
    return DEFAULT_LEVELS;
  }
  function autoLevel(area, score) {
    if (score == null) return null;
    var lv = S.levels[area], cut = S.cut[area] || [];
    for (var i = 0; i < lv.length - 1; i++) { var t = cut[i]; if (t === '' || t == null || isNaN(t)) return null; if (score >= +t) return lv[i]; }
    return lv[lv.length - 1];
  }
  function finalLevel(stu, area) {
    var k = stu.key || stu.no, o = S.override[k] && S.override[k][area];
    return o || autoLevel(area, stu.scores[area]);
  }
  function cutsReady() {
    return RECIPE.every(function (rc) {
      var lv = S.levels[rc.area], cut = S.cut[rc.area] || [];
      for (var i = 0; i < lv.length - 1; i++) if (cut[i] === '' || cut[i] == null || isNaN(cut[i])) return false;
      for (var j = 1; j < lv.length - 1; j++) if (+cut[j] > +cut[j - 1]) return false;
      return true;
    });
  }
  function matchedStudents() {
    // 나이스와 번호/이름 대조
    var list = S.data.students;
    if (S.data.integrated) list = S.neis ? list.filter(function (s) { return s.grd === String(S.neis.grd) && s.classNo === String(S.neis.cls); }) : [];
    return list.map(function (s) {
      var st = 'ok';
      if (S.neis) {
        var nn = S.neis.students[s.no];
        if (nn == null) st = 'notInNeis'; else if (nameKey(nn) !== nameKey(s.name)) st = 'nameDiff';
      }
      return { s: s, st: st };
    });
  }

  // ───────────────────────── UI ─────────────────────────
  var host = document.createElement('div'); host.id = 'ngh-host';
  host.style.cssText = 'position:fixed;left:0;top:0;z-index:2147483646;';
  document.body.appendChild(host);
  var root = host.attachShadow({ mode: 'open' });
  root.innerHTML = '<style>' +
    ':host{all:initial}*{box-sizing:border-box;font-family:"Malgun Gothic","맑은 고딕",sans-serif}' +
    '.p,.p *{line-height:1.45}button{white-space:nowrap}.p{overflow:auto;min-width:340px;min-height:120px;background:#fff;border:1px solid #9bb3d6;border-radius:10px;box-shadow:0 8px 30px rgba(0,0,0,.25);font-size:13px;color:#222}' +
    '.hd{position:sticky;top:0;background:#2f6fd6;color:#fff;padding:10px 14px;display:flex;justify-content:space-between;align-items:center;font-weight:bold;font-size:14px;z-index:2}' +
    '.hd button{background:transparent;border:0;color:#fff;font-size:18px;cursor:pointer;margin-left:6px;width:26px}.hd{cursor:move;user-select:none}' +
    '.p.min{height:auto!important;min-height:0;overflow:hidden}.p.min #body,.p.min #mode{display:none}' +
    '.mb{display:flex;border-bottom:1px solid #d6dfec}.mb button{flex:1;border:0;background:#eef3fa;padding:8px 4px;font-size:12px;cursor:pointer;color:#557}.mb button.on{background:#fff;color:#2f6fd6;font-weight:bold;box-shadow:inset 0 -2px 0 #2f6fd6}' +
    '.grip{position:absolute;right:1px;bottom:1px;width:18px;height:18px;cursor:nwse-resize;z-index:5;border-bottom-right-radius:10px;' +
    'background:linear-gradient(135deg,transparent 0 45%,#7f9cc8 45% 52%,transparent 52% 64%,#7f9cc8 64% 71%,transparent 71% 83%,#7f9cc8 83% 90%,transparent 90%)}.grip.hide{display:none}' +
    'button.lk{background:none;border:1px solid #9bb3d6;color:#2f6fd6;border-radius:4px;font-size:11px;padding:1px 6px;cursor:pointer;margin-left:6px}' +
    '.sec{padding:12px 14px;border-bottom:1px solid #e6ebf3}.sec h3{margin:0 0 8px;font-size:13px;color:#2f6fd6}' +
    '.drop{border:2px dashed #9bb3d6;border-radius:8px;padding:16px;text-align:center;color:#557;cursor:pointer;background:#f6f9ff}.drop.on{background:#e3edff}' +
    'input[type=password],input[type=number]{border:1px solid #b8c4d6;border-radius:5px;padding:5px 6px;font-size:13px}' +
    'input[type=number]{width:70px;text-align:right}input.stale{background:#fff4c2}' +
    'button.b{background:#2f6fd6;color:#fff;border:0;border-radius:6px;padding:7px 12px;font-size:13px;cursor:pointer;font-weight:bold}button.b:disabled{background:#aab6c8;cursor:default}' +
    'button.g{background:#fff;color:#2f6fd6;border:1px solid #2f6fd6}' +
    'table{border-collapse:collapse;width:100%}td,th{border:1px solid #e1e6ee;padding:4px 5px;text-align:center;font-size:12px}th{background:#f1f5fb}' +
    '.err{color:#c0392b}.warn{color:#b36b00}.ok{color:#1e8449}.muted{color:#778}.small{font-size:11px}' +
    'select{font-size:12px;border:1px solid #c5cfdd;border-radius:4px;padding:1px 2px}select.ov{background:#ffe3e3;font-weight:bold}' +
    'td.edge{background:#fff4c2}tr.bad td{background:#fdecec}.cnt{font-size:11px;color:#446;white-space:nowrap}' +
    '.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.btns{display:flex;gap:8px;justify-content:flex-end;padding:12px 14px;position:sticky;bottom:0;background:#fff;border-top:1px solid #e6ebf3}' +
    '</style><div class="p" id="p"><div class="hd" id="hd" title="끌어서 옮기기 · 더블클릭하면 접기/펼치기"><span>성적 입력 도우미 <span class="small">v' + VERSION + '</span></span><span><button id="mn" title="접기">–</button><button id="x" title="닫기">×</button></span></div><div id="mode"></div><div id="body"></div></div><div class="grip" id="grip" title="끌어서 크기 조절"></div>';
  var $ = function (id) { return root.getElementById(id); };

  // ── 떠 있는 창: 이동 / 크기 조절 / 접기 / 위치 기억 ──
  var PW = $('p');
  var W = Object.assign({ x: Math.max(0, innerWidth - 544), y: 12, w: 520, h: Math.min(innerHeight - 24, 760), min: false }, loadJSON(LS_WIN, {}));
  var saveT = null;
  function saveW() { if (!host.isConnected) return; clearTimeout(saveT); saveT = setTimeout(function () { saveJSON(LS_WIN, W); }, 300); }
  function applyW() {
    W.w = Math.max(340, Math.min(W.w, innerWidth));
    W.x = Math.min(Math.max(0, W.x), Math.max(0, innerWidth - 120));
    W.y = Math.min(Math.max(0, W.y), Math.max(0, innerHeight - 44));
    host.style.left = W.x + 'px'; host.style.top = W.y + 'px';
    PW.style.width = W.w + 'px';
    if (W.min) { PW.classList.add('min'); PW.style.height = ''; }
    else { PW.classList.remove('min'); PW.style.height = Math.max(120, Math.min(W.h, innerHeight - W.y - 4)) + 'px'; }
    $('mn').textContent = W.min ? '□' : '–'; $('mn').title = W.min ? '펼치기' : '접기';
    $('grip').className = W.min ? 'grip hide' : 'grip';
  }
  $('grip').addEventListener('mousedown', function (e) {
    if (e.button !== 0) return;
    e.preventDefault();
    var sx = e.clientX, sy = e.clientY, ow = W.w, oh = Math.min(W.h, innerHeight - W.y - 4);
    function mv(ev) { W.w = Math.max(340, ow + ev.clientX - sx); W.h = Math.max(120, Math.min(innerHeight - W.y - 4, oh + ev.clientY - sy)); applyWSafe(); }
    function up() { window.removeEventListener('mousemove', mv, true); window.removeEventListener('mouseup', up, true); saveW(); }
    window.addEventListener('mousemove', mv, true); window.addEventListener('mouseup', up, true);
  });
  var applying = false;
  new ResizeObserver(function () {
    if (W.min || applying) return;
    var r = PW.getBoundingClientRect();
    if (Math.abs(r.width - W.w) > 1 || Math.abs(r.height - W.h) > 1) { W.w = Math.round(r.width); W.h = Math.round(r.height); saveW(); }
  }).observe(PW);
  function applyWSafe() { if (!host.isConnected) { window.removeEventListener('resize', applyWSafe); return; } applying = true; applyW(); setTimeout(function () { applying = false; }, 0); }
  $('hd').addEventListener('mousedown', function (e) {
    if (e.button !== 0 || (e.target.closest && e.target.closest('button'))) return;
    e.preventDefault();
    var sx = e.clientX, sy = e.clientY, ox = W.x, oy = W.y;
    function mv(ev) { W.x = ox + ev.clientX - sx; W.y = oy + ev.clientY - sy; applyWSafe(); }
    function up() { window.removeEventListener('mousemove', mv, true); window.removeEventListener('mouseup', up, true); saveW(); }
    window.addEventListener('mousemove', mv, true); window.addEventListener('mouseup', up, true);
  });
  function toggleMin() { W.min = !W.min; applyWSafe(); saveW(); }
  $('hd').addEventListener('dblclick', function (e) { if (!(e.target.closest && e.target.closest('button'))) toggleMin(); });
  $('mn').onclick = toggleMin;
  window.addEventListener('resize', applyWSafe);
  $('x').onclick = function () { window.removeEventListener('resize', applyWSafe); host.remove(); };
  applyWSafe();
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }

  function renderOpen(msg, cls) {
    $('body').innerHTML =
      '<div class="sec"><h3>1. 성적 엑셀 파일</h3>' +
      '<div class="drop" id="drop">' + (S.file ? '<b>' + esc(S.file.name) + '</b><br><span class="small muted">다른 파일은 다시 끌어다 놓기</span>' : '여기에 엑셀 파일을 끌어다 놓거나 <u>클릭해서 선택</u>') + '</div>' +
      '<input type="file" id="fi" accept=".xlsx" style="display:none">' +
      (S.file ? '<div class="row" style="margin-top:10px"><span>비밀번호</span><input type="password" id="pw" placeholder="암호가 없으면 비워두기" autocomplete="off"><button class="b" id="open">열기</button></div>' : '') +
      '<div id="msg" class="' + (cls || '') + '" style="margin-top:8px">' + (msg || '') + '</div></div>';
    var drop = $('drop'), fi = $('fi');
    drop.onclick = function () { fi.click(); };
    drop.ondragover = function (e) { e.preventDefault(); drop.classList.add('on'); };
    drop.ondragleave = function () { drop.classList.remove('on'); };
    drop.ondrop = function (e) { e.preventDefault(); drop.classList.remove('on'); if (e.dataTransfer.files[0]) pick(e.dataTransfer.files[0]); };
    fi.onchange = function () { if (fi.files[0]) pick(fi.files[0]); };
    if ($('open')) { $('open').onclick = doOpen; $('pw').onkeydown = function (e) { if (e.key === 'Enter') doOpen(); }; $('pw').focus(); }
  }
  async function pick(f) { S.file = f; S.bytes = new Uint8Array(await f.arrayBuffer()); renderOpen(); }
  async function doOpen() {
    var pw = $('pw').value; $('open').disabled = true; $('msg').className = 'muted'; $('msg').textContent = '여는 중… (암호 해제에 몇 초 걸립니다)';
    try {
      S.wb = await NGH.openWorkbookBytes(S.bytes, pw);
      S.password = S.wb.encrypted ? pw : '';
      S.data = extract(S.wb);
      S.neis = null; refreshNeis();
      setupState();
      renderMain();
    } catch (e) {
      renderOpen(esc(e.message), 'err');
    }
  }

  // 나이스 화면을 다시 확인. 화면(탭·학년·반·교과·평가요소)이 바뀌었으면 true
  function neisSig(n) { return n ? [n.screen, n.grd, n.cls, n.sbjtCd, n.elements.map(function (e) { return e.key; }).join(',')].join('|') : ''; }
  function refreshNeis() {
    var f = neisFind(), info = null;
    if (f.ctx) { try { info = neisInfo(); } catch (e) { f.reason = '나이스 화면을 읽지 못했습니다: ' + e.message; } }
    S.neisReason = info ? '' : f.reason;
    var changed = neisSig(info) !== neisSig(S.neis);
    if (changed && S.neis && info && (S.neis.grd !== info.grd || S.neis.cls !== info.cls)) S.override = {};
    S.neis = info;
    if (changed && S.data) setupMapLevels();
    return changed;
  }
  function wake() {
    host.style.display = '';
    if (W.min) { W.min = false; saveW(); }
    applyWSafe();
    var sm = screenMode();
    if (sm && sm !== MODE) { setMode(sm); return; }
    if (MODE === 'op') { var oc = opRefresh(); opRender(); if (oc) $('st').innerHTML = '<span class="warn">나이스 화면을 다시 불러왔습니다.</span>'; return; }
    if (S.data) { var ch = refreshNeis(); renderMain(); if (ch) $('st').innerHTML = '<span class="warn">나이스 화면을 다시 불러왔습니다. 연결과 기준값을 확인하세요.</span>'; }
  }
  // ── 모드: 단계 입력(교과평가) / 평어 입력(학기말종합의견) ──
  var MODE = 'grade';
  function screenMode() {
    var P = window.cpr && cpr.core && cpr.core.Platform && cpr.core.Platform.INSTANCE; if (!P) return null;
    var vis = P.getAllRunningAppInstances().filter(function (a) { try { return a.getContainer().isShowing(); } catch (e) { return false; } }).map(function (a) { return a.id; });
    if (vis.some(function (id) { return /els_scres10_m00/.test(id); })) return 'op';
    if (vis.some(function (id) { return /els_scres00_m0[12]/.test(id); })) return 'grade';
    return null;
  }
  function renderModeBar() {
    $('mode').innerHTML = '<div class="mb"><button data-m="grade" class="' + (MODE === 'grade' ? 'on' : '') + '">단계 입력 (교과평가)</button><button data-m="op" class="' + (MODE === 'op' ? 'on' : '') + '">평어 입력 (학기말종합의견)</button></div>';
    Array.prototype.forEach.call(root.querySelectorAll('[data-m]'), function (b) { b.onclick = function () { setMode(b.dataset.m); }; });
  }
  function setMode(m) {
    MODE = m; renderModeBar();
    if (m === 'op') { opRefresh(); opRender(); }
    else if (S.data) { refreshNeis(); renderMain(); }
    else renderOpen();
  }
  function setupState() {
    S.override = {}; S.cutTouched = {}; S.exceptions = {};
    setupMapLevels();
  }
  function inferArea(el) {
    var t = (el.goal || '') + ' ' + (el.relm || '');
    if (/읽/.test(t)) return 'Reading';
    if (/듣/.test(t)) return 'Listening';
    if (/쓰기|쓰는|문장\s*쓰/.test(t)) return 'Writing';
    if (/말하|말하기|활동/.test(t)) return 'Speaking';
    return '';
  }
  function setupMapLevels() {
    S.map = {};
    if (S.neis && S.data && S.data.integrated) {
      S.neis.elements.forEach(function (el) { S.map[el.key] = inferArea(el); });
    } else if (S.neis) {
      var saved = loadJSON(LS_MAP + S.neis.sbjtCd + '.' + S.neis.grd, {});
      S.neis.elements.forEach(function (el) {
        if (saved[el.key] !== undefined) { S.map[el.key] = saved[el.key]; return; }
        var t = el.goal + ' ' + el.relm, g = '';
        RECIPE.forEach(function (rc) { if (!g && rc.neis.some(function (w) { return t.indexOf(w) >= 0; })) g = rc.area; });
        S.map[el.key] = g;
      });
    }
    var savedCut = loadJSON(LS_CUT, {});
    RECIPE.forEach(function (rc) {
      S.levels[rc.area] = levelsFor(rc.area);
      var fromFile = S.data && S.data.integrated && S.levels[rc.area].length === 3 ? S.data.cutoffs[rc.area] : null;
      var c = fromFile || savedCut[rc.area + '|' + S.levels[rc.area].join('/')];
      S.cut[rc.area] = c ? c.slice() : [];
      if (fromFile) { S.cutTouched[rc.area + '0'] = S.cutTouched[rc.area + '1'] = true; }
    });
  }

  function renderMain() {
    var d = S.data, n = S.neis, h = '';
    // 파일 요약
    var fileCls = (/\((\d+)-(\d+)\)/.exec(S.file.name) || []);
    h += '<div class="sec"><h3>1. 파일</h3><div><b>' + esc(S.file.name) + '</b> ' + (S.wb.encrypted ? '<span class="ok">(암호 해제됨)</span>' : '') + '</div>' +
      '<div class="muted small">시트 "' + esc(d.sheet.name) + '" · 학생 ' + d.students.length + '명' + (d.integrated ? ' · 정규 반배정의 새 반·새 번호로 매칭' : '') + '</div>' +
      (d.integrated && d.unmatched.length ? '<div class="err small">정규 반배정에서 못 찾은 학생: ' + esc(d.unmatched.join(', ')) + '</div>' : '') +
      (d.integrated && d.noScore.length ? '<div class="warn small">점수 없는 학생(입력 안 함): ' + esc(d.noScore.join(', ')) + '</div>' : '') +
      '<div class="muted small">점수 열: ' + RECIPE.map(function (rc) { return rc.area + ' ← ' + d.heads[0].cols[rc.area].map(NGH.colName).join('+') + (d.heads[0].cols[rc.area].length > 1 ? ' 평균' : ''); }).join(', ') + '</div>';
    if (n) {
      h += '<div class="small">나이스 화면: ' + esc(n.tab) + ' · ' + esc(n.grd) + '학년 ' + esc(n.cls) + '반 ' + esc(n.sbjt) + ' (평가요소 ' + n.elements.length + '개)<button class="lk" id="rf">나이스 다시 확인</button></div>';
      if (!d.integrated && fileCls[1] && (fileCls[1] !== String(n.grd) || fileCls[2] !== String(n.cls)))
        h += '<div class="err"><b>⚠ 파일은 ' + fileCls[1] + '-' + fileCls[2] + '반인데 나이스 화면은 ' + n.grd + '-' + n.cls + '반입니다.</b></div>';
    } else h += '<div class="warn small">나이스 입력 불가: ' + esc(S.neisReason || '교과평가 화면을 찾지 못했습니다.') + '<br>조회한 뒤 <button class="lk" id="rf">나이스 다시 확인</button> (결과 엑셀은 지금도 만들 수 있습니다)</div>';
    if (d.integrated) {
      var classes = Array.from(new Set(d.students.map(function (s) { return s.cls; }))).sort();
      var grades = Array.from(new Set(classes.map(function (x) { return x.split('-')[0]; })));
      h += '<div class="row" style="margin-top:8px"><b>반 이동</b>' + (grades.length > 1 ? '<span class="err small">학년이 섞여 있어 자동 이동을 막았습니다.</span>' :
        classes.map(function (c) { var p = S.classProgress[c]; return '<button class="lk" data-go="' + esc(c) + '">' + esc(c) + (p ? ' · ' + esc(p) : '') + '</button>'; }).join('')) + '</div>';
    }
    h += '</div>';
    // 연결
    if (n) {
      h += '<div class="sec"><h3>2. 나이스 평가요소 ↔ 엑셀 영역</h3><table><tr><th>나이스 평가요소</th><th style="width:120px">엑셀 영역</th></tr>';
      n.elements.forEach(function (el, i) {
        h += '<tr><td style="text-align:left">' + esc(el.relm) + ' · ' + esc(el.goal) + '<div class="muted small">단계: ' + el.levels.map(function (l) { return esc(l.name); }).join('/') + '</div></td><td><select data-map="' + i + '"><option value="">(입력 안 함)</option>' +
          RECIPE.map(function (rc) { return '<option' + (S.map[el.key] === rc.area ? ' selected' : '') + '>' + rc.area + '</option>'; }).join('') + '</select></td></tr>';
      });
      h += '</table></div>';
    }
    // 기준값
    h += '<div class="sec"><h3>' + (n ? 3 : 2) + '. 영역별 기준값 <span class="muted small">(점수 이상이면 그 단계)</span></h3><table id="cuts"></table>' +
      '<div class="small warn" style="margin-top:6px">노란 칸은 지난번 값입니다. 이번 기준이 맞는지 확인하세요.</div></div>';
    // 미리보기
    h += '<div class="sec"><h3>' + (n ? 4 : 3) + '. 학생별 미리보기 <span class="muted small">(단계를 바꾸면 그 학생만 직접 지정)</span></h3><div id="pv"></div></div>';
    h += '<div class="btns"><span id="st" class="small" style="margin-right:auto;align-self:center"></span>' + (n ? '<button class="b" id="ap">나이스에 입력</button>' : '') + '<button class="b g" id="dl">결과 엑셀 받기</button></div>';
    $('body').innerHTML = h;
    Array.prototype.forEach.call(root.querySelectorAll('select[data-map]'), function (sel) {
      sel.onchange = function () {
        var el = n.elements[+sel.dataset.map]; S.map[el.key] = sel.value;
        var all = loadJSON(LS_MAP + n.sbjtCd + '.' + n.grd, {}); all[el.key] = sel.value; saveJSON(LS_MAP + n.sbjtCd + '.' + n.grd, all);
        RECIPE.forEach(function (rc) { var nl = levelsFor(rc.area); if (nl.join('/') !== S.levels[rc.area].join('/')) { S.levels[rc.area] = nl; S.cut[rc.area] = []; } });
        renderCuts(); renderPreview();
      };
    });
    if ($('ap')) $('ap').onclick = doApply;
    Array.prototype.forEach.call(root.querySelectorAll('[data-go]'), function (b) {
      b.onclick = async function () {
        var cls = b.dataset.go; b.disabled = true; $('st').innerHTML = '<span class="muted">' + esc(cls) + '반으로 이동해 조회하는 중…</span>';
        try {
          var moved = await goClass(cls); if (!moved) { b.disabled = false; $('st').innerHTML = '<span class="warn">이동을 취소했습니다.</span>'; return; }
          refreshNeis(); S.classProgress[cls] = '조회됨'; renderMain();
          $('st').innerHTML = '<span class="ok">' + esc(cls) + '반 영어를 조회했습니다. 검사 결과를 확인한 뒤 나이스에 입력을 누르세요.</span>';
        } catch (e) { b.disabled = false; $('st').innerHTML = '<span class="err">' + esc(e.message) + '</span>'; }
      };
    });
    if ($('rf')) $('rf').onclick = function () {
      var ch = refreshNeis(); renderMain();
      $('st').innerHTML = S.neis ? (ch ? '<span class="warn">나이스 화면을 다시 불러왔습니다. 연결과 기준값을 확인하세요.</span>' : '<span class="ok">나이스 화면이 그대로입니다.</span>') : '<span class="err">' + esc(S.neisReason) + '</span>';
    };
    $('dl').onclick = doDownload;
    renderCuts(); renderPreview();
  }

  function counts(area) {
    var c = {}; S.levels[area].forEach(function (l) { c[l] = 0; });
    (S.data.integrated ? matchedStudents().map(function (m) { return m.s; }) : S.data.students).forEach(function (s) { var l = finalLevel(s, area); if (l && c[l] != null) c[l]++; });
    return S.levels[area].map(function (l) { return c[l]; }).join(' / ');
  }
  function renderCuts() {
    var maxLv = Math.max.apply(null, RECIPE.map(function (rc) { return S.levels[rc.area].length; }));
    var h = '';
    RECIPE.forEach(function (rc) {
      var lv = S.levels[rc.area];
      h += '<tr><th style="width:74px">' + rc.area + '</th>';
      for (var i = 0; i < maxLv - 1; i++) {
        if (i < lv.length - 1) {
          var v = S.cut[rc.area][i]; var stale = v !== undefined && v !== '' && !S.cutTouched[rc.area + i];
          h += '<td><div class="small">' + esc(lv[i]) + '</div><input type="number" step="any" data-a="' + rc.area + '" data-i="' + i + '" value="' + (v == null ? '' : v) + '"' + (stale ? ' class="stale"' : '') + '></td>';
        } else h += '<td></td>';
      }
      h += '<td><div class="small">' + esc(lv[lv.length - 1]) + '</div><span class="muted small">나머지</span></td><td class="cnt" data-cnt="' + rc.area + '">' + counts(rc.area) + '</td></tr>';
    });
    $('cuts').innerHTML = h;
    Array.prototype.forEach.call(root.querySelectorAll('#cuts input'), function (inp) {
      inp.oninput = function () {
        var a = inp.dataset.a, i = +inp.dataset.i; S.cut[a][i] = inp.value === '' ? '' : +inp.value; S.cutTouched[a + i] = true; inp.classList.remove('stale');
        var all = loadJSON(LS_CUT, {}); all[a + '|' + S.levels[a].join('/')] = S.cut[a]; saveJSON(LS_CUT, all);
        root.querySelector('[data-cnt="' + a + '"]').textContent = counts(a);
        renderPreview();
      };
    });
  }
  function isEdge(area, score) {
    var cut = S.cut[area] || []; if (score == null) return false;
    return cut.some(function (t) { return t !== '' && t != null && Math.abs(score - t) <= 1 && score < t; });
  }
  function renderPreview() {
    var ms = matchedStudents(), h = '<table><tr><th>' + (S.data.integrated ? '반-번호' : '번호') + '</th><th>이름</th>' + RECIPE.map(function (rc) { return '<th>' + rc.area + '</th>'; }).join('') + '</tr>';
    var notes = [];
    ms.forEach(function (m) {
      var s = m.s;
      h += '<tr' + (m.st !== 'ok' ? ' class="bad"' : '') + '><td>' + esc(s.cls ? s.cls + '-' + s.no : s.no) + '</td><td>' + esc(s.name) + (m.st === 'nameDiff' ? '<div class="err small">나이스: ' + esc(S.neis.students[s.no]) + '</div>' : m.st === 'notInNeis' ? '<div class="err small">나이스 명단에 없음</div>' : '') + '</td>';
      RECIPE.forEach(function (rc) {
        var sk = s.key || s.no, sc = s.scores[rc.area], auto = autoLevel(rc.area, sc), ov = S.override[sk] && S.override[sk][rc.area];
        h += '<td' + (isEdge(rc.area, sc) ? ' class="edge" title="기준까지 1점 이내"' : '') + '><div class="small muted">' + (sc == null ? '<span class="err">점수 없음</span>' : sc) + '</div>' +
          '<select data-no="' + esc(sk) + '" data-a="' + rc.area + '"' + (ov ? ' class="ov"' : '') + '><option value="">' + (auto ? esc(auto) : '-') + '</option>' +
          S.levels[rc.area].map(function (l) { return '<option' + (ov === l ? ' selected' : '') + '>' + esc(l) + '</option>'; }).join('') + '</select></td>';
      });
      h += '</tr>';
    });
    h += '</table>';
    if (S.neis) {
      var inX = {}; ms.forEach(function (m) { inX[m.s.no] = 1; });
      var miss = Object.keys(S.neis.students).filter(function (no) { return !inX[no]; });
      if (miss.length) notes.push('<div class="warn small">엑셀에 없는 나이스 학생(입력 안 함): ' + miss.map(function (no) { return no + '번 ' + esc(S.neis.students[no]); }).join(', ') + '</div>');
    }
    if (S.data.integrated && S.neis) {
      var exRows = [];
      ms.filter(function (m) { return m.st === 'notInNeis'; }).forEach(function (m) {
        var k = 'excel:' + (m.s.key || m.s.no);
        exRows.push('<tr><td>' + esc(m.s.cls + ' ' + m.s.no + '번') + '</td><td>' + esc(m.s.name) + '</td><td>엑셀에만 있음</td><td><select data-ex="' + esc(k) + '"><option value="">확인 필요</option><option value="exclude"' + (S.exceptions[k] === 'exclude' ? ' selected' : '') + '>입력 제외</option></select></td></tr>');
      });
      var inX2 = {}; ms.forEach(function (m) { inX2[m.s.no] = 1; });
      Object.keys(S.neis.students).filter(function (no) { return !inX2[no]; }).forEach(function (no) {
        var key = S.neis.grd + '-' + S.neis.cls, isNoScore = S.data.noScore.some(function (x) { return x.indexOf(key + ' ' + no + '번 ') === 0; });
        if (isNoScore) return;
        var k2 = 'neis:' + key + '-' + no;
        exRows.push('<tr><td>' + esc(key + ' ' + no + '번') + '</td><td>' + esc(S.neis.students[no]) + '</td><td>나이스에만 있음</td><td><select data-ex="' + esc(k2) + '"><option value="">확인 필요</option><option value="skip"' + (S.exceptions[k2] === 'skip' ? ' selected' : '') + '>입력 안 함</option></select></td></tr>');
      });
      if (exRows.length) notes.unshift('<div class="warn small" style="margin-top:6px"><b>확인 필요 학생</b></div><table><tr><th>반·번호</th><th>이름</th><th>상황</th><th>처리</th></tr>' + exRows.join('') + '</table>');
      var vr = validationReport(ms);
      notes.unshift('<div class="' + (vr.errs.length ? 'err' : 'ok') + ' small" style="margin:6px 0"><b>입력 전 검사: ' + (vr.errs.length ? '오류 ' + vr.errs.length + '건' : '통과') + '</b>' + (vr.errs.length ? '<br>' + vr.errs.map(esc).join('<br>') : '') + (vr.warns.length ? '<div class="warn">' + vr.warns.map(esc).join('<br>') + '</div>' : '') + '</div>');
    }
    $('pv').innerHTML = h + notes.join('');
    Array.prototype.forEach.call(root.querySelectorAll('#pv select[data-ex]'), function (sel) {
      sel.onchange = function () { if (sel.value) S.exceptions[sel.dataset.ex] = sel.value; else delete S.exceptions[sel.dataset.ex]; renderPreview(); };
    });
    Array.prototype.forEach.call(root.querySelectorAll('#pv select[data-no]'), function (sel) {
      sel.onchange = function () {
        var no = sel.dataset.no, a = sel.dataset.a; S.override[no] = S.override[no] || {};
        if (sel.value) S.override[no][a] = sel.value; else delete S.override[no][a];
        sel.className = sel.value ? 'ov' : '';
        root.querySelector('[data-cnt="' + a + '"]').textContent = counts(a);
      };
    });
    var ready = cutsReady() && !(S.data.integrated && S.neis && validationReport(ms).errs.length);
    if ($('ap')) $('ap').disabled = !ready;
    $('dl').disabled = !ready;
    $('st').innerHTML = ready ? '' : '<span class="warn">기준값을 모두 입력하세요 (위 단계일수록 큰 점수)</span>';
  }

  function doApply() {
    // 누르는 순간 나이스 화면을 다시 확인 (탭/반이 바뀌었거나 다시 조회한 경우)
    if (refreshNeis()) {
      renderMain();
      $('st').innerHTML = S.neis ? '<span class="warn">나이스 화면이 바뀌어 다시 불러왔습니다. 연결과 기준값을 확인한 뒤 다시 눌러주세요.</span>' : '<span class="err">' + esc(S.neisReason) + '</span>';
      return;
    }
    var byNo = {}; matchedStudents().forEach(function (m) { if (m.st === 'ok') byNo[m.s.no] = m.s; });
    var mapped = Object.keys(S.map).filter(function (k) { return S.map[k]; });
    if (!mapped.length) { alert('연결된 평가요소가 없습니다.'); return; }
    var fc = S.data.integrated ? null : /\((\d+)-(\d+)\)/.exec(S.file.name);
    if (fc && S.neis && (fc[1] !== String(S.neis.grd) || fc[2] !== String(S.neis.cls)) &&
        !confirm('파일은 ' + fc[1] + '-' + fc[2] + '반, 나이스 화면은 ' + S.neis.grd + '-' + S.neis.cls + '반입니다.\n그래도 입력할까요? (이름이 다른 학생은 어차피 건너뜁니다)')) return;
    try {
      var ms0 = matchedStudents();
      if (S.data.integrated) {
        var vr0 = validationReport(ms0); if (vr0.errs.length) { renderPreview(); $('st').innerHTML = '<span class="err">입력 전 검사에서 오류 ' + vr0.errs.length + '건이 있어 입력하지 않았습니다.</span>'; return; }
        var cx = neisCtx(), filled = 0; for (var q = 0; q < cx.ds.getRowCount(); q++) if (S.map[cx.ds.getValue(q, 'sccesCtrCd') + '|' + cx.ds.getValue(q, 'sccesCtrSn')] && cx.ds.getValue(q, 'evlCtrNm')) filled++;
        if (filled && !confirm('이미 단계가 들어 있는 칸이 ' + filled + '개 있습니다. 덮어쓸까요?')) return;
      }
      var finalOf = function (no, area) { var s = byNo[no]; return s ? finalLevel(s, area) : null; };
      var r = neisApply(S.map, finalOf);
      var vf = S.data.integrated ? verifyNeis(S.map, finalOf) : null;
      if (vf && (vf.bad.length || vf.expected !== vf.ok || r.done !== vf.expected)) {
        $('st').innerHTML = '<span class="err"><b>입력 후 검사 실패. 저장하지 마세요.</b> 예상 ' + vf.expected + '칸, 일치 ' + vf.ok + '칸</span>' + (vf.bad.length ? '<div class="err">' + esc(vf.bad.slice(0, 12).join(', ')) + '</div>' : '');
        if (S.neis) S.classProgress[S.neis.grd + '-' + S.neis.cls] = '검사 실패';
        return;
      }
      if (S.neis) S.classProgress[S.neis.grd + '-' + S.neis.cls] = '입력 완료(저장 전)';
      $('st').innerHTML = '<span class="ok">나이스에 ' + r.done + '칸 입력 (변경 ' + r.modified + '행).' + (vf ? ' 입력 후 검사 ' + vf.ok + '/' + vf.expected + '칸 일치.' : '') + ' 화면 확인 후 <b>저장</b>은 직접 누르세요.</span>' +
        (r.skipped.length ? '<div class="warn">건너뜀: ' + esc(Array.from(new Set(r.skipped)).join(', ')) + '</div>' : '');
      var btn = root.querySelector('[data-go="' + (S.neis.grd + '-' + S.neis.cls) + '"]'); if (btn) btn.textContent = S.neis.grd + '-' + S.neis.cls + ' · 입력 완료(저장 전)';
    } catch (e) { $('st').innerHTML = '<span class="err">' + esc(e.message) + '</span>'; }
  }

  async function doDownload() {
    $('dl').disabled = true; $('st').innerHTML = '<span class="muted">결과 파일 만드는 중…' + (S.password ? ' (암호 거는 중)' : '') + '</span>';
    try {
      var wb = { zip: { files: Object.assign({}, S.wb.zip.files), order: S.wb.zip.order.slice() }, cfbExtra: S.wb.cfbExtra };
      var d = S.data, writes = [];
      if (d.integrated) {
        var outRows = [['반', '번호', '한국어 이름', '영어 이름', '영어반'].concat(RECIPE.map(function (rc) { return rc.area + ' 점수'; })).concat(RECIPE.map(function (rc) { return rc.area + ' 평가'; }))];
        d.students.slice().sort(function (a, b) { return a.cls === b.cls ? a.no - b.no : a.cls.localeCompare(b.cls); }).forEach(function (s) {
          outRows.push([s.cls, s.no, s.name, s.eng, s.engClass].concat(RECIPE.map(function (rc) { return s.scores[rc.area]; })).concat(RECIPE.map(function (rc) { return finalLevel(s, rc.area) || ''; })));
        });
        NGH.addSheet(wb, '나이스 입력 결과', outRows);
      } else {
      d.heads.forEach(function (h) {
        RECIPE.forEach(function (rc) { writes.push({ r: h.r, c: h.outCols[rc.area], v: rc.area, styleFrom: h.cols[rc.area][0] }); });
      });
      d.students.forEach(function (s) {
        RECIPE.forEach(function (rc) { var l = finalLevel(s, rc.area); writes.push({ r: s.row, c: s.head.outCols[rc.area], v: l || '', styleFrom: s.head.nameCol }); });
      });
      NGH.writeCells(wb, d.sheet.path, writes);
      NGH.removeCalcChain(wb);
      }
      var now = new Date(), ds = now.getFullYear() + '-' + ('0' + (now.getMonth() + 1)).slice(-2) + '-' + ('0' + now.getDate()).slice(-2) + ' ' + ('0' + now.getHours()).slice(-2) + ':' + ('0' + now.getMinutes()).slice(-2);
      var rows = [['단계 기준값 기록'], ['작성', ds], ['원본 파일', S.file.name], [], ['영역', '점수 열'].concat(['단계1', '기준1', '단계2', '기준2', '단계3', '기준3', '마지막 단계'])];
      RECIPE.forEach(function (rc) {
        var lv = S.levels[rc.area], row = [rc.area, d.heads[0].cols[rc.area].map(NGH.colName).join('+') + (d.heads[0].cols[rc.area].length > 1 ? ' 평균' : '')];
        for (var i = 0; i < 3; i++) { if (i < lv.length - 1) row.push(lv[i], (i === lv.length - 2 && d.integrated ? '≥ ' : '≥ ') + S.cut[rc.area][i]); else row.push('', ''); }
        row.push(lv[lv.length - 1]); rows.push(row);
      });
      var ovs = []; Object.keys(S.override).forEach(function (no) { Object.keys(S.override[no]).forEach(function (a) { ovs.push([no, a, S.override[no][a]]); }); });
      if (ovs.length) { rows.push([], ['직접 지정한 학생'], ['번호', '영역', '단계']); ovs.forEach(function (o) { rows.push(o); }); }
      NGH.addSheet(wb, '단계기준', rows);
      var out = await NGH.saveWorkbookBytes(wb, S.password);
      var a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([out], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' }));
      a.download = S.file.name.replace(/\.xlsx$/i, '') + '_결과.xlsx';
      document.body.appendChild(a); a.click(); setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 5000);
      window.__nghLastOut = out;
      $('st').innerHTML = '<span class="ok">결과 파일을 내려받았습니다' + (S.password ? ' (같은 비밀번호로 잠김)' : '') + '.</span>';
    } catch (e) { $('st').innerHTML = '<span class="err">' + esc(e.message) + '</span>'; }
    $('dl').disabled = !cutsReady();
  }

  // ═════════════════════════ 평어 모드 (학기말종합의견) ═════════════════════════
  var LS_OPMAP = 'ngh.opmap.v1';
  var O = { pending: [], sources: [], edit: {}, pick: {}, open: {}, opt: { overwrite: false, joinLines: true }, neis: null, reason: '', progress: {}, editing: null, msg: '' };
  var ROLE_LABEL = { ign: '무시', name: '이름', cls: '반', no: '번호', op: '평어', eng: '영어반' };
  var ENG_RE = /tulip|violet|rose|daisy|lily|clover/i;

  // ── 셀 해석 ──
  function cellStr(v) { if (v == null) return ''; if (typeof v === 'number') return String(Math.round(v * 1e6) / 1e6); return String(v); }
  function parseCls(s) {
    s = norm(s); if (!s) return null; var m;
    if ((m = /^(\d)\s*학년\s*(\d{1,2})\s*반?$/.exec(s))) return { g: +m[1], c: +m[2] };
    if ((m = /^(\d)\s*[-_.]\s*(\d{1,2})$/.exec(s))) return { g: +m[1], c: +m[2] };
    if ((m = /^(\d{1,2})\s*반$/.exec(s))) return { g: null, c: +m[1] };
    if ((m = /^(\d{1,2})$/.exec(s)) && +m[1] <= 20) return { g: null, c: +m[1] };
    return null;
  }
  function hangulName(s) {
    s = norm(s); if (!s || s.length > 30) return '';
    function pick(t) {
      var runs = t.match(/[가-힣]+/g) || [];
      if (runs.length >= 2 && runs.length <= 4 && runs.every(function (r) { return r.length === 1; })) return runs.join('');
      var r = runs.filter(function (x) { return x.length >= 2 && x.length <= 5; })[0];
      return r || '';
    }
    var outside = pick(s.replace(/\(.*?\)|\[.*?\]/g, ' '));
    if (outside) return outside;
    var inner = (s.match(/\((.*?)\)/g) || []).map(function (x) { return pick(x); }).filter(Boolean)[0];
    return inner || '';
  }
  function bytesOf(t, unit) { return unit === 'utf8' || !unit ? new TextEncoder().encode(t).length : t.length; }
  function cleanText(t) {
    t = String(t || '').replace(/\u00a0/g, ' ');
    if (O.opt.joinLines) t = t.replace(/\s*\r?\n\s*/g, ' ');
    return t.replace(/[ \t]{2,}/g, ' ').trim();
  }
  function editDist(a, b) {
    if (Math.abs(a.length - b.length) > 1) return 9;
    var d = []; for (var i = 0; i <= a.length; i++) { d[i] = [i]; for (var j = 1; j <= b.length; j++) d[i][j] = i ? Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)) : j; }
    return d[a.length][b.length];
  }

  // ── 표 가져오기: 엑셀 시트 / 붙여넣기(HTML 표 또는 탭 구분) ──
  function gridToRows(g) {
    var rk = Object.keys(g).map(Number).sort(function (a, b) { return a - b; }), maxC = 0;
    rk.forEach(function (r) { Object.keys(g[r]).forEach(function (c) { if (cellStr(g[r][c]).trim()) maxC = Math.max(maxC, +c); }); });
    var rows = [];
    rk.forEach(function (r) { var row = []; for (var c = 1; c <= maxC; c++) row.push(cellStr(g[r][c])); if (row.some(function (x) { return x.trim(); })) rows.push(row); });
    return rows;
  }
  function htmlTableRows(html) {
    var doc = new DOMParser().parseFromString(html, 'text/html');
    var tables = Array.prototype.slice.call(doc.querySelectorAll('table'));
    if (!tables.length) return null;
    var t = tables.sort(function (a, b) { return b.querySelectorAll('tr').length - a.querySelectorAll('tr').length; })[0];
    var grid = [];
    Array.prototype.forEach.call(t.querySelectorAll('tr'), function (tr, ri) {
      grid[ri] = grid[ri] || []; var ci = 0;
      Array.prototype.forEach.call(tr.children, function (td) {
        if (!/^(TD|TH)$/.test(td.tagName)) return;
        while (grid[ri][ci] !== undefined) ci++;
        var c = td.cloneNode(true);
        Array.prototype.forEach.call(c.querySelectorAll('br'), function (b) { b.replaceWith('\n'); });
        Array.prototype.forEach.call(c.querySelectorAll('p,div'), function (p) { p.append('\n'); });
        var txt = c.textContent.replace(/\n+$/, '').replace(/\u00a0/g, ' ');
        var rs = +td.getAttribute('rowspan') || 1, cs = +td.getAttribute('colspan') || 1;
        for (var r = 0; r < rs; r++) for (var k = 0; k < cs; k++) { grid[ri + r] = grid[ri + r] || []; grid[ri + r][ci + k] = (k === 0) ? txt : ''; }
        ci += cs;
      });
    });
    var w = Math.max.apply(null, grid.map(function (r) { return r.length; }));
    return grid.map(function (r) { var o = []; for (var i = 0; i < w; i++) o.push(r[i] == null ? '' : r[i]); return o; }).filter(function (r) { return r.some(function (x) { return x.trim(); }); });
  }
  function tsvRows(text) {
    var rows = [], row = [], cell = '', q = false, i = 0;
    text = text.replace(/\r\n?/g, '\n');
    while (i < text.length) {
      var ch = text[i];
      if (q) { if (ch === '"') { if (text[i + 1] === '"') { cell += '"'; i++; } else q = false; } else cell += ch; }
      else if (ch === '"' && cell === '') q = true;
      else if (ch === '\t') { row.push(cell); cell = ''; }
      else if (ch === '\n') { row.push(cell); rows.push(row); row = []; cell = ''; }
      else cell += ch;
      i++;
    }
    if (cell || row.length) { row.push(cell); rows.push(row); }
    var w = Math.max.apply(null, rows.map(function (r) { return r.length; }).concat([0]));
    return rows.map(function (r) { while (r.length < w) r.push(''); return r; }).filter(function (r) { return r.some(function (x) { return x.trim(); }); });
  }

  // ── 열 역할 자동 추측 ──
  var HEAD = {
    name: /^(이름|성명|학생\s*명|학생\s*이름|학생|name|korean\s*name)$/i,
    cls: /^(반|학급|학반|학년\s*반|학년반|반\s*번호)$/i,
    no: /^(번호|번|no\.?|num(ber)?|출석\s*번호)$/i,
    op: /(평어|의견|종합|평가\s*내용|코멘트|comment|특기|소견|평가\s*결과)/i,
    eng: /(영어\s*반|레벨|level)/i
  };
  function detectTable(rows) {
    var head = -1;
    for (var r = 0; r < Math.min(8, rows.length); r++) {
      var hits = rows[r].filter(function (c) { var t = norm(c); return t && Object.keys(HEAD).some(function (k) { return HEAD[k].test(t); }) || /^class$/i.test(t); }).length;
      if (hits >= 1 && rows[r].filter(function (c) { return norm(c); }).length >= 2) { head = r; break; }
    }
    var data = rows.slice(head + 1), n = rows[0] ? rows[0].length : 0, roles = [], st = [];
    for (var c = 0; c < n; c++) {
      var vals = data.map(function (r) { return norm(r[c]); }), nb = vals.filter(Boolean);
      var s = { h: head >= 0 ? norm(rows[head][c]) : '', nb: nb.length, len: nb.length ? nb.reduce(function (a, v) { return a + v.length; }, 0) / nb.length : 0,
        name: nb.filter(function (v) { return v.length <= 25 && hangulName(v) && !/[.!?。]$/.test(v); }).length / (nb.length || 1),
        cls: nb.filter(function (v) { return parseCls(v); }).length / (nb.length || 1),
        int: nb.filter(function (v) { return /^\d{1,2}$/.test(v); }).length / (nb.length || 1),
        eng: nb.filter(function (v) { return ENG_RE.test(v); }).length / (nb.length || 1),
        distinct: Object.keys(nb.reduce(function (o, v) { o[v] = 1; return o; }, {})).length, blanks: vals.length - nb.length };
      st.push(s); roles.push('ign');
    }
    // 1) 제목 글자로
    st.forEach(function (s, c) {
      if (!s.h) return;
      if (HEAD.op.test(s.h)) roles[c] = 'op';
      else if (HEAD.name.test(s.h)) roles[c] = 'name';
      else if (HEAD.no.test(s.h)) roles[c] = 'no';
      else if (HEAD.eng.test(s.h)) roles[c] = 'eng';
      else if (HEAD.cls.test(s.h) || /^class$/i.test(s.h)) roles[c] = s.eng > 0.5 || (s.cls < 0.5 && s.nb) ? 'eng' : 'cls';
    });
    function has(role) { return roles.indexOf(role) >= 0; }
    // 2) 내용으로
    if (!has('op')) { var best = -1; st.forEach(function (s, c) { if (roles[c] === 'ign' && s.len >= 15 && (best < 0 || s.len > st[best].len)) best = c; }); if (best >= 0) roles[best] = 'op'; }
    if (!has('name')) { var bn = -1; st.forEach(function (s, c) { if (roles[c] === 'ign' && s.name >= 0.6 && s.len <= 12 && (bn < 0 || s.name > st[bn].name)) bn = c; }); if (bn >= 0) roles[bn] = 'name'; }
    if (!has('eng')) st.forEach(function (s, c) { if (roles[c] === 'ign' && s.eng >= 0.6) roles[c] = 'eng'; });
    var ints = []; st.forEach(function (s, c) { if (roles[c] === 'ign' && s.nb && s.cls >= 0.8) ints.push(c); });
    if (!has('cls') && !has('no') && ints.length >= 2) {
      ints.sort(function (a, b) { return st[a].distinct - st[b].distinct; });
      roles[ints[0]] = 'cls'; roles[ints[ints.length - 1]] = 'no';
    } else if (ints.length) {
      ints.forEach(function (c) {
        var s = st[c];
        if (!has('cls') && (s.distinct <= 12 && (s.blanks > 0 || s.distinct < s.nb * 0.5) || st[c].int < 0.8)) roles[c] = 'cls';
        else if (!has('no') && s.int >= 0.8 && s.distinct >= s.nb * 0.6) roles[c] = 'no';
      });
    }
    // 3) 같은 제목 모양이면 지난번에 고른 대로
    var sig = head >= 0 ? rows[head].map(norm).join('|') : '';
    var saved = sig ? loadJSON(LS_OPMAP, {})[sig] : null;
    if (saved && saved.length === n) roles = saved.slice();
    return { head: head, roles: roles, sig: sig };
  }
  function engFromLabel(s) { var m = ENG_RE.exec(s || ''); return m ? m[0][0].toUpperCase() + m[0].slice(1).toLowerCase() : ''; }
  function addSource(label, rows) {
    if (!rows || rows.length < 1) return false;
    var d = detectTable(rows);
    O.sources.push({ id: Date.now() + Math.random(), label: label, rows: rows, head: d.head, roles: d.roles, sig: d.sig, eng: engFromLabel(label) });
    return d.roles.indexOf('name') >= 0 && d.roles.indexOf('op') >= 0;
  }
  function entriesOf(src) {
    var out = [], lastCls = null, R = src.roles;
    var ci = R.indexOf('cls'), ni = R.indexOf('name'), noi = R.indexOf('no'), ei = R.indexOf('eng');
    var ops = []; R.forEach(function (r, i) { if (r === 'op') ops.push(i); });
    if (ni < 0 || !ops.length) return out;
    src.rows.slice(src.head + 1).forEach(function (row, k) {
      var cl = null;
      if (ci >= 0) { cl = parseCls(row[ci]); if (cl) lastCls = cl; else if (!norm(row[ci])) cl = lastCls; }
      var name = hangulName(row[ni]); if (!name) return;
      var txt = ops.map(function (i) { return String(row[i] || '').trim(); }).filter(Boolean).join(' ');
      out.push({ id: src.id + ':' + k, src: src, rowNo: src.head + 2 + k, rawName: norm(row[ni]), name: name, cls: cl ? cl.c : null, grd: cl ? cl.g : null, hasCls: ci >= 0,
        no: noi >= 0 && /^\d{1,2}$/.test(norm(row[noi])) ? +norm(row[noi]) : null, eng: (ei >= 0 ? norm(row[ei]) : '') || src.eng, text: txt });
    });
    return out;
  }
  function allEntries() { var a = []; O.sources.forEach(function (s) { a = a.concat(entriesOf(s)); }); return a; }

  // ── 나이스 학기말종합의견 화면 ──
  function opFind() {
    var P = window.cpr && cpr.core && cpr.core.Platform && cpr.core.Platform.INSTANCE;
    if (!P) return { reason: '이 탭은 나이스 화면이 아닙니다.' };
    var apps = P.getAllRunningAppInstances().filter(function (a) { return /els_scres10_m00/.test(a.id); });
    if (!apps.length) return { reason: '나이스 학생평가 > 학기말종합의견 화면이 열려 있지 않습니다.' };
    var a = apps.filter(function (x) { try { return x.getContainer().isShowing(); } catch (e) { return true; } })[0];
    if (!a) return { reason: '학기말종합의견 화면이 지금 보이지 않습니다.' };
    var ds = a.lookup('dsMain');
    if (!ds || !ds.getRowCount()) return { reason: '학기말종합의견 조회 결과가 없습니다(0명). 학년·반·교과를 고르고 조회하세요.' };
    return { app: a, ds: ds };
  }
  function opInfo() {
    var f = opFind(); if (!f.app) return { reason: f.reason };
    var a = f.app, ds = f.ds, dm = a.lookup('dmSearch'), st = [];
    for (var i = 0; i < ds.getRowCount(); i++) st.push({ i: i, no: +ds.getValue(i, 'stdntCn'), name: nameKey(ds.getValue(i, 'stdntNm')), rawName: ds.getValue(i, 'stdntNm'), same: ds.getValue(i, 'sameFlnm') === '1', existing: ds.getValue(i, 'gnrlzOpiCn') || '' });
    var cl = a.lookup('dsScrClsCd'), classes = [];
    for (var j = 0; cl && j < cl.getRowCount(); j++) classes.push(+cl.getValue(j, 'clsCdNm') || +cl.getValue(j, 'cd'));
    var txa = a.lookup('txaGnrlzOpiCn');
    return { grd: +ds.getValue(0, 'grd'), cls: +(dm ? dm.getValue('clsCd') : 0), sbjt: ds.getValue(0, 'sbjtCdNm'), students: st, classes: classes,
      limit: txa && txa.maxLength ? txa.maxLength : 4000, unit: txa && txa.lengthUnit ? txa.lengthUnit : 'utf8' };
  }
  function opSig(n) { return n && n.students ? [n.grd, n.cls, n.students.map(function (s) { return s.no + s.name; }).join(',')].join('|') : ''; }
  function opRefresh() {
    var info = opInfo();
    var changed = opSig(info.students ? info : null) !== opSig(O.neis);
    if (info.students) { O.neis = info; O.reason = ''; } else { O.neis = null; O.reason = info.reason; }
    if (changed) { O.pick = {}; O.edit = {}; O.open = {}; }
    return changed;
  }

  // ── 학생 맞추기 ──
  function opMatch() {
    var n = O.neis, ents = allEntries(), res = { rows: [], warn: [], unmatched: [], counts: {} };
    if (!n) return res;
    ents = ents.filter(function (e) { return !(e.grd && e.grd !== n.grd); });
    var anyCls = ents.some(function (e) { return e.hasCls; });
    // 명단으로 실제 반 추정 (검색조건만 바꾸고 조회 안 한 경우 대비)
    var names = {}; n.students.forEach(function (s) { names[s.name] = (names[s.name] || 0) + 1; });
    var byCls = {}; ents.forEach(function (e) { if (e.cls != null && names[e.name]) byCls[e.cls] = (byCls[e.cls] || 0) + 1; });
    var bestC = null; Object.keys(byCls).forEach(function (k) { if (bestC == null || byCls[k] > byCls[bestC]) bestC = +k; });
    res.block = false;
    if (anyCls && bestC != null && bestC !== n.cls && byCls[bestC] >= 3 && byCls[bestC] > (byCls[n.cls] || 0) * 2) {
      res.warn.push('검색 조건은 ' + n.cls + '반인데, 화면 명단은 ' + bestC + '반 학생들과 일치합니다. 반을 확인하고 조회를 다시 누르세요.'); res.block = true;
    }
    var pool = ents.filter(function (e) { return e.cls === n.cls || (!e.hasCls); });
    if (anyCls && !ents.some(function (e) { return e.cls === n.cls; })) res.warn.push('불러온 평어에 ' + n.cls + '반 학생이 없습니다.');
    var used = {};
    n.students.forEach(function (s) {
      var row = { s: s, cands: [], status: '', entry: null, note: '' };
      var dupRoster = names[s.name] > 1;
      var byName = pool.filter(function (e) { return e.name === s.name; });
      var byNo = pool.filter(function (e) { return e.hasCls && e.no != null && e.no === s.no; });
      if (byNo.length === 1 && byNo[0].name !== s.name) { row.status = 'nameDiff'; row.note = '번호 ' + s.no + '번은 파일에 "' + byNo[0].rawName + '"(으)로 적혀 있음'; row.cands = byNo.concat(byName); }
      else if (dupRoster) { var nb = byName.filter(function (e) { return e.no === s.no; }); if (nb.length === 1) { row.entry = nb[0]; row.status = 'ok'; } else { row.status = 'pick'; row.note = '같은 반 동명이인'; row.cands = byName; } }
      else if (byName.length === 1) {
        if (!byName[0].hasCls && s.same) { row.status = 'pick'; row.note = '동명이인 표시 학생인데 파일에 반 정보 없음'; row.cands = byName; }
        else { row.entry = byName[0]; row.status = 'ok'; if (s.same) row.note = '동명이인 표시(반 일치로 확인)'; }
      } else if (byName.length > 1) {
        var withNo = byName.filter(function (e) { return e.no === s.no; });
        if (withNo.length === 1) { row.entry = withNo[0]; row.status = 'ok'; }
        else { row.status = 'pick'; row.note = '같은 이름이 ' + byName.length + '줄 (' + byName.map(function (e) { return e.src.label; }).join(', ') + ')'; row.cands = byName; }
      } else row.status = 'none';
      if (row.entry) used[row.entry.id] = 1;
      res.rows.push(row);
    });
    // 직접 고른 것 반영
    res.rows.forEach(function (row) {
      var p = O.pick[row.s.no];
      if (p === '__skip') { row.entry = null; row.status = 'skip'; return; }
      if (p) { var e = ents.filter(function (x) { return x.id === p; })[0]; if (e) { row.entry = e; row.status = 'manual'; used[e.id] = 1; } }
    });
    res.unmatched = pool.filter(function (e) { return !used[e.id] && (e.cls === n.cls || !e.hasCls) && !n.students.some(function (s) { return s.name === e.name; }); });
    if (!anyCls) res.unmatched = res.unmatched.filter(function (e) { return n.students.some(function (s) { return editDist(s.name, e.name) <= 1; }); });
    res.rows.forEach(function (row) {
      row.text = O.edit[row.s.no] != null ? O.edit[row.s.no] : (row.entry ? cleanText(row.entry.text) : '');
      row.bytes = bytesOf(row.text, n.unit);
      row.suggest = res.unmatched.filter(function (e) { return editDist(e.name, row.s.name) <= 1; });
      var willWrite = (row.status === 'ok' || row.status === 'manual') && row.text;
      if (willWrite && row.s.existing === row.text) row.state = 'done';
      else if (willWrite && row.bytes > n.limit) row.state = 'over';
      else if (willWrite && row.s.existing && !O.opt.overwrite) row.state = 'exist';
      else if (willWrite) row.state = row.s.existing ? 'replace' : 'new';
      else if ((row.status === 'ok' || row.status === 'manual') && !row.text) row.state = 'empty';
      else row.state = row.status;
      res.counts[row.state] = (res.counts[row.state] || 0) + 1;
    });
    return res;
  }

  // ── 화면 ──
  var STATE = {
    done: ['ok', '입력됨(저장 전)'], 'new': ['ok', '새로 입력'], replace: ['warn', '덮어씀'], exist: ['muted', '기존 평어 유지'], over: ['err', '글자 수 초과'],
    empty: ['muted', '평어 칸 비어 있음'], none: ['muted', '평어 없음'], skip: ['muted', '입력 안 함'], pick: ['err', '확인 필요'], nameDiff: ['err', '확인 필요']
  };
  function opRender() {
    var n = O.neis, h = '';
    h += '<div class="sec"><h3>1. 평어 가져오기 <span class="muted small">(여러 파일, 여러 번 붙여넣기 가능)</span></h3>' +
      '<div class="drop" id="odrop">평어 엑셀 파일을 끌어다 놓거나 <u>클릭해서 선택</u> (여러 개 가능)</div><input type="file" id="ofi" accept=".xlsx" multiple style="display:none">' +
      (O.pending.length ? '<div class="row" style="margin-top:8px"><span class="small">' + O.pending.map(function (p) { return esc(p.file.name); }).join(', ') + '</span></div><div class="row" style="margin-top:6px"><span>비밀번호</span><input type="password" id="opw" placeholder="암호 없으면 비워두기" autocomplete="off"><button class="b" id="oopen">열기</button></div>' : '') +
      '<textarea id="opaste" placeholder="또는 한글·워드·엑셀의 표를 복사해서 여기에 붙여넣기 (Ctrl+V)" style="width:100%;height:46px;margin-top:8px;border:1px solid #b8c4d6;border-radius:6px;padding:6px;font-size:12px"></textarea>' +
      '<div id="omsg" class="small" style="margin-top:4px">' + (O.msg || '') + '</div>';
    if (O.sources.length) {
      h += '<table style="margin-top:8px"><tr><th>가져온 표</th><th>열 지정</th><th>줄</th><th></th></tr>';
      O.sources.forEach(function (s, i) {
        var ok = s.roles.indexOf('name') >= 0 && s.roles.indexOf('op') >= 0;
        var desc = s.roles.map(function (r, c) { return r === 'ign' ? '' : ROLE_LABEL[r] + ' ' + NGH.colName(c + 1); }).filter(Boolean).join(', ');
        h += '<tr><td style="text-align:left">' + esc(s.label) + (s.eng ? ' <span class="muted small">(' + esc(s.eng) + ')</span>' : '') + '</td><td style="text-align:left" class="small ' + (ok ? '' : 'err') + '">' + (ok ? esc(desc) : '이름/평어 열을 지정하세요') +
          ' <button class="lk" data-ed="' + i + '">열 바꾸기</button></td><td>' + entriesOf(s).length + '</td><td><button class="lk" data-rm="' + i + '">빼기</button></td></tr>';
        if (O.editing === s.id) h += '<tr><td colspan="4">' + roleEditor(s) + '</td></tr>';
      });
      h += '</table>';
    }
    h += '</div>';
    // 나이스
    h += '<div class="sec"><h3>2. 나이스 화면</h3>';
    if (n) h += '<div class="small">학기말종합의견 · ' + n.grd + '학년 ' + n.cls + '반 ' + esc(n.sbjt) + ' · ' + n.students.length + '명 · 제한 ' + n.limit.toLocaleString() + (n.unit === 'utf8' ? '바이트' : '자') + '<button class="lk" id="orf">나이스 다시 확인</button></div>';
    else h += '<div class="warn small">' + esc(O.reason) + ' <button class="lk" id="orf">나이스 다시 확인</button></div>';
    h += '<div class="row small" style="margin-top:6px"><label><input type="checkbox" id="oow"' + (O.opt.overwrite ? ' checked' : '') + '> 기존 평어 덮어쓰기</label><label><input type="checkbox" id="ojl"' + (O.opt.joinLines ? ' checked' : '') + '> 줄바꿈을 띄어쓰기로</label></div></div>';
    // 미리보기
    var m = opMatch();
    if (n && O.sources.length) {
      var c = m.counts, need = (c.pick || 0) + (c.nameDiff || 0);
      h += '<div class="sec"><h3>3. 미리보기</h3>';
      m.warn.forEach(function (w) { h += '<div class="err"><b>⚠ ' + esc(w) + '</b></div>'; });
      h += '<div class="small">입력 예정 <b class="ok">' + ((c['new'] || 0) + (c.replace || 0)) + '</b>명' + (c.done ? ' · 입력됨(저장 전) ' + c.done + '명' : '') + (need ? ' · <b class="err">확인 필요 ' + need + '명</b>' : '') + (c.over ? ' · <span class="err">글자 수 초과 ' + c.over + '명</span>' : '') +
        (c.none ? ' · 평어 없음 ' + c.none + '명' : '') + (c.exist ? ' · 기존 유지 ' + c.exist + '명' : '') + '</div>';
      h += '<table style="margin-top:6px"><tr><th>번호</th><th>이름</th><th>평어 출처</th><th>바이트</th><th style="width:42%">평어 <span class="muted small">(눌러서 전체 보기·수정)</span></th><th>상태</th></tr>';
      m.rows.forEach(function (r) {
        var stc = STATE[r.state] || ['', r.state], bad = r.state === 'pick' || r.state === 'nameDiff' || r.state === 'over';
        var opts = '<option value="">' + (r.status === 'ok' && !O.pick[r.s.no] ? esc(r.entry.src.label) + ' (자동)' : '선택…') + '</option>';
        var cands = (r.status === 'manual' && r.entry ? [r.entry] : []).concat(r.cands).concat(r.suggest).concat(m.unmatched).filter(function (e, i, arr) { return arr.indexOf(e) === i; });
        cands.forEach(function (e) { opts += '<option value="' + esc(e.id) + '"' + (O.pick[r.s.no] === e.id ? ' selected' : '') + '>' + esc(e.rawName) + (e.cls != null ? ' ' + e.cls + '반' : '') + ' · ' + esc(e.src.label) + '</option>'; });
        opts += '<option value="__skip"' + (O.pick[r.s.no] === '__skip' ? ' selected' : '') + '>입력 안 함</option>';
        h += '<tr' + (bad ? ' class="bad"' : '') + '><td>' + r.s.no + '</td><td>' + esc(r.s.rawName) + (r.note ? '<div class="small ' + (bad ? 'err' : 'muted') + '">' + esc(r.note) + '</div>' : '') +
          (r.suggest.length && r.status === 'none' ? '<div class="small warn">혹시 ' + r.suggest.map(function (e) { return esc(e.rawName); }).join(', ') + '?</div>' : '') + '</td>' +
          '<td><select data-pick="' + r.s.no + '" style="max-width:130px">' + opts + '</select></td>' +
          '<td class="small' + (r.state === 'over' ? ' err' : '') + '">' + (r.text ? r.bytes.toLocaleString() : '') + '</td>' +
          '<td style="text-align:left;cursor:pointer" data-open="' + r.s.no + '" class="small">' + (r.text ? esc(r.text.length > 48 ? r.text.slice(0, 48) + '…' : r.text) : '<span class="muted">-</span>') + (O.edit[r.s.no] != null ? ' <span class="warn">(수정함)</span>' : '') + '</td>' +
          '<td class="small ' + stc[0] + '">' + stc[1] + '</td></tr>';
        if (O.open[r.s.no]) {
          h += '<tr><td colspan="6"><textarea data-edit="' + r.s.no + '" style="width:100%;height:90px;font-size:12px;border:1px solid #b8c4d6;border-radius:5px;padding:5px">' + esc(r.text) + '</textarea>' +
            (r.s.existing ? '<div class="small muted">나이스 기존 평어: ' + esc(r.s.existing.slice(0, 120)) + (r.s.existing.length > 120 ? '…' : '') + '</div>' : '') +
            (O.edit[r.s.no] != null ? '<button class="lk" data-reset="' + r.s.no + '">원래 평어로</button>' : '') + '</td></tr>';
        }
      });
      h += '</table>';
      if (m.unmatched.length) h += '<div class="small warn" style="margin-top:6px">이 반으로 적혀 있지만 명단에 없는 이름: ' + m.unmatched.map(function (e) { return esc(e.rawName) + '(' + esc(e.src.label) + ' ' + e.rowNo + '행)'; }).join(', ') + '</div>';
      h += '</div>';
    }
    // 진행 현황
    var prog = '';
    if (n && n.classes.length) prog = '진행: ' + n.classes.map(function (k) { var p = O.progress[n.grd + '-' + k]; return k + '반 ' + (p ? '<b class="ok">' + p.done + '/' + p.total + '</b>' : '-'); }).join(' · ');
    h += '<div class="btns"><span id="st" class="small" style="margin-right:auto;align-self:center">' + prog + '</span><button class="b" id="oap"' + (n && O.sources.length && !m.block ? '' : ' disabled') + '>나이스에 입력</button></div>';
    $('body').innerHTML = h;
    opBind(m);
  }
  function roleEditor(s) {
    var rows = s.rows.slice(Math.max(0, s.head), Math.max(0, s.head) + 6), w = s.roles.length;
    var h = '<div class="small muted">각 열이 무엇인지 고르세요. 평어를 여러 열에 나눠 썼다면 평어를 여러 개 고르면 순서대로 이어 붙입니다.</div><div style="overflow:auto"><table><tr>';
    for (var c = 0; c < w; c++) h += '<th><select data-role="' + c + '">' + Object.keys(ROLE_LABEL).map(function (k) { return '<option value="' + k + '"' + (s.roles[c] === k ? ' selected' : '') + '>' + ROLE_LABEL[k] + '</option>'; }).join('') + '</select><div class="muted small">' + NGH.colName(c + 1) + '</div></th>';
    h += '</tr>';
    rows.forEach(function (r) { h += '<tr>' + r.map(function (v) { v = String(v || ''); return '<td class="small" style="text-align:left">' + esc(v.length > 30 ? v.slice(0, 30) + '…' : v) + '</td>'; }).join('') + '</tr>'; });
    h += '</table></div><div class="row small" style="margin-top:4px">제목 줄: <select id="rhead"><option value="-1"' + (s.head < 0 ? ' selected' : '') + '>없음</option>' +
      s.rows.slice(0, 8).map(function (r, i) { return '<option value="' + i + '"' + (s.head === i ? ' selected' : '') + '>' + (i + 1) + '번째 줄</option>'; }).join('') + '</select><button class="lk" id="rdone">완료</button></div>';
    return h;
  }
  function opBind(m) {
    var drop = $('odrop'), fi = $('ofi');
    drop.onclick = function () { fi.click(); };
    drop.ondragover = function (e) { e.preventDefault(); drop.classList.add('on'); };
    drop.ondragleave = function () { drop.classList.remove('on'); };
    drop.ondrop = function (e) { e.preventDefault(); drop.classList.remove('on'); addPending(e.dataTransfer.files); };
    fi.onchange = function () { addPending(fi.files); };
    if ($('oopen')) { $('oopen').onclick = openPending; $('opw').onkeydown = function (e) { if (e.key === 'Enter') openPending(); }; }
    $('opaste').addEventListener('paste', function (e) {
      e.preventDefault();
      var html = e.clipboardData.getData('text/html'), txt = e.clipboardData.getData('text/plain');
      var rows = (html && htmlTableRows(html)) || tsvRows(txt || '');
      var k = O.sources.filter(function (s) { return /^붙여넣기/.test(s.label); }).length + 1;
      if (!rows.length) { O.msg = '<span class="err">붙여넣은 내용에서 표를 찾지 못했습니다.</span>'; }
      else { var ok = addSource('붙여넣기 ' + k, rows); O.msg = ok ? '<span class="ok">붙여넣기 ' + k + ': ' + rows.length + '줄을 읽었습니다.</span>' : '<span class="warn">붙여넣기 ' + k + ': 이름/평어 열을 찾지 못했습니다. "열 바꾸기"로 지정하세요.</span>'; if (!ok) O.editing = O.sources[O.sources.length - 1].id; }
      opRender();
    });
    Array.prototype.forEach.call(root.querySelectorAll('[data-rm]'), function (b) { b.onclick = function () { O.sources.splice(+b.dataset.rm, 1); opRender(); }; });
    Array.prototype.forEach.call(root.querySelectorAll('[data-ed]'), function (b) { b.onclick = function () { var s = O.sources[+b.dataset.ed]; O.editing = O.editing === s.id ? null : s.id; opRender(); }; });
    Array.prototype.forEach.call(root.querySelectorAll('[data-role]'), function (sel) {
      sel.onchange = function () {
        var s = O.sources.filter(function (x) { return x.id === O.editing; })[0]; if (!s) return;
        var c = +sel.dataset.role, v = sel.value;
        if (v !== 'op' && v !== 'ign') s.roles = s.roles.map(function (r, i) { return r === v && i !== c ? 'ign' : r; });
        s.roles[c] = v; rememberRoles(s); opRender();
      };
    });
    if ($('rhead')) $('rhead').onchange = function () { var s = O.sources.filter(function (x) { return x.id === O.editing; })[0]; s.head = +$('rhead').value; s.sig = s.head >= 0 ? s.rows[s.head].map(norm).join('|') : ''; rememberRoles(s); opRender(); };
    if ($('rdone')) $('rdone').onclick = function () { O.editing = null; opRender(); };
    $('orf').onclick = function () { var ch = opRefresh(); opRender(); if (ch) $('st').innerHTML = '<span class="warn">나이스 화면을 다시 불러왔습니다.</span>'; };
    $('oow').onchange = function () { O.opt.overwrite = $('oow').checked; opRender(); };
    $('ojl').onchange = function () { O.opt.joinLines = $('ojl').checked; opRender(); };
    Array.prototype.forEach.call(root.querySelectorAll('[data-pick]'), function (sel) { sel.onchange = function () { if (sel.value) O.pick[sel.dataset.pick] = sel.value; else delete O.pick[sel.dataset.pick]; opRender(); }; });
    Array.prototype.forEach.call(root.querySelectorAll('[data-open]'), function (td) { td.onclick = function () { var k = td.dataset.open; O.open[k] = !O.open[k]; opRender(); }; });
    Array.prototype.forEach.call(root.querySelectorAll('[data-edit]'), function (ta) {
      ta.oninput = function () {
        O.edit[ta.dataset.edit] = ta.value;
        var tr = ta.closest('tr').previousElementSibling; if (tr) tr.children[3].textContent = bytesOf(ta.value, O.neis.unit).toLocaleString();
      };
      ta.onblur = function () { opRender(); };
    });
    Array.prototype.forEach.call(root.querySelectorAll('[data-reset]'), function (b) { b.onmousedown = function (e) { e.preventDefault(); delete O.edit[b.dataset.reset]; opRender(); }; });
    $('oap').onclick = opApply;
  }
  function rememberRoles(s) { if (!s.sig) return; var all = loadJSON(LS_OPMAP, {}); all[s.sig] = s.roles; saveJSON(LS_OPMAP, all); }
  async function addPending(files) {
    for (var i = 0; i < files.length; i++) O.pending.push({ file: files[i], bytes: new Uint8Array(await files[i].arrayBuffer()) });
    O.msg = ''; opRender(); if ($('opw')) $('opw').focus();
  }
  async function openPending() {
    var pw = $('opw').value, msgs = [], left = [];
    $('oopen').disabled = true; $('omsg').innerHTML = '<span class="muted">여는 중… (암호 해제에 몇 초 걸립니다)</span>';
    for (var i = 0; i < O.pending.length; i++) {
      var p = O.pending[i];
      try {
        var wb = await NGH.openWorkbookBytes(p.bytes, pw), sst = NGH.sharedStrings(wb), sheets = NGH.sheetList(wb), found = 0;
        sheets.forEach(function (sh) {
          var rows = gridToRows(NGH.readSheet(wb, sh.path, sst));
          if (rows.length < 2) return;
          var label = p.file.name.replace(/\.xlsx$/i, '') + (sheets.length > 1 ? ' / ' + sh.name : '');
          var before = O.sources.length;
          if (addSource(label, rows)) found++; else O.sources.splice(before, 1);
        });
        msgs.push(found ? '<span class="ok">' + esc(p.file.name) + ': 표 ' + found + '개</span>' : '<span class="warn">' + esc(p.file.name) + ': 평어 표를 찾지 못함 (붙여넣기를 이용하세요)</span>');
      } catch (e) {
        if (e.code === 'BADPW' || e.code === 'NEEDPW') { left.push(p); msgs.push('<span class="err">' + esc(p.file.name) + ': ' + esc(e.message) + '</span>'); }
        else msgs.push('<span class="err">' + esc(p.file.name) + ': ' + esc(e.message) + '</span>');
      }
    }
    O.pending = left; O.msg = msgs.join('<br>'); opRender();
  }
  function opApply() {
    if (opRefresh()) { opRender(); $('st').innerHTML = '<span class="warn">나이스 화면(반)이 바뀌어 다시 맞췄습니다. 미리보기를 확인한 뒤 다시 누르세요.</span>'; return; }
    if (!O.neis) { opRender(); $('st').innerHTML = '<span class="err">' + esc(O.reason) + '</span>'; return; }
    var m = opMatch(); if (m.block) { opRender(); return; }
    var f = opFind(), ds = f.ds, done = 0;
    ds.setEventActivation(false);
    try {
      m.rows.forEach(function (r) { if (r.state === 'new' || r.state === 'replace') { ds.setValue(r.s.i, 'gnrlzOpiCn', r.text); done++; } });
    } finally {
      ds.setEventActivation(true); try { ds.refresh(); } catch (e) {} try { var g = f.app.lookup('grdMain'); if (g) g.redraw(); } catch (e) {}
    }
    O.progress[O.neis.grd + '-' + O.neis.cls] = { done: done, total: O.neis.students.length };
    opRefresh(); opRender();
    $('st').innerHTML = '<span class="ok">' + done + '명 입력했습니다. 화면 확인 후 <b>저장</b>은 직접 누르세요. 다음 반은 반을 바꿔 조회한 뒤 "나이스 다시 확인".</span>';
  }

  window.__ngh = { S: S, O: O, extract: extract, neisInfo: neisInfo, wake: wake, W: W, opMatch: opMatch };
  setMode(screenMode() || 'grade');
})();

})();
