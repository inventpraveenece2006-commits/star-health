/* =============================================
   Steganography Lab — script.js
   LSB steganography for images (PNG), audio (WAV) & video (uncompressed AVI)
   ============================================= */

"use strict";

const $ = id => document.getElementById(id);

/* ─────────────────────────────────────────────
   Byte / string helpers
   ───────────────────────────────────────────── */
const enc8 = new TextEncoder();
const dec8 = new TextDecoder();

function asciiOf(u8, o, n) { let s = ""; for (let i = 0; i < n; i++) s += String.fromCharCode(u8[o + i]); return s; }
function concatBytes(...arrs) {
  let len = 0; for (const a of arrs) len += a.length;
  const out = new Uint8Array(len); let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}
function le32(n) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; }
function fnv1a(u8) {
  let h = 0x811c9dc5;
  for (let i = 0; i < u8.length; i++) { h ^= u8[i]; h = Math.imul(h, 0x01000193); }
  return h >>> 0;
}
function xorStream(data, password) {
  if (!password) return data;
  const key = enc8.encode(password);
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) out[i] = data[i] ^ key[i % key.length];
  return out;
}
function fmtBytes(n) {
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  return (n / 1048576).toFixed(2) + " MB";
}
function esc(s) { return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }
function guessMime(name) {
  const ext = (name.split(".").pop() || "").toLowerCase();
  const map = {
    png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", bmp: "image/bmp", webp: "image/webp", gif: "image/gif",
    wav: "audio/wav", mp3: "audio/mpeg", ogg: "audio/ogg", m4a: "audio/mp4",
    mp4: "video/mp4", webm: "video/webm", avi: "video/x-msvideo", mov: "video/quicktime", mkv: "video/x-matroska"
  };
  return map[ext] || "";
}

/* ─────────────────────────────────────────────
   Payload package format
   [STEG][ver][kind][nameLen u32][payloadLen u32][name][encrypted payload + 4-byte FNV]
   kind: 0=text  1=file
   payloadLen includes the trailing 4-byte checksum
   ───────────────────────────────────────────── */
const MAGIC = [0x53, 0x54, 0x45, 0x47]; // "STEG"
const HEADER_LEN = 14;

function buildPackage(kind, nameUtf8, dataBytes, password) {
  const checksum = le32(fnv1a(dataBytes));
  const body = concatBytes(dataBytes, checksum);
  const enc = xorStream(body, password);
  const name = kind === 1 ? nameUtf8 : new Uint8Array(0);
  const hdr = new Uint8Array(HEADER_LEN);
  hdr[0] = MAGIC[0]; hdr[1] = MAGIC[1]; hdr[2] = MAGIC[2]; hdr[3] = MAGIC[3];
  hdr[4] = 1; // version
  hdr[5] = kind;
  new DataView(hdr.buffer).setUint32(6, name.length, true);
  new DataView(hdr.buffer).setUint32(10, enc.length, true);
  return concatBytes(hdr, name, enc);
}

function readPackage(pkgBytes, password) {
  if (pkgBytes.length < HEADER_LEN) throw new Error("No steganography payload found.");
  for (let i = 0; i < 4; i++) if (pkgBytes[i] !== MAGIC[i]) throw new Error("No steganography payload found.");
  if (pkgBytes[4] !== 1) throw new Error("Unsupported payload version.");
  const kind = pkgBytes[5];
  const nameLen = new DataView(pkgBytes.buffer, pkgBytes.byteOffset + 6, 4).getUint32(0, true);
  const encLen = new DataView(pkgBytes.buffer, pkgBytes.byteOffset + 10, 4).getUint32(0, true);
  if (pkgBytes.length < HEADER_LEN + nameLen + encLen) throw new Error("Payload is truncated or the media was damaged.");
  const name = kind === 1 ? dec8.decode(pkgBytes.subarray(HEADER_LEN, HEADER_LEN + nameLen)) : "";
  const enc = pkgBytes.subarray(HEADER_LEN + nameLen, HEADER_LEN + nameLen + encLen);
  if (encLen < 4) throw new Error("Payload is too short.");
  const body = xorStream(enc, password);
  const data = body.subarray(0, body.length - 4);
  const check = body.subarray(body.length - 4);
  const hash = le32(fnv1a(data));
  for (let i = 0; i < 4; i++) if (check[i] !== hash[i]) throw new Error("Incorrect password, or the data was modified.");
  return { kind, name, data: new Uint8Array(data) };
}

function readBits(bytes, offset, byteCount) {
  const out = new Uint8Array(byteCount);
  for (let i = 0; i < byteCount; i++) {
    let v = 0;
    for (let k = 0; k < 8; k++) v = (v << 1) | (bytes[offset + i * 8 + k] & 1);
    out[i] = v;
  }
  return out;
}

/* Parse a package straight out of a carrier's bit stream (no decryption/verify).
   Returns the raw package bytes: header + name + (encrypted payload + checksum). */
function readPackageBits(flat) {
  const hdr = readBits(flat, 0, HEADER_LEN);
  for (let i = 0; i < 4; i++) if (hdr[i] !== MAGIC[i]) throw new Error("No steganography payload found.");
  const dvH = new DataView(hdr.buffer);
  const nameLen = dvH.getUint32(6, true);
  const encLen = dvH.getUint32(10, true);
  const nameEnd = HEADER_LEN + nameLen;
  if (nameEnd + encLen > flat.length) throw new Error("Payload is truncated or the media was damaged.");
  const name = readBits(flat, HEADER_LEN * 8, nameLen);
  const enc = readBits(flat, nameEnd * 8, encLen);
  return concatBytes(hdr, name, enc);
}

/* ─────────────────────────────────────────────
   IMAGE CARRIER  (RGB channels of each pixel → PNG out)
   ───────────────────────────────────────────── */
async function loadImageCarrier(file) {
  const bmp = await createImageBitmap(file);
  const w = bmp.width, h = bmp.height;
  const cv = document.createElement("canvas");
  cv.width = w; cv.height = h;
  const ctx = cv.getContext("2d", { willReadFrequently: true });
  ctx.drawImage(bmp, 0, 0);
  const im = ctx.getImageData(0, 0, w, h);
  bmp.close && bmp.close();
  const d = im.data;
  const n = w * h * 3; // bits
  return {
    kind: "image", n,
    bit(i) {
      const px = (i / 3) | 0, ch = i % 3;
      return d[px * 4 + ch] & 1;
    },
    setBit(i, b) {
      const px = (i / 3) | 0, ch = i % 3, idx = px * 4 + ch;
      d[idx] = (d[idx] & 0xFE) | b;
    },
    async blob() {
      ctx.putImageData(im, 0, 0);
      return await new Promise(res => cv.toBlob(res, "image/png"));
    }
  };
}

/* ─────────────────────────────────────────────
   AUDIO CARRIER  (raw WAV, LSB of byte 0 of each sample → WAV out)
   ───────────────────────────────────────────── */
function parseWav(ab) {
  const u8 = new Uint8Array(ab);
  if (asciiOf(u8, 0, 4) !== "RIFF" || asciiOf(u8, 8, 4) !== "WAVE") throw new Error("Not a valid WAV file.");
  const dv = new DataView(u8.buffer);
  let bits = 16, dataStart = -1, dataSize = 0;
  let off = 12;
  while (off + 8 <= u8.length) {
    const id = asciiOf(u8, off, 4);
    const size = dv.getUint32(off + 4, true);
    const ds = off + 8;
    if (id === "fmt " && ds + 16 <= u8.length) {
      bits = dv.getUint16(ds + 14, true);
    } else if (id === "data") { dataStart = ds; dataSize = size; }
    off = ds + size + (size & 1);
  }
  if (dataStart < 0) throw new Error("WAV file has no data chunk.");
  const bps = Math.max(1, (bits / 8) | 0);
  const n = Math.floor(dataSize / bps);
  if (n < 128) throw new Error("Audio is too short.");
  return { u8, dataStart, bps, n };
}

function loadAudioCarrier(file) {
  return file.arrayBuffer().then(ab => {
    const w = parseWav(ab);
    return {
      kind: "audio", n: w.n,
      bit(i) { return w.u8[w.dataStart + i * w.bps] & 1; },
      setBit(i, b) {
        const o = w.dataStart + i * w.bps;
        w.u8[o] = (w.u8[o] & 0xFE) | b;
      },
      blob() { return new Blob([w.u8], { type: "audio/wav" }); }
    };
  });
}

/* ─────────────────────────────────────────────
   VIDEO CARRIER  (lossless uncompressed AVI, 24-bit DIB frames)
   ───────────────────────────────────────────── */
function imageDataToDib(im, w, h) {
  const rowBytes = ((w * 3 + 3) & ~3);
  const buf = new Uint8Array(rowBytes * h);
  const d = im.data;
  for (let y = 0; y < h; y++) {
    const srcRow = h - 1 - y;
    const dst = y * rowBytes;
    for (let x = 0; x < w; x++) {
      const p = (srcRow * w + x) * 4;
      buf[dst + x * 3] = d[p + 2];      // B
      buf[dst + x * 3 + 1] = d[p + 1];  // G
      buf[dst + x * 3 + 2] = d[p];      // R
    }
  }
  return buf;
}

class DataWriter {
  constructor() { this.chunks = []; this.len = 0; }
  u8(x) { this.chunks.push(new Uint8Array([x & 0xFF])); this.len += 1; }
  u16(x) { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, x, true); this.chunks.push(b); this.len += 2; }
  u32(x) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, x >>> 0, true); this.chunks.push(b); this.len += 4; }
  i32(x) { const b = new Uint8Array(4); new DataView(b.buffer).setInt32(0, x, true); this.chunks.push(b); this.len += 4; }
  cc(s) { this.raw(new Uint8Array([s.charCodeAt(0), s.charCodeAt(1), s.charCodeAt(2), s.charCodeAt(3)])); }
  raw(b) { this.chunks.push(b); this.len += b.length; }
  build() {
    const out = new Uint8Array(this.len); let o = 0;
    for (const c of this.chunks) { out.set(c, o); o += c.length; }
    return out;
  }
}

class AVIWriter {
  constructor(w, h, fps) {
    this.w = w; this.h = h; this.fps = fps;
    this.rowBytes = ((w * 3 + 3) & ~3);
    this.frameSize = this.rowBytes * h;
    this.frames = [];
  }
  addFrame(dib) {
    if (dib.length !== this.frameSize) throw new Error("frame size mismatch");
    this.frames.push(dib);
  }
  build() {
    const w = this.w, h = this.h, n = this.frames.length;
    const fps = Math.max(1, Math.round(this.fps));
    const rowBytes = this.rowBytes, frameSize = this.frameSize;

    // avih chunk
    const avih = new DataWriter();
    avih.cc("avih"); avih.u32(56);
    avih.u32(Math.round(1000000 / fps)); // dwMicroSecPerFrame
    avih.u32(frameSize * fps);           // dwMaxBytesPerSec
    avih.u32(0); avih.u32(0x10);         // AVIF_HASINDEX
    avih.u32(n); avih.u32(0); avih.u32(1);
    avih.u32(frameSize);
    avih.u32(w); avih.u32(h);
    for (let i = 0; i < 4; i++) avih.u32(0);

    // strh chunk
    const strh = new DataWriter();
    strh.cc("strh"); strh.u32(56);
    strh.cc("vids"); strh.cc("DIB ");
    strh.u32(0); strh.u16(0); strh.u16(0);
    strh.u32(0); strh.u32(1); strh.u32(fps);
    strh.u32(0); strh.u32(n); strh.u32(frameSize);
    strh.u32(0xFFFFFFFF);
    strh.u32(frameSize);
    strh.u16(0); strh.u16(0); strh.u16(w); strh.u16(h);

    // strf chunk
    const strf = new DataWriter();
    strf.cc("strf"); strf.u32(40);
    strf.u32(40); strf.i32(w); strf.i32(h);
    strf.u16(1); strf.u16(24); strf.u32(0);
    strf.u32(frameSize);
    strf.i32(0); strf.i32(0); strf.u32(0); strf.u32(0);

    // hdrl LIST body (includes its own 'hdrl' type code)
    const hdrlBody = new DataWriter();
    hdrlBody.cc("hdrl");
    hdrlBody.raw(avih.build());
    hdrlBody.cc("LIST"); hdrlBody.u32(4 + 64 + 48); // strh(8+56) + strf(8+40) + type(4)
    hdrlBody.cc("strl");
    hdrlBody.raw(strh.build());
    hdrlBody.raw(strf.build());

    // movi LIST body (includes its own 'movi' type code)
    const moviBody = new DataWriter();
    moviBody.cc("movi");
    const offsets = [];
    let cur = 0;
    for (let i = 0; i < n; i++) {
      const fr = this.frames[i];
      offsets.push(cur);
      moviBody.cc("00dc"); moviBody.u32(fr.length);
      moviBody.raw(fr);
      if (fr.length & 1) moviBody.u8(0);
      cur += 8 + fr.length + (fr.length & 1);
    }

    // idx1 chunk
    const idx = new DataWriter();
    idx.cc("idx1"); idx.u32(16 * n);
    for (let i = 0; i < n; i++) {
      idx.cc("00dc"); idx.u32(0x10); idx.u32(offsets[i]); idx.u32(this.frames[i].length);
    }

    // assemble
    const riffBody = new DataWriter();
    riffBody.cc("LIST"); riffBody.u32(hdrlBody.len); riffBody.raw(hdrlBody.build());
    riffBody.cc("LIST"); riffBody.u32(moviBody.len); riffBody.raw(moviBody.build());
    riffBody.raw(idx.build());

    const riff = new DataWriter();
    riff.cc("RIFF"); riff.u32(4 + riffBody.len); riff.cc("AVI ");
    riff.raw(riffBody.build());
    return new Blob([riff.build()], { type: "video/x-msvideo" });
  }
}

function readAVIFrames(u8) {
  const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  const frames = [];
  if (asciiOf(u8, 0, 4) !== "RIFF" || asciiOf(u8, 8, 4) !== "AVI ") throw new Error("Not an AVI video.");
  const walk = (start, end) => {
    let o = start;
    while (o + 8 <= end) {
      const id = asciiOf(u8, o, 4);
      const size = dv.getUint32(o + 4, true);
      if (size > end - o - 8) break;
      if (id === "00dc") frames.push(new Uint8Array(u8.buffer, u8.byteOffset + o + 8, size));
      o += 8 + size + (size & 1);
    }
  };
  let o = 12;
  while (o + 8 <= u8.length) {
    const id = asciiOf(u8, o, 4);
    const size = dv.getUint32(o + 4, true);
    if (size > u8.length - o - 8) break;
    if (id === "LIST") {
      if (size >= 4 && asciiOf(u8, o + 8, 4) === "movi") walk(o + 12, o + 12 + size - 4);
    }
    o += 8 + size + (size & 1);
  }
  if (!frames.length) throw new Error("No video frames found.");
  return frames;
}

async function extractVideo(file) {
  const ab = await file.arrayBuffer();
  const u8 = new Uint8Array(ab);
  const frames = readAVIFrames(u8);
  const flat = new Uint8Array(frames.reduce((s, f) => s + f.byteLength, 0));
  let o = 0;
  for (const f of frames) { flat.set(new Uint8Array(f), o); o += f.byteLength; }
  return readPackageBits(flat);
}

async function videoMeta(file) {
  const v = document.createElement("video");
  v.muted = true; v.preload = "metadata"; v.playsInline = true;
  v.src = URL.createObjectURL(file);
  try {
    await new Promise((res, rej) => { v.onloadedmetadata = res; v.onerror = rej; });
    return { w: v.videoWidth, h: v.videoHeight, dur: isFinite(v.duration) ? v.duration : 0 };
  } finally { URL.revokeObjectURL(v.src); }
}

async function extractSourceFrames(file, count, maxSide, onFrame) {
  const v = document.createElement("video");
  v.muted = true; v.playsInline = true;
  v.src = URL.createObjectURL(file);
  await new Promise((res, rej) => { v.onloadedmetadata = res; v.onerror = rej; });
  const dur = v.duration;
  let w = v.videoWidth, h = v.videoHeight;
  if (Math.max(w, h) > maxSide) {
    const s = maxSide / Math.max(w, h);
    w = Math.round(w * s); h = Math.round(h * s);
  }
  const cv = document.createElement("canvas");
  cv.width = w; cv.height = h;
  const ctx = cv.getContext("2d", { willReadFrequently: true });
  const frames = [];
  const step = Math.max(dur / 200, 1 / 30);
  for (let i = 0; i < count; i++) {
    const t = Math.min(i * step, Math.max(0, dur - 0.03));
    v.currentTime = t;
    await new Promise(res => {
      let done = false;
      const timer = setTimeout(() => { if (!done) { done = true; res(); } }, 4000);
      v.onseeked = () => { if (!done) { done = true; clearTimeout(timer); res(); } };
      if (Math.abs(v.currentTime - t) < 0.001) { clearTimeout(timer); if (!done) { done = true; res(); } }
    });
    ctx.drawImage(v, 0, 0, w, h);
    frames.push(ctx.getImageData(0, 0, w, h));
    onFrame && onFrame(frames.length, count);
    await new Promise(r => setTimeout(r, 0));
  }
  URL.revokeObjectURL(v.src);
  return { frames, w, h };
}

function syntheticFrame(w, h, i, n) {
  const im = new ImageData(w, h);
  const d = im.data;
  const hue = (i / Math.max(1, n)) * Math.PI * 2;
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const idx = (y * w + x) * 4;
      d[idx]     = (x / w * 255) | 0;
      d[idx + 1] = (y / h * 255) | 0;
      d[idx + 2] = (128 + 120 * Math.sin(hue + (x + y) / 90)) | 0;
      d[idx + 3] = 255;
    }
  }
  return im;
}

async function getVideoFrames(useSynthetic, sourceFile, payloadBytes, onProgress) {
  const needBits = payloadBytes * 8;
  if (useSynthetic || !sourceFile) {
    const w = 640, h = 360;
    const perFrame = (((w * 3 + 3) & ~3)) * h;
    let count = Math.max(2, Math.ceil(needBits / (perFrame * 8)) + 1);
    count = Math.min(count, 400);
    const capBits = perFrame * count * 8;
    if (capBits < needBits) throw new Error("Message/file too large for a synthetic video cover (max " + fmtBytes(capBits / 8) + ").");
    const fps = Math.max(1, Math.min(30, Math.round(count / 3)));
    const frames = [];
    for (let i = 0; i < count; i++) {
      frames.push(syntheticFrame(w, h, i, count));
      onProgress && onProgress(i + 1, count);
      await new Promise(r => setTimeout(r, 0));
    }
    return { frames, w, h, fps };
  }
  const meta = await videoMeta(sourceFile);
  if (!meta.w || !meta.dur) throw new Error("Could not read the source video.");
  let w = meta.w, h = meta.h;
  if (Math.max(w, h) > 960) {
    const s = 960 / Math.max(w, h);
    w = Math.round(w * s); h = Math.round(h * s);
  }
  const perFrame = (((w * 3 + 3) & ~3)) * h;
  const availFrames = Math.max(1, Math.floor(meta.dur * 30));
  let count = Math.min(availFrames, Math.ceil(needBits / (perFrame * 8)) + 1);
  if (count > 500) {
    throw new Error("Payload too large for this video (max ~" + fmtBytes(500 * perFrame) + "). Try a shorter/larger payload or a longer video.");
  }
  const capBits = perFrame * count * 8;
  if (capBits < needBits) {
    throw new Error("Source video can only hold about " + fmtBytes(capBits / 8) + " here — reduce the payload or use a longer video.");
  }
  const { frames } = await extractSourceFrames(sourceFile, count, 960, onProgress);
  const fps = Math.max(1, Math.min(30, Math.round(count / Math.max(0.1, meta.dur))));
  return { frames, w, h, fps };
}

async function embedVideo(useSynthetic, sourceFile, pkg, onProgress) {
  const { frames, w, h, fps } = await getVideoFrames(useSynthetic, sourceFile, pkg.length, onProgress);
  const frameBytes = (((w * 3 + 3) & ~3)) * h;
  if (pkg.length * 8 > frames.length * frameBytes * 8) throw new Error("Payload too large for the video cover.");
  const aw = new AVIWriter(w, h, fps);
  let pos = 0; // global bit index into the package
  for (let i = 0; i < frames.length; i++) {
    const dib = imageDataToDib(frames[i], w, h);
    for (let j = 0; j < frameBytes && pos < pkg.length * 8; j++, pos++) {
      const b = pkg[pos >> 3];
      dib[j] = (dib[j] & 0xFE) | ((b >> (7 - (pos & 7))) & 1);
    }
    aw.addFrame(dib);
    onProgress && onProgress(i + 1, frames.length);
    await new Promise(r => setTimeout(r, 0));
  }
  return aw.build();
}

/* ─────────────────────────────────────────────
   UI STATE
   ───────────────────────────────────────────── */
let coverType = "image";
let payloadMode = "text";
let payloadFileType = "image";
let coverFile = null;
let payloadFile = null;
let extractFile = null;

function toast(msg, err) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.toggle("err", !!err);
  t.classList.add("show");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => t.classList.remove("show"), 3200);
}

function coverAccept() {
  if (coverType === "image") return "image/*";
  if (coverType === "audio") return ".wav";
  return ".mp4,.webm,.mkv,.mov,.avi,.ogv";
}
function coverPrompt() {
  if (coverType === "image") return ["Drop a PNG / JPG image here", "or click to browse · output is always lossless PNG"];
  if (coverType === "audio") return ["Drop a WAV audio file here", "or click to browse · LSB of each audio sample"];
  return ["Drop a video file here", "or tick the box below to generate a demo cover"];
}

function setCover(type) {
  coverType = type;
  const [t1, t2] = coverPrompt();
  $("coverDzTitle").textContent = t1;
  $("coverDzSub").textContent = t2;
  $("coverFile").accept = coverAccept();
  $("synthCovers").style.display = type === "video" ? "flex" : "none";
  $("coverPreview").innerHTML = ""; $("coverPreview").style.display = "none";
  $("coverDrop").classList.remove("has-file");
  coverFile = null;
  updateMeter();
}

function setPayloadMode(mode) {
  payloadMode = mode;
  $("textBox").style.display = mode === "text" ? "block" : "none";
  $("fileBox").style.display = mode === "file" ? "block" : "none";
  if (mode !== "file") { payloadFile = null; $("payloadFileInfo").style.display = "none"; }
  updateMeter();
}

const payloadTypeLabels = {
  image: "secret image", audio: "secret audio", video: "secret video", other: "any file"
};
function setPayloadFileType(t) {
  payloadFileType = t;
  const map = { image: "image/*", audio: "audio/*", video: "video/*", other: undefined };
  $("payloadFile").accept = map[t] || "";
  $("payloadDzTitle").textContent = "Drop a " + payloadTypeLabels[t] + " to hide";
  payloadFile = null;
  $("payloadFileInfo").style.display = "none";
  updateMeter();
}

/* ── Drop zones ────────────────────────────── */
function wireDrop(zoneId, inputId, onChange) {
  const zone = $(zoneId), input = $(inputId);
  zone.addEventListener("click", () => input.click());
  input.addEventListener("change", () => { if (input.files[0]) onChange(input.files[0]); });
  zone.addEventListener("dragover", e => { e.preventDefault(); zone.classList.add("dragover"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("dragover"));
  zone.addEventListener("drop", e => {
    e.preventDefault(); zone.classList.remove("dragover");
    if (e.dataTransfer.files[0]) onChange(e.dataTransfer.files[0]);
  });
}

function previewCover(file, wrapId) {
  const wrap = $(wrapId);
  wrap.innerHTML = "";
  if (file.type && file.type.startsWith("image/")) {
    const img = document.createElement("img");
    img.src = URL.createObjectURL(file);
    wrap.appendChild(img);
  } else if (file.type && file.type.startsWith("video/")) {
    const v = document.createElement("video");
    v.muted = true; v.src = URL.createObjectURL(file);
    wrap.appendChild(v);
  }
  const meta = document.createElement("div");
  meta.className = "cover-meta";
  meta.innerHTML = "<b>" + esc(file.name) + "</b><br>" + fmtBytes(file.size);
  wrap.appendChild(meta);
  wrap.style.display = "flex";
}

/* ── Capacity meter ────────────────────────── */
function currentNeed() {
  if (payloadMode === "text") {
    const bytes = enc8.encode($("secretText").value || "");
    return bytes.length + HEADER_LEN + 4;
  }
  if (payloadFile) {
    return (payloadFile.size + 4) + HEADER_LEN + 2 + enc8.encode(payloadFile.name).length;
  }
  return 0;
}

function drawMeter(capacity, need) {
  const box = $("capacityBox"), txt = $("capacityText"), fill = $("capacityFill");
  if (!capacity) { box.style.display = "none"; return; }
  const pct = Math.min(100, (need / capacity) * 100);
  fill.classList.remove("warn", "bad");
  if (need > capacity) fill.classList.add("bad");
  else if (pct > 75) fill.classList.add("warn");
  fill.style.width = pct + "%";
  txt.innerHTML = "<b>Capacity</b> " + fmtBytes(capacity) +
    " &nbsp;·&nbsp; <b>Payload</b> " + fmtBytes(need) +
    (need > capacity ? " — too large!" : " — " + (need ? Math.round(pct) + "% used" : "ready"));
  box.style.display = "block";
}

function updateMeter() {
  const cov = coverFile;
  if (!cov) { $("capacityBox").style.display = "none"; return; }
  const need = currentNeed();
  if (coverType === "image") {
    createImageBitmap(cov).then(bmp => {
      const c = bmp.width * bmp.height * 3 / 8;
      bmp.close && bmp.close();
      drawMeter(c, need);
    }).catch(() => drawMeter(0, need));
  } else if (coverType === "audio") {
    cov.arrayBuffer().then(ab => {
      try { drawMeter(parseWav(ab).n / 8, need); } catch (e) { drawMeter(0, need); }
    }).catch(() => drawMeter(0, need));
  } else {
    const v = document.createElement("video");
    v.preload = "metadata"; v.muted = true;
    v.src = URL.createObjectURL(cov);
    v.onloadedmetadata = () => {
      const dur = v.duration || 0;
      const count = Math.min(400, Math.max(2, dur * 25));
      drawMeter((((640 * 3 + 3) & ~3)) * 360 * count, need);
      URL.revokeObjectURL(v.src);
    };
    v.onerror = () => drawMeter(0, need);
  }
}

/* ─────────────────────────────────────────────
   HIDE FLOW
   ───────────────────────────────────────────── */
async function doHide() {
  const useSynth = coverType === "video" && $("synthVideo").checked;
  if (!coverFile && !useSynth) {
    return toast("Please choose a cover " + (coverType === "image" ? "image" : coverType === "audio" ? "audio file" : "video") + ".", true);
  }
  let pkg;
  const pass = $("hidePass").value || "";
  if (payloadMode === "text") {
    const text = $("secretText").value;
    if (!text.trim()) return toast("Type a secret message first.", true);
    pkg = buildPackage(0, "", enc8.encode(text), pass);
  } else {
    if (!payloadFile) return toast("Please choose the file to hide.", true);
    pkg = buildPackage(1, enc8.encode(payloadFile.name), new Uint8Array(await payloadFile.arrayBuffer()), pass);
  }

  const busy = $("hideBusy"), btn = $("hideBtn"), busyt = $("hideBusyText");
  btn.disabled = true; busy.classList.remove("hidden"); busyt.textContent = "Preparing…";

  try {
    let result;
    if (coverType === "image") {
      const c = await loadImageCarrier(coverFile);
      if (pkg.length * 8 > c.n) throw new Error("Cover image too small — need " + fmtBytes(pkg.length) + ", it holds " + fmtBytes(c.n / 8) + ".");
      let pos = 0;
      for (let i = 0; i < pkg.length; i++) {
        const b = pkg[i];
        for (let k = 7; k >= 0; k--) c.setBit(pos++, (b >> k) & 1);
      }
      result = {
        name: coverFile.name.replace(/\.[^.]+$/, "") + "_stego.png",
        blob: await c.blob(), type: "image"
      };
    } else if (coverType === "audio") {
      const c = await loadAudioCarrier(coverFile);
      if (pkg.length * 8 > c.n) throw new Error("Audio too short — need " + fmtBytes(pkg.length) + ", it holds " + fmtBytes(c.n / 8) + ".");
      let pos = 0;
      for (let i = 0; i < pkg.length; i++) {
        const b = pkg[i];
        for (let k = 7; k >= 0; k--) c.setBit(pos++, (b >> k) & 1);
      }
      result = {
        name: coverFile.name.replace(/\.[^.]+$/, "") + "_stego.wav",
        blob: c.blob(), type: "audio"
      };
    } else {
      busyt.textContent = "Embedding into video frames…";
      const blob = await embedVideo(useSynth, coverFile, pkg, (d, t) => {
        if (t) busyt.textContent = "Video frame " + d + " / " + t + "…";
      });
      result = {
        name: (useSynth ? "stego_cover" : coverFile.name.replace(/\.[^.]+$/, "")) + "_stego.avi",
        blob, type: "video"
      };
    }
    showResult("hideResult", "✔ Hidden — download the stego " + (coverType === "image" ? "image" : coverType === "audio" ? "audio" : "video") + ":", result, true);
    toast("Message hidden.");
  } catch (e) {
    showError("hideResult", e.message || String(e));
  } finally {
    btn.disabled = false; busy.classList.add("hidden");
  }
}

/* ─────────────────────────────────────────────
   EXTRACT FLOW
   ───────────────────────────────────────────── */
function pkgNeededLen(carrier) {
  const maxBytes = Math.floor(carrier.n / 8);
  const hdr = readBitsFromCarrier(carrier, 0, Math.min(maxBytes, HEADER_LEN));
  for (let i = 0; i < 4; i++) if (hdr[i] !== MAGIC[i]) return HEADER_LEN;
  const dv = new DataView(hdr.buffer);
  const nameLen = dv.getUint32(6, true);
  const encLen = dv.getUint32(10, true);
  return Math.min(maxBytes, HEADER_LEN + nameLen + encLen);
}
function readBitsFromCarrier(carrier, offset, byteCount) {
  const out = new Uint8Array(byteCount);
  for (let i = 0; i < byteCount; i++) {
    let v = 0;
    for (let k = 0; k < 8; k++) v = (v << 1) | carrier.bit(offset + i * 8 + k);
    out[i] = v;
  }
  return out;
}

async function doExtract() {
  if (!extractFile) return toast("Please choose a stego media file.", true);
  const pass = $("extractPass").value || "";
  const busy = $("extractBusy"), btn = $("extractBtn");
  btn.disabled = true; busy.classList.remove("hidden");

  try {
    let pkgInfo;
    if (/\.avi$/i.test(extractFile.name) || extractFile.type === "video/x-msvideo") {
      pkgInfo = readPackage(await extractVideo(extractFile), pass);
    } else if ((extractFile.type && extractFile.type.startsWith("image/")) || /\.(png|jpe?g|bmp|webp|gif)$/i.test(extractFile.name)) {
      const carrier = await loadImageCarrier(extractFile);
      const bits = new Uint8Array(Math.min(carrier.n, pkgNeededLen(carrier) * 8));
      for (let i = 0; i < bits.length; i++) bits[i] = carrier.bit(i);
      pkgInfo = readPackage(readPackageBits(bits), pass);
    } else {
      const carrier = await loadAudioCarrier(extractFile);
      const bits = new Uint8Array(Math.min(carrier.n, pkgNeededLen(carrier) * 8));
      for (let i = 0; i < bits.length; i++) bits[i] = carrier.bit(i);
      pkgInfo = readPackage(readPackageBits(bits), pass);
    }

    if (pkgInfo.kind === 0) {
      const text = dec8.decode(pkgInfo.data);
      const resEl = $("extractResult");
      resEl.style.display = "block";
      resEl.innerHTML = '<div class="res-title">✔ Secret extracted</div>';
      const pre = document.createElement("pre");
      pre.textContent = text;
      resEl.appendChild(pre);
      toast("Message extracted.");
    } else {
      const mime = guessMime(pkgInfo.name);
      showResult("extractResult", "✔ File extracted — " + esc(pkgInfo.name) + " (" + fmtBytes(pkgInfo.data.length) + "):", {
        name: pkgInfo.name,
        blob: new Blob([pkgInfo.data], mime ? { type: mime } : undefined),
        type: mime.startsWith("image/") ? "image" : mime.startsWith("video/") ? "video" : mime.startsWith("audio/") ? "audio" : "file"
      }, false);
      toast("File extracted.");
    }
  } catch (e) {
    showError("extractResult", e.message || String(e));
  } finally {
    btn.disabled = false; busy.classList.add("hidden");
  }
}

/* ─────────────────────────────────────────────
   RESULT RENDERING + download
   ───────────────────────────────────────────── */
function showResult(containerId, title, res, isEmbed) {
  const el = $(containerId);
  el.style.display = "block";
  el.innerHTML = "";
  const h = document.createElement("div");
  h.className = "res-title";
  h.innerHTML = title;
  el.appendChild(h);

  if (res.type === "image") {
    const img = document.createElement("img");
    img.src = URL.createObjectURL(res.blob);
    el.appendChild(img);
  } else if (res.type === "audio") {
    const a = document.createElement("audio");
    a.controls = true; a.src = URL.createObjectURL(res.blob);
    el.appendChild(a);
  } else if (res.type === "video") {
    if (!isEmbed) {
      const v = document.createElement("video");
      v.controls = true; v.src = URL.createObjectURL(res.blob);
      el.appendChild(v);
    } else {
      const note = document.createElement("div");
      note.className = "note";
      note.textContent = "Lossless uncompressed AVI — browsers can't play AVI directly; download and open with a player like VLC. The hidden data survives perfectly.";
      el.appendChild(note);
    }
  }

  const dl = document.createElement("a");
  dl.className = "download";
  dl.href = URL.createObjectURL(res.blob);
  dl.download = res.name;
  dl.textContent = "⬇  Download " + res.name;
  el.appendChild(dl);
}

function showError(containerId, msg) {
  const el = $(containerId);
  el.style.display = "block";
  el.innerHTML = '<div class="res-title err">✖ ' + esc(msg) + "</div>";
}

/* ─────────────────────────────────────────────
   WIRING / INIT
   ───────────────────────────────────────────── */
window.addEventListener("DOMContentLoaded", () => {
  const cover = $("coverSeg");
  cover.querySelectorAll("button").forEach(b =>
    b.addEventListener("click", () => {
      cover.querySelectorAll("button").forEach(x => x.classList.remove("active"));
      b.classList.add("active");
      setCover(b.dataset.cover);
    }));

  const pay = $("payloadSeg");
  pay.querySelectorAll("button").forEach(b =>
    b.addEventListener("click", () => {
      pay.querySelectorAll("button").forEach(x => x.classList.remove("active"));
      b.classList.add("active");
      setPayloadMode(b.dataset.payload);
    }));

  const ft = $("fileTypeSeg");
  ft.querySelectorAll("button").forEach(b =>
    b.addEventListener("click", () => {
      ft.querySelectorAll("button").forEach(x => x.classList.remove("active"));
      b.classList.add("active");
      setPayloadFileType(b.dataset.filetype);
    }));

  wireDrop("coverDrop", "coverFile", f => {
    coverFile = f;
    $("coverDrop").classList.add("has-file");
    previewCover(f, "coverPreview");
    updateMeter();
  });

  wireDrop("payloadDrop", "payloadFile", f => {
    payloadFile = f;
    const info = $("payloadFileInfo");
    info.style.display = "flex";
    info.innerHTML = "";
    if (f.type && f.type.startsWith("image/")) {
      const img = document.createElement("img");
      img.src = URL.createObjectURL(f);
      info.appendChild(img);
    }
    const txt = document.createElement("span");
    txt.innerHTML = "<b>" + esc(f.name) + "</b> · " + fmtBytes(f.size);
    if (f.type) txt.innerHTML += "<br>" + f.type;
    info.appendChild(txt);
    updateMeter();
  });

  wireDrop("extractDrop", "extractFile", f => {
    extractFile = f;
    $("extractDrop").classList.add("has-file");
    previewCover(f, "extractPreview");
  });

  $("secretText").addEventListener("input", updateMeter);

  setCover("image");
});