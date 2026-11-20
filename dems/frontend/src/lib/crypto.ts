/**
 * Client-side SHA-256 pre-hashing for evidence uploads.
 *
 * Why two code paths?  `window.crypto.subtle.digest` is the fastest, audited implementation, but it
 * is one-shot: it needs the whole input in memory and has no incremental (update/final) API. So:
 *
 *   - files up to SUBTLE_MAX_BYTES are read in chunks (with progress) and hashed natively with
 *     `crypto.subtle.digest`;
 *   - larger files, and pages where SubtleCrypto is unavailable (it requires a secure context:
 *     https or localhost), are hashed incrementally with the `Sha256` class below, which uses
 *     constant memory (one chunk at a time) and yields to the event loop between chunks.
 *
 * Both paths produce identical lowercase hex digests (verified against Node's crypto in tests).
 * The server recomputes the hash independently; this value is the submitter's claim of what they sent.
 */

export interface HashProgress {
  loaded: number
  total: number
  /** 0..1 */
  fraction: number
}

export interface HashOptions {
  onProgress?: (progress: HashProgress) => void
  signal?: AbortSignal
  /** Read size per chunk. Default 4 MiB. */
  chunkSize?: number
  /** Force the incremental JS implementation (used by tests). */
  forceIncremental?: boolean
}

export const DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024
export const SUBTLE_MAX_BYTES = 64 * 1024 * 1024

export class HashAbortedError extends Error {
  constructor() {
    super('Hashing was cancelled')
    this.name = 'HashAbortedError'
  }
}

// --------------------------------------------------------------------------------------------
// Incremental SHA-256 (FIPS 180-4)
// --------------------------------------------------------------------------------------------
// prettier-ignore
const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
])

const rotr = (x: number, n: number): number => (x >>> n) | (x << (32 - n))

export class Sha256 {
  private readonly h = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ])
  private readonly block = new Uint8Array(64)
  private readonly w = new Uint32Array(64)
  private blockLength = 0
  private total = 0
  private finished = false

  update(data: Uint8Array): this {
    if (this.finished) throw new Error('Sha256: update() after digest()')
    let offset = 0
    this.total += data.length

    if (this.blockLength > 0) {
      const take = Math.min(64 - this.blockLength, data.length)
      this.block.set(data.subarray(0, take), this.blockLength)
      this.blockLength += take
      offset = take
      if (this.blockLength === 64) {
        this.compress(this.block, 0)
        this.blockLength = 0
      }
    }
    while (offset + 64 <= data.length) {
      this.compress(data, offset)
      offset += 64
    }
    if (offset < data.length) {
      this.block.set(data.subarray(offset), 0)
      this.blockLength = data.length - offset
    }
    return this
  }

  digest(): Uint8Array {
    if (this.finished) throw new Error('Sha256: digest() already called')
    this.finished = true

    const bitsHigh = Math.floor(this.total / 0x20000000) // total * 8 / 2^32
    const bitsLow = (this.total * 8) >>> 0

    this.block[this.blockLength] = 0x80
    this.block.fill(0, this.blockLength + 1)
    if (this.blockLength + 1 > 56) {
      this.compress(this.block, 0)
      this.block.fill(0)
    }
    const view = new DataView(this.block.buffer)
    view.setUint32(56, bitsHigh >>> 0, false)
    view.setUint32(60, bitsLow, false)
    this.compress(this.block, 0)

    const out = new Uint8Array(32)
    const outView = new DataView(out.buffer)
    for (let i = 0; i < 8; i += 1) outView.setUint32(i * 4, this.h[i] ?? 0, false)
    return out
  }

  digestHex(): string {
    return bytesToHex(this.digest())
  }

  private compress(buf: Uint8Array, offset: number): void {
    const w = this.w
    for (let i = 0; i < 16; i += 1) {
      const o = offset + i * 4
      w[i] = ((buf[o]! << 24) | (buf[o + 1]! << 16) | (buf[o + 2]! << 8) | buf[o + 3]!) | 0
    }
    for (let i = 16; i < 64; i += 1) {
      const w15 = w[i - 15]!
      const w2 = w[i - 2]!
      const s0 = rotr(w15, 7) ^ rotr(w15, 18) ^ (w15 >>> 3)
      const s1 = rotr(w2, 17) ^ rotr(w2, 19) ^ (w2 >>> 10)
      w[i] = (w[i - 16]! + s0 + w[i - 7]! + s1) | 0
    }

    const h = this.h
    let a = h[0]!, b = h[1]!, c = h[2]!, d = h[3]!, e = h[4]!, f = h[5]!, g = h[6]!, hh = h[7]!
    for (let i = 0; i < 64; i += 1) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
      const ch = (e & f) ^ (~e & g)
      const t1 = (hh + S1 + ch + K[i]! + w[i]!) | 0
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
      const maj = (a & b) ^ (a & c) ^ (b & c)
      const t2 = (S0 + maj) | 0
      hh = g; g = f; f = e
      e = (d + t1) | 0
      d = c; c = b; b = a
      a = (t1 + t2) | 0
    }
    h[0] = (h[0]! + a) | 0; h[1] = (h[1]! + b) | 0; h[2] = (h[2]! + c) | 0; h[3] = (h[3]! + d) | 0
    h[4] = (h[4]! + e) | 0; h[5] = (h[5]! + f) | 0; h[6] = (h[6]! + g) | 0; h[7] = (h[7]! + hh) | 0
  }
}

// --------------------------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------------------------
export function bytesToHex(bytes: Uint8Array): string {
  let out = ''
  for (const b of bytes) out += b.toString(16).padStart(2, '0')
  return out
}

export function isSubtleCryptoAvailable(): boolean {
  return typeof globalThis.crypto !== 'undefined' && typeof globalThis.crypto.subtle?.digest === 'function'
}

export function isValidSha256Hex(value: string): boolean {
  return /^[0-9a-f]{64}$/.test(value)
}

/** Constant-time comparison of two hex digests (avoids early-exit timing differences). */
export function hashesEqual(a: string, b: string): boolean {
  const x = a.toLowerCase()
  const y = b.toLowerCase()
  if (x.length !== y.length) return false
  let diff = 0
  for (let i = 0; i < x.length; i += 1) diff |= x.charCodeAt(i) ^ y.charCodeAt(i)
  return diff === 0
}

const nextTick = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0))

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new HashAbortedError()
}

async function readChunk(blob: Blob, start: number, end: number): Promise<Uint8Array> {
  return new Uint8Array(await blob.slice(start, end).arrayBuffer())
}

// --------------------------------------------------------------------------------------------
// Public API
// --------------------------------------------------------------------------------------------
export async function sha256Bytes(data: ArrayBuffer | Uint8Array): Promise<string> {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data)
  if (isSubtleCryptoAvailable()) {
    const view = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer
    return bytesToHex(new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', view)))
  }
  return new Sha256().update(bytes).digestHex()
}

/** SHA-256 of a File/Blob as lowercase hex, with progress and cancellation. */
export async function sha256File(file: Blob, options: HashOptions = {}): Promise<string> {
  const { onProgress, signal, chunkSize = DEFAULT_CHUNK_SIZE, forceIncremental = false } = options
  const total = file.size
  const report = (loaded: number): void =>
    onProgress?.({ loaded, total, fraction: total === 0 ? 1 : Math.min(loaded / total, 1) })

  throwIfAborted(signal)
  report(0)

  const useSubtle = !forceIncremental && isSubtleCryptoAvailable() && total <= SUBTLE_MAX_BYTES
  if (useSubtle) {
    // Chunked read (progress + cancellation), then one native digest call.
    const buffer = new Uint8Array(total)
    for (let offset = 0; offset < total; offset += chunkSize) {
      throwIfAborted(signal)
      const chunk = await readChunk(file, offset, Math.min(offset + chunkSize, total))
      buffer.set(chunk, offset)
      report(offset + chunk.length)
    }
    throwIfAborted(signal)
    return bytesToHex(new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', buffer)))
  }

  // Constant-memory streaming path.
  const hasher = new Sha256()
  let loaded = 0
  for (let offset = 0; offset < total; offset += chunkSize) {
    throwIfAborted(signal)
    const chunk = await readChunk(file, offset, Math.min(offset + chunkSize, total))
    hasher.update(chunk)
    loaded += chunk.length
    report(loaded)
    await nextTick() // keep the UI responsive
  }
  throwIfAborted(signal)
  return hasher.digestHex()
}
