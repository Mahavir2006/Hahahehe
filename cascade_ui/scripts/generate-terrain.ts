/**
 * Bakes the synthetic shaded-relief textures used by the prototype terrain map.
 *
 *   node --experimental-strip-types scripts/generate-terrain.ts
 *
 * The relief is procedural and aligned with src/components/terrain/geography.ts
 * (river valleys, reservoir basin, built-up area). It does not depict a real
 * location. Requires ImageMagick (`magick`) for WebP encoding.
 */
import { execFileSync } from "node:child_process"
import { mkdirSync, rmSync, writeFileSync } from "node:fs"
import {
  GROUND_EXTENT,
  REGION_EXTENT,
  VILLAGES,
  cityArea,
  distToSegment,
  pointInPolygon,
  reservoir,
  rivers,
  rng,
  type Extent,
  type Pt,
} from "../src/components/terrain/geography.ts"

const OUT_DIR = "src/components/terrain/assets"
type RGB = [number, number, number]

/* Noise ------------------------------------------------------------------ */

function simplex(seed: number) {
  const random = rng(seed)
  const p = Array.from({ length: 256 }, (_, i) => i)
  for (let i = 255; i > 0; i--) {
    const j = Math.floor(random() * (i + 1))
    ;[p[i], p[j]] = [p[j], p[i]]
  }
  const perm = new Uint8Array(512)
  for (let i = 0; i < 512; i++) perm[i] = p[i & 255]
  const gx = [1, -1, 1, -1, 1, -1, 0, 0]
  const gy = [1, 1, -1, -1, 0, 0, 1, -1]
  const F2 = 0.5 * (Math.sqrt(3) - 1)
  const G2 = (3 - Math.sqrt(3)) / 6
  return (xin: number, yin: number) => {
    const s = (xin + yin) * F2
    const i = Math.floor(xin + s)
    const j = Math.floor(yin + s)
    const t = (i + j) * G2
    const x0 = xin - (i - t)
    const y0 = yin - (j - t)
    const i1 = x0 > y0 ? 1 : 0
    const j1 = x0 > y0 ? 0 : 1
    const x1 = x0 - i1 + G2
    const y1 = y0 - j1 + G2
    const x2 = x0 - 1 + 2 * G2
    const y2 = y0 - 1 + 2 * G2
    const ii = i & 255
    const jj = j & 255
    let n = 0
    let t0 = 0.5 - x0 * x0 - y0 * y0
    if (t0 > 0) {
      const g = perm[ii + perm[jj]] & 7
      t0 *= t0
      n += t0 * t0 * (gx[g] * x0 + gy[g] * y0)
    }
    let t1 = 0.5 - x1 * x1 - y1 * y1
    if (t1 > 0) {
      const g = perm[ii + i1 + perm[jj + j1]] & 7
      t1 *= t1
      n += t1 * t1 * (gx[g] * x1 + gy[g] * y1)
    }
    let t2 = 0.5 - x2 * x2 - y2 * y2
    if (t2 > 0) {
      const g = perm[ii + 1 + perm[jj + 1]] & 7
      t2 *= t2
      n += t2 * t2 * (gx[g] * x2 + gy[g] * y2)
    }
    return 70 * n
  }
}

type Noise = ReturnType<typeof simplex>
const warpX = simplex(11)
const warpY = simplex(12)
const baseNoise = simplex(13)
const ridgeNoise = simplex(14)
const vegetationNoise = simplex(15)
const fineNoise = simplex(16)
const fieldNoise = simplex(17)

function fbm(noise: Noise, x: number, y: number, octaves: number) {
  let amplitude = 1
  let frequency = 1
  let sum = 0
  let norm = 0
  for (let o = 0; o < octaves; o++) {
    sum += amplitude * noise(x * frequency, y * frequency)
    norm += amplitude
    amplitude *= 0.5
    frequency *= 2.03
  }
  return sum / norm
}

function ridged(noise: Noise, x: number, y: number, octaves: number) {
  let amplitude = 0.5
  let frequency = 1
  let sum = 0
  let weight = 1
  for (let o = 0; o < octaves; o++) {
    let n = 1 - Math.abs(noise(x * frequency, y * frequency))
    n *= n * weight
    weight = Math.max(0, Math.min(1, n * 1.8))
    sum += n * amplitude
    amplitude *= 0.5
    frequency *= 2.1
  }
  return sum
}

const smooth = (e0: number, e1: number, v: number) => {
  const t = Math.max(0, Math.min(1, (v - e0) / (e1 - e0)))
  return t * t * (3 - 2 * t)
}
const mix = (a: number, b: number, t: number) => a + (b - a) * t
const mixRGB = (a: RGB, b: RGB, t: number): RGB => [mix(a[0], b[0], t), mix(a[1], b[1], t), mix(a[2], b[2], t)]
const hash = (n: number) => {
  const s = Math.sin(n * 127.1 + 311.7) * 43758.5453
  return s - Math.floor(s)
}

/* Distance fields --------------------------------------------------------- */

interface Field {
  x0: number
  y0: number
  step: number
  nx: number
  ny: number
  data: Float32Array
}

function makeField(ext: Extent, step: number): Field {
  const nx = Math.ceil((ext.x1 - ext.x0) / step) + 1
  const ny = Math.ceil((ext.y1 - ext.y0) / step) + 1
  return { x0: ext.x0, y0: ext.y0, step, nx, ny, data: new Float32Array(nx * ny).fill(1e4) }
}

function splat(field: Field, line: Pt[], radius: number, closed = false) {
  const count = closed ? line.length : line.length - 1
  for (let s = 0; s < count; s++) {
    const a = line[s]
    const b = line[(s + 1) % line.length]
    const i0 = Math.max(0, Math.floor((Math.min(a[0], b[0]) - radius - field.x0) / field.step))
    const i1 = Math.min(field.nx - 1, Math.ceil((Math.max(a[0], b[0]) + radius - field.x0) / field.step))
    const j0 = Math.max(0, Math.floor((Math.min(a[1], b[1]) - radius - field.y0) / field.step))
    const j1 = Math.min(field.ny - 1, Math.ceil((Math.max(a[1], b[1]) + radius - field.y0) / field.step))
    for (let j = j0; j <= j1; j++) {
      for (let i = i0; i <= i1; i++) {
        const d = distToSegment([field.x0 + i * field.step, field.y0 + j * field.step], a, b)
        const k = j * field.nx + i
        if (d < field.data[k]) field.data[k] = d
      }
    }
  }
}

function signPolygon(field: Field, poly: Pt[], margin: number) {
  const xs = poly.map((p) => p[0])
  const ys = poly.map((p) => p[1])
  const i0 = Math.max(0, Math.floor((Math.min(...xs) - margin - field.x0) / field.step))
  const i1 = Math.min(field.nx - 1, Math.ceil((Math.max(...xs) + margin - field.x0) / field.step))
  const j0 = Math.max(0, Math.floor((Math.min(...ys) - margin - field.y0) / field.step))
  const j1 = Math.min(field.ny - 1, Math.ceil((Math.max(...ys) + margin - field.y0) / field.step))
  for (let j = j0; j <= j1; j++) {
    for (let i = i0; i <= i1; i++) {
      if (pointInPolygon([field.x0 + i * field.step, field.y0 + j * field.step], poly)) field.data[j * field.nx + i] *= -1
    }
  }
}

function sample(field: Field, x: number, y: number) {
  const fx = Math.max(0, Math.min(field.nx - 1.001, (x - field.x0) / field.step))
  const fy = Math.max(0, Math.min(field.ny - 1.001, (y - field.y0) / field.step))
  const i = Math.floor(fx)
  const j = Math.floor(fy)
  const tx = fx - i
  const ty = fy - j
  const k = j * field.nx + i
  const d = field.data
  return mix(mix(d[k], d[k + 1], tx), mix(d[k + field.nx], d[k + field.nx + 1], tx), ty)
}

console.time("fields")
const fieldExtent = GROUND_EXTENT
const mainRiver = makeField(fieldExtent, 2.5)
const tributaries = makeField(fieldExtent, 2.5)
const streams = makeField(fieldExtent, 2.5)
const lakeField = makeField(fieldExtent, 2.5)
const cityField = makeField(fieldExtent, 2.5)
for (const river of rivers) {
  if (river.id === "main") splat(mainRiver, river.points, 175)
  else if (river.id === "stream") splat(streams, river.points, 90)
  else splat(tributaries, river.points, 120)
}
splat(lakeField, reservoir, 60, true)
signPolygon(lakeField, reservoir, 2)
splat(cityField, cityArea, 90, true)
signPolygon(cityField, cityArea, 2)
console.timeEnd("fields")

/* Terrain model ----------------------------------------------------------- */

function height(x: number, y: number) {
  const wx = x + 36 * fbm(warpX, x / 260, y / 260, 4)
  const wy = y + 36 * fbm(warpY, x / 260, y / 260, 4)
  const broad = fbm(baseNoise, wx / 340, wy / 340, 3)
  const detail = fbm(baseNoise, wx / 120 + 17, wy / 120 - 9, 4)
  const ridge = ridged(ridgeNoise, wx / 190, wy / 190, 5)
  const bump = (cx: number, cy: number, r: number) => Math.exp(-((x - cx) ** 2 + (y - cy) ** 2) / (2 * r * r))
  const north = smooth(560, 60, y)
  const relief = Math.min(
    1.25,
    1.0 * bump(250, 150, 160) +
      0.62 * bump(482, 118, 100) +
      0.72 * bump(690, 112, 145) +
      0.5 * bump(860, 175, 100) +
      0.42 * bump(262, 598, 100) +
      0.34 * bump(108, 300, 110) +
      0.14 * north,
  )
  let h = 0.13 + 0.11 * broad + 0.025 * detail + relief * (0.66 * ridge + 0.14 * detail + 0.05)

  const dm = sample(mainRiver, x, y)
  const dt = sample(tributaries, x, y)
  const ds = sample(streams, x, y)
  const valley = Math.max(Math.exp(-((dm / 82) ** 2)), 0.8 * Math.exp(-((dt / 46) ** 2)), 0.6 * Math.exp(-((ds / 30) ** 2)))
  h -= valley * 0.5 * Math.max(0, h - 0.06)
  const floor = Math.max(Math.exp(-((dm / 26) ** 2)), 0.8 * Math.exp(-((dt / 14) ** 2)), 0.6 * Math.exp(-((ds / 9) ** 2)))
  h = mix(h, 0.06 + 0.12 * north, floor * 0.85)

  const city = smooth(50, -25, sample(cityField, x, y))
  h = mix(h, 0.09 + 0.02 * broad, city * 0.8)
  const lake = smooth(22, -4, sample(lakeField, x, y))
  return mix(h, 0.02, lake * 0.95)
}

const RAMP: Array<[number, RGB]> = [
  [0.0, [38, 54, 46]],
  [0.12, [44, 60, 47]],
  [0.24, [55, 64, 48]],
  [0.36, [66, 68, 53]],
  [0.5, [78, 75, 63]],
  [0.64, [92, 89, 81]],
  [0.8, [112, 111, 105]],
  [1.0, [142, 143, 139]],
]
const FOREST: RGB = [26, 42, 35]
const RIPARIAN: RGB = [30, 50, 40]
const WATER: RGB = [19, 43, 58]
const URBAN: RGB = [82, 81, 76]
const PASTURE: RGB = [52, 66, 46]
const PARCELS: RGB[] = [
  [64, 74, 50],
  [80, 79, 56],
  [54, 66, 46],
  [92, 86, 63],
  [60, 70, 52],
  [74, 84, 57],
  [98, 92, 70],
  [50, 62, 47],
]

function fieldBlock(x: number, y: number) {
  const size = 85
  const gx = Math.floor(x / size)
  const gy = Math.floor(y / size)
  let best = Infinity
  let second = Infinity
  let block = { id: 0, x: 0, y: 0 }
  for (let oy = -1; oy <= 1; oy++) {
    for (let ox = -1; ox <= 1; ox++) {
      const cx = gx + ox
      const cy = gy + oy
      const px = (cx + 0.15 + 0.7 * hash(cx * 91.7 + cy * 13.3)) * size
      const py = (cy + 0.15 + 0.7 * hash(cx * 27.1 + cy * 61.9)) * size
      const d = Math.hypot(x - px, y - py)
      if (d < best) {
        second = best
        best = d
        block = { id: cx * 131 + cy * 977, x: px, y: py }
      } else if (d < second) second = d
    }
  }
  return {
    ...block,
    angle: -0.75 + hash(block.id * 3.3) * 1.5,
    row: 11 + hash(block.id * 1.7) * 8,
    farmed: hash(block.id * 5.9) > 0.22,
    edge: (second - best) * 0.5,
  }
}

function ramp(h: number): RGB {
  if (h <= RAMP[0][0]) return RAMP[0][1]
  for (let i = 1; i < RAMP.length; i++) {
    if (h <= RAMP[i][0]) return mixRGB(RAMP[i - 1][1], RAMP[i][1], (h - RAMP[i - 1][0]) / (RAMP[i][0] - RAMP[i - 1][0]))
  }
  return RAMP[RAMP.length - 1][1]
}

function render(ext: Extent, pxPerUnit: number) {
  const w = Math.round((ext.x1 - ext.x0) * pxPerUnit)
  const h = Math.round((ext.y1 - ext.y0) * pxPerUnit)
  const heights = new Float32Array(w * h)
  for (let j = 0; j < h; j++) {
    const y = ext.y0 + (j + 0.5) / pxPerUnit
    for (let i = 0; i < w; i++) heights[j * w + i] = height(ext.x0 + (i + 0.5) / pxPerUnit, y)
  }

  const rgb = new Uint8Array(w * h * 3)
  const exaggeration = 110
  const light = [-0.55, -0.7, 0.85]
  const ll = Math.hypot(light[0], light[1], light[2])
  const interval = 0.035
  const urbanAngle = -0.3
  const uc = Math.cos(urbanAngle)
  const us = Math.sin(urbanAngle)

  for (let j = 0; j < h; j++) {
    const y = ext.y0 + (j + 0.5) / pxPerUnit
    for (let i = 0; i < w; i++) {
      const x = ext.x0 + (i + 0.5) / pxPerUnit
      const k = j * w + i
      const hv = heights[k]
      const hx = (heights[j * w + Math.min(w - 1, i + 1)] - heights[j * w + Math.max(0, i - 1)]) * (pxPerUnit / 2)
      const hy = (heights[Math.min(h - 1, j + 1) * w + i] - heights[Math.max(0, j - 1) * w + i]) * (pxPerUnit / 2)
      const slope = Math.hypot(hx, hy)
      const nx = -hx * exaggeration
      const ny = -hy * exaggeration
      const nl = Math.hypot(nx, ny, 1)
      const shade = Math.max(0, (nx * light[0] + ny * light[1] + light[2]) / (nl * ll))

      const dm = sample(mainRiver, x, y)
      const dt = sample(tributaries, x, y)
      const ds = sample(streams, x, y)
      const lakeD = sample(lakeField, x, y)
      const city = smooth(4, -12, sample(cityField, x, y) + 11 * fbm(fineNoise, x / 38, y / 38, 3))
      const lake = smooth(0.8, -0.8, lakeD)
      let village = 0
      for (const [vx, vy, count, spread] of VILLAGES) {
        const d2 = ((x - vx) ** 2 + ((y - vy) / 0.8) ** 2) / (spread * spread)
        if (d2 < 2.5) village = Math.max(village, Math.exp(-d2 * 1.6) * Math.min(1, count / 14))
      }

      let c = ramp(hv)
      // Forest favours slopes and uplands, with crisp edges like aerial imagery.
      const vegetation = fbm(vegetationNoise, x / 52, y / 52, 5)
      const forestChance = 0.55 * vegetation + 0.9 * smooth(0.003, 0.011, slope) + 0.35 * smooth(0.22, 0.4, hv) - 0.25
      const forest = smooth(0.08, 0.2, forestChance) * (1 - smooth(0.56, 0.72, hv)) * (1 - city)
      c = mixRGB(c, FOREST, forest * 0.68)

      const fieldMask = (1 - smooth(0.004, 0.009, slope)) * (1 - smooth(0.22, 0.34, hv)) * (1 - forest) * (1 - city) * (1 - lake)
      if (fieldMask > 0.01) {
        // Irregular field blocks: each block has its own orientation and parcel rhythm.
        const block = fieldBlock(x, y)
        if (block.farmed) {
          const ca = Math.cos(block.angle)
          const sa = Math.sin(block.angle)
          const u = (x - block.x) * ca + (y - block.y) * sa
          const v = -(x - block.x) * sa + (y - block.y) * ca
          const row = Math.floor(v / block.row)
          const cellWidth = 14 + hash(block.id + row * 3.1) * 24
          const offset = hash(block.id + row * 7.7) * cellWidth
          const col = Math.floor((u + offset) / cellWidth)
          const parcel = PARCELS[Math.floor(hash(block.id + row * 31.7 + col * 17.3) * PARCELS.length)]
          const fu = (u + offset) / cellWidth - col
          const fv = v / block.row - row
          const edge = Math.min(fu * cellWidth, (1 - fu) * cellWidth, fv * block.row, (1 - fv) * block.row, block.edge)
          const furrow = 1 + 0.045 * Math.sin(u * 2.3)
          c = mixRGB(c, [parcel[0] * furrow, parcel[1] * furrow, parcel[2] * furrow], fieldMask * 0.5)
          const hedge = (1 - smooth(0.2, 0.8, edge)) * fieldMask * 0.2
          c = [c[0] * (1 - hedge), c[1] * (1 - hedge), c[2] * (1 - hedge)]
        } else {
          c = mixRGB(c, PASTURE, fieldMask * 0.35)
        }
      }

      const riparian = Math.max(Math.exp(-((dm / 10) ** 2)), 0.7 * Math.exp(-((dt / 7) ** 2)), 0.5 * Math.exp(-((ds / 5) ** 2)))
      c = mixRGB(c, RIPARIAN, riparian * 0.55)

      if (city > 0.01) {
        // Superblocks with irregular subdivision; avenues separate the blocks.
        const bu = (x * uc + y * us) / 15
        const bv = (-x * us + y * uc) / 13
        const su = Math.floor(bu)
        const sv = Math.floor(bv)
        const nu = 2 + Math.floor(hash(su * 3.7 + sv * 9.1) * 3)
        const nv = 2 + Math.floor(hash(su * 5.3 + sv * 2.9) * 2)
        const lu = (bu - su) * nu
        const lv = (bv - sv) * nv
        const avenue = bu - su < 0.06 || bv - sv < 0.07
        const lane = lu - Math.floor(lu) < 0.1 || lv - Math.floor(lv) < 0.1
        const tone = 0.86 + 0.24 * hash(su * 17 + sv * 31 + Math.floor(lu) * 7 + Math.floor(lv) * 3)
        let urban: RGB = [URBAN[0] * tone, URBAN[1] * tone, URBAN[2] * tone]
        if (lane) urban = [urban[0] * 0.84, urban[1] * 0.84, urban[2] * 0.84]
        if (avenue) urban = [66, 68, 66]
        urban = mixRGB(urban, FOREST, smooth(0.15, 0.45, fbm(vegetationNoise, x / 18, y / 18, 2)) * 0.5)
        c = mixRGB(c, urban, city * 0.74)
      }
      if (village > 0.02) {
        const speck = hash(Math.floor(x / 2.4) * 7.1 + Math.floor(y / 2.2) * 3.7)
        if (speck > 0.55) c = mixRGB(c, [URBAN[0] * (0.9 + 0.3 * speck), URBAN[1] * (0.9 + 0.3 * speck), URBAN[2] * (0.9 + 0.3 * speck)], village * 0.7)
      }

      const detail = 1 + 0.07 * fineNoise(x / 2.2, y / 2.2)
      const lit = (0.26 + 1.0 * shade) * detail
      c = [c[0] * lit, c[1] * lit, c[2] * lit]

      const water = Math.max(lake, smooth(2.5, 0.9, dm), smooth(1.8, 0.4, dt), smooth(1.3, 0.2, ds))
      if (water > 0) c = mixRGB(c, WATER, water)

      if (city < 0.5 && lake < 0.5) {
        const level = hv / interval
        const frac = Math.abs(level - Math.round(level))
        const pixels = (frac * interval * pxPerUnit) / Math.max(slope, 1e-5)
        const line = 1 - smooth(0.35, 1.1, pixels)
        if (line > 0) {
          const strength = Math.round(level) % 5 === 0 ? 0.2 : 0.1
          const f = 1 - line * strength
          c = [c[0] * f, c[1] * f, c[2] * f]
        }
      }

      rgb[k * 3] = Math.max(0, Math.min(255, c[0] * 0.92 * 0.93))
      rgb[k * 3 + 1] = Math.max(0, Math.min(255, c[1] * 0.92 * 0.99))
      rgb[k * 3 + 2] = Math.max(0, Math.min(255, c[2] * 0.92 * 1.04 + 2))
    }
  }
  return { w, h, rgb }
}

function encode(name: string, image: ReturnType<typeof render>, quality: number) {
  const tmp = `/tmp/${name}.ppm`
  writeFileSync(tmp, Buffer.concat([Buffer.from(`P6\n${image.w} ${image.h}\n255\n`), Buffer.from(image.rgb.buffer)]))
  execFileSync("magick", [tmp, "-quality", String(quality), `${OUT_DIR}/${name}.webp`])
  rmSync(tmp)
  console.log(`${name}.webp ${image.w}x${image.h}`)
}

mkdirSync(OUT_DIR, { recursive: true })
console.time("region")
encode("relief-region", render(REGION_EXTENT, 2.4), 80)
console.timeEnd("region")
console.time("ground")
encode("relief-ground", render(GROUND_EXTENT, 0.75), 74)
console.timeEnd("ground")
