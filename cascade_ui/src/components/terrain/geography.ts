/**
 * Synthetic geography for the CascadeShield prototype terrain.
 *
 * Coordinates are abstract plane units on a 1000 x 700 canvas. None of these
 * shapes represent a real place. The same model drives the interactive map and
 * scripts/generate-terrain.ts, which bakes the matching shaded-relief texture.
 * Keep this module free of browser and bundler imports so Node can run it.
 */

export type Pt = [number, number]
export type ZoneOrg = "WGEC" | "MetroWater" | "CCMN" | null

export interface Extent {
  x0: number
  y0: number
  x1: number
  y1: number
}

/** Area covered by the high-resolution relief texture (the raised region). */
export const REGION_EXTENT: Extent = { x0: 40, y0: 30, x1: 980, y1: 680 }
/** Area covered by the low-resolution context texture (surrounding ground). */
export const GROUND_EXTENT: Extent = { x0: -280, y0: -260, x1: 1280, y1: 960 }

export function rng(seed: number): () => number {
  let s = seed >>> 0
  return () => {
    s = (s + 0x6d2b79f5) >>> 0
    let t = s
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

export const dist = (a: Pt, b: Pt) => Math.hypot(a[0] - b[0], a[1] - b[1])

export function catmullRom(ctrl: Pt[], closed: boolean, step = 3): Pt[] {
  const n = ctrl.length
  const at = (i: number): Pt => (closed ? ctrl[((i % n) + n) % n] : ctrl[Math.max(0, Math.min(n - 1, i))])
  const out: Pt[] = []
  const spans = closed ? n : n - 1
  for (let i = 0; i < spans; i++) {
    const p0 = at(i - 1)
    const p1 = at(i)
    const p2 = at(i + 1)
    const p3 = at(i + 2)
    const steps = Math.max(2, Math.ceil(dist(p1, p2) / step))
    for (let k = 0; k < steps; k++) {
      const t = k / steps
      const t2 = t * t
      const t3 = t2 * t
      const c = (j: 0 | 1) =>
        0.5 *
        (2 * p1[j] +
          (p2[j] - p0[j]) * t +
          (2 * p0[j] - 5 * p1[j] + 4 * p2[j] - p3[j]) * t2 +
          (3 * p1[j] - p0[j] - 3 * p2[j] + p3[j]) * t3)
      out.push([c(0), c(1)])
    }
  }
  if (!closed) out.push([ctrl[n - 1][0], ctrl[n - 1][1]])
  return out
}

function periodicNoise(seed: number, period: number) {
  const r = rng(seed)
  const values = Array.from({ length: period }, () => r() * 2 - 1)
  return (t: number) => {
    const i = Math.floor(t)
    const f = t - i
    const a = values[((i % period) + period) % period]
    const b = values[(((i + 1) % period) + period) % period]
    return a + (b - a) * f * f * (3 - 2 * f)
  }
}

/** Offsets a polyline along its normals with layered noise for natural edges. */
export function displace(points: Pt[], closed: boolean, seed: number, octaves: Array<[number, number]>): Pt[] {
  const n = points.length
  const cumulative = [0]
  for (let i = 1; i < n; i++) cumulative.push(cumulative[i - 1] + dist(points[i - 1], points[i]))
  const total = cumulative[n - 1] + (closed ? dist(points[n - 1], points[0]) : 0)
  const layers = octaves.map(([amplitude, wavelength], index) => {
    const period = Math.max(3, Math.round(total / wavelength))
    return { amplitude, period, noise: periodicNoise(seed + index * 101, period) }
  })
  return points.map((p, i) => {
    const prev = closed ? points[(i - 1 + n) % n] : points[Math.max(0, i - 1)]
    const next = closed ? points[(i + 1) % n] : points[Math.min(n - 1, i + 1)]
    const tx = next[0] - prev[0]
    const ty = next[1] - prev[1]
    const length = Math.hypot(tx, ty) || 1
    let offset = 0
    for (const layer of layers) offset += layer.amplitude * layer.noise((cumulative[i] / total) * layer.period)
    if (!closed) offset *= Math.min(1, cumulative[i] / 30, (total - cumulative[i]) / 30)
    return [p[0] - (ty / length) * offset, p[1] + (tx / length) * offset]
  })
}

export function toPath(points: Pt[], closed = false): string {
  let d = `M${points[0][0].toFixed(1)} ${points[0][1].toFixed(1)}`
  for (let i = 1; i < points.length; i++) d += `L${points[i][0].toFixed(1)} ${points[i][1].toFixed(1)}`
  return closed ? `${d}Z` : d
}

export function pointInPolygon(p: Pt, poly: Pt[]): boolean {
  let inside = false
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const [xi, yi] = poly[i]
    const [xj, yj] = poly[j]
    if (yi > p[1] !== yj > p[1] && p[0] < ((xj - xi) * (p[1] - yi)) / (yj - yi) + xi) inside = !inside
  }
  return inside
}

export function distToSegment(p: Pt, a: Pt, b: Pt): number {
  const dx = b[0] - a[0]
  const dy = b[1] - a[1]
  const l2 = dx * dx + dy * dy
  const t = l2 ? Math.max(0, Math.min(1, ((p[0] - a[0]) * dx + (p[1] - a[1]) * dy) / l2)) : 0
  return Math.hypot(p[0] - (a[0] + t * dx), p[1] - (a[1] + t * dy))
}

export function distToPolyline(p: Pt, line: Pt[]): number {
  let best = Infinity
  for (let i = 0; i < line.length - 1; i++) best = Math.min(best, distToSegment(p, line[i], line[i + 1]))
  return best
}

export function bounds(points: Pt[]): Extent {
  const out = { x0: Infinity, y0: Infinity, x1: -Infinity, y1: -Infinity }
  for (const [x, y] of points) {
    out.x0 = Math.min(out.x0, x)
    out.y0 = Math.min(out.y0, y)
    out.x1 = Math.max(out.x1, x)
    out.y1 = Math.max(out.y1, y)
  }
  return out
}

function signedArea(poly: Pt[]): number {
  let area = 0
  for (let i = 0; i < poly.length; i++) {
    const [x1, y1] = poly[i]
    const [x2, y2] = poly[(i + 1) % poly.length]
    area += x1 * y2 - x2 * y1
  }
  return area / 2
}

function centroid(poly: Pt[]): Pt {
  const area = signedArea(poly)
  let cx = 0
  let cy = 0
  for (let i = 0; i < poly.length; i++) {
    const [x1, y1] = poly[i]
    const [x2, y2] = poly[(i + 1) % poly.length]
    const cross = x1 * y2 - x2 * y1
    cx += (x1 + x2) * cross
    cy += (y1 + y2) * cross
  }
  return [cx / (6 * area), cy / (6 * area)]
}

/* ------------------------------------------------------------------------ */
/* Region outline                                                            */
/* ------------------------------------------------------------------------ */

const LAND_CTRL: Pt[] = [
  [70, 300], [92, 228], [138, 162], [198, 112], [268, 84], [338, 92], [392, 132], [440, 120],
  [498, 88], [568, 68], [640, 58], [720, 52], [798, 76], [858, 120], [880, 186], [862, 248],
  [896, 298], [938, 348], [956, 420], [936, 494], [892, 558], [822, 600], [742, 614], [672, 586],
  [610, 600], [546, 640], [470, 650], [396, 626], [330, 582], [266, 592], [196, 562], [140, 506],
  [100, 442], [74, 372],
]

export const landmass = displace(catmullRom(LAND_CTRL, true, 3), true, 7, [
  [7, 48],
  [2.6, 14],
  [1, 5],
])
export const landmassPath = toPath(landmass, true)
export const landBounds = bounds(landmass)

/* ------------------------------------------------------------------------ */
/* Water                                                                     */
/* ------------------------------------------------------------------------ */

export interface River {
  id: string
  width: number
  points: Pt[]
  d: string
}

function river(id: string, width: number, ctrl: Pt[], seed: number, meander: number): River {
  const points = displace(catmullRom(ctrl, false, 2.5), false, seed, [
    [meander, 34],
    [meander * 0.32, 10],
  ])
  return { id, width, points, d: toPath(points) }
}

export const rivers: River[] = [
  river(
    "main",
    3.4,
    [
      [238, -40], [262, 30], [290, 92], [302, 150], [330, 205], [372, 250], [408, 300], [452, 332],
      [512, 350], [570, 356], [622, 372], [662, 398], [712, 424], [770, 440], [828, 444], [884, 432],
      [944, 428], [1010, 440], [1080, 460],
    ],
    21,
    5,
  ),
  river("tributary", 2.1, [[768, 238], [758, 272], [736, 312], [712, 350], [688, 380], [662, 398]], 22, 3.5),
  river("inflow", 1.5, [[742, -40], [748, 30], [753, 80], [748, 116]], 23, 3),
  river("stream", 1.15, [[150, 660], [205, 560], [268, 500], [330, 455], [380, 392], [420, 345], [452, 332]], 24, 3),
]

const LAKE_CTRL: Pt[] = [
  [742, 112], [760, 118], [772, 138], [794, 146], [812, 140], [818, 156], [800, 172], [790, 196],
  [782, 222], [768, 234], [752, 226], [744, 204], [724, 196], [706, 186], [712, 172], [732, 168],
  [738, 146], [734, 126],
]
export const reservoir = displace(catmullRom(LAKE_CTRL, true, 2), true, 31, [
  [2.2, 16],
  [0.8, 5],
])
export const reservoirPath = toPath(reservoir, true)
export const damPath = toPath([
  [753, 232],
  [783, 229],
])

/* ------------------------------------------------------------------------ */
/* Built environment                                                         */
/* ------------------------------------------------------------------------ */

const CITY_CTRL: Pt[] = [
  [700, 398], [744, 376], [800, 372], [856, 382], [904, 404], [930, 446], [922, 498], [890, 538],
  [838, 560], [780, 562], [728, 546], [694, 512], [682, 466], [688, 428],
]
export const cityArea = displace(catmullRom(CITY_CTRL, true, 3), true, 41, [
  [5, 30],
  [2, 9],
])
export const cityPath = toPath(cityArea, true)

export interface Road {
  id: string
  tier: 1 | 2 | 3
  points: Pt[]
  d: string
}

function road(id: string, tier: 1 | 2 | 3, ctrl: Pt[], seed: number): Road {
  const points = displace(catmullRom(ctrl, false, 3), false, seed, [
    [2.2, 60],
    [0.6, 14],
  ])
  return { id, tier, points, d: toPath(points) }
}

export const roads: Road[] = [
  road(
    "highway",
    1,
    [
      [20, 395], [100, 400], [190, 410], [292, 425], [380, 410], [470, 398], [560, 408], [640, 426],
      [700, 452], [760, 486], [830, 492], [900, 476], [960, 470], [1040, 476],
    ],
    51,
  ),
  road(
    "north-south",
    2,
    [
      [520, -20], [530, 70], [526, 150], [540, 230], [556, 300], [572, 360], [566, 430], [548, 510],
      [520, 590], [500, 660], [490, 740],
    ],
    52,
  ),
  road(
    "reservoir",
    2,
    [[818, 480], [810, 420], [806, 360], [798, 300], [790, 252], [800, 210], [830, 168], [858, 128], [900, 70], [940, 10]],
    53,
  ),
  road("hydro", 2, [[292, 425], [300, 360], [298, 300], [288, 240], [272, 185], [262, 130], [246, 70], [228, -20]], 54),
  road("west", 2, [[190, 410], [170, 350], [150, 290], [140, 230], [150, 170], [130, 100], [100, 20]], 55),
  road("farm", 3, [[470, 398], [452, 470], [430, 540], [410, 620], [400, 700]], 56),
  road("logistics", 3, [[640, 426], [652, 500], [690, 560], [740, 600], [790, 680]], 57),
  road("east", 3, [[556, 300], [620, 268], [690, 262], [760, 270], [860, 250], [940, 260]], 58),
  road("catchment", 3, [[526, 150], [600, 140], [660, 120], [712, 96]], 59),
  road("south", 3, [[292, 425], [250, 500], [230, 580], [210, 680]], 60),
]

/** Transmission corridors; pylons are straight segments between towers. */
export const powerLines: Pt[][] = [
  [[322, 168], [286, 234], [250, 300], [205, 376], [160, 452]],
  [[160, 452], [232, 446], [305, 440], [400, 452], [500, 432], [596, 382]],
  [[596, 382], [662, 420], [730, 470], [800, 506], [872, 532]],
  [[322, 168], [400, 190], [470, 212], [522, 228]],
  [[522, 228], [610, 240], [700, 246], [774, 246]],
]
export const powerPath = powerLines.map((line) => toPath(line)).join("")

export const pylons: Pt[] = powerLines.flatMap((line) => {
  const out: Pt[] = []
  for (let i = 0; i < line.length - 1; i++) {
    const steps = Math.max(1, Math.round(dist(line[i], line[i + 1]) / 18))
    for (let s = 0; s < steps; s++) {
      const t = s / steps
      out.push([line[i][0] + (line[i + 1][0] - line[i][0]) * t, line[i][1] + (line[i + 1][1] - line[i][1]) * t])
    }
  }
  return out
})

/* ------------------------------------------------------------------------ */
/* Service zones (Voronoi partition of the region with organic boundaries)   */
/* ------------------------------------------------------------------------ */

export interface ZoneDef {
  id: string
  name: string
  org: ZoneOrg
  kind: string
  seed: Pt
}

export const zoneDefs: ZoneDef[] = [
  { id: "ridge", name: "Northern Ridge", org: "WGEC", kind: "Transmission uplands", seed: [205, 170] },
  { id: "hydro", name: "Ridge Hydro Works", org: "WGEC", kind: "Generation", seed: [350, 150] },
  { id: "highland", name: "Highland Reserve", org: null, kind: "Protected forest", seed: [480, 135] },
  { id: "catchment", name: "Upper Catchment", org: "MetroWater", kind: "Raw water catchment", seed: [615, 125] },
  { id: "reservoir", name: "Reservoir & Dam", org: "MetroWater", kind: "Storage and dam control", seed: [760, 175] },
  { id: "intake", name: "Eastern Intake", org: "MetroWater", kind: "Intake pumping", seed: [855, 240] },
  { id: "uplands", name: "Western Uplands", org: "WGEC", kind: "Regional operations", seed: [112, 300] },
  { id: "corridor", name: "Transmission Corridor", org: "WGEC", kind: "High-voltage corridor", seed: [245, 290] },
  { id: "control", name: "Grid Control Centre", org: "WGEC", kind: "Control and remote access", seed: [420, 230] },
  { id: "treatment", name: "Treatment Works", org: "MetroWater", kind: "Water treatment", seed: [530, 235] },
  { id: "pumping", name: "Pumping District", org: "MetroWater", kind: "Pressure management", seed: [690, 285] },
  { id: "switching", name: "Primary Switching", org: "WGEC", kind: "Substation cluster", seed: [150, 450] },
  { id: "feeder", name: "Feeder Substations", org: "WGEC", kind: "Distribution feeders", seed: [300, 440] },
  { id: "farmland", name: "Central Farmland", org: null, kind: "Agricultural", seed: [450, 430] },
  { id: "riverside", name: "Riverside Pumping", org: "MetroWater", kind: "Distribution pumping", seed: [590, 400] },
  { id: "campus", name: "Medical Campus", org: "CCMN", kind: "Clinical services", seed: [785, 470] },
  { id: "emergency", name: "Emergency Annex", org: "CCMN", kind: "Emergency care", seed: [890, 405] },
  { id: "power", name: "Backup Power Yard", org: "CCMN", kind: "Standby generation", seed: [870, 540] },
  { id: "logistics", name: "Supply & Logistics", org: "CCMN", kind: "Pharmacy and supply", seed: [745, 575] },
  { id: "hills", name: "Southern Hills", org: null, kind: "Mixed woodland", seed: [250, 565] },
  { id: "plains", name: "South Plains", org: null, kind: "Agricultural", seed: [410, 570] },
  { id: "industrial", name: "Industrial Estate", org: null, kind: "Light industry", seed: [590, 540] },
]

export interface Zone extends ZoneDef {
  points: Pt[]
  d: string
  centroid: Pt
  bounds: Extent
  area: number
}

function clipToBisector(poly: Pt[], a: Pt, b: Pt): Pt[] {
  const mx = (a[0] + b[0]) / 2
  const my = (a[1] + b[1]) / 2
  const dx = b[0] - a[0]
  const dy = b[1] - a[1]
  const side = (p: Pt) => (p[0] - mx) * dx + (p[1] - my) * dy
  const out: Pt[] = []
  for (let i = 0; i < poly.length; i++) {
    const p = poly[i]
    const q = poly[(i + 1) % poly.length]
    const sp = side(p)
    const sq = side(q)
    if (sp <= 0) out.push(p)
    if ((sp < 0 && sq > 0) || (sp > 0 && sq < 0)) {
      const t = sp / (sp - sq)
      out.push([p[0] + (q[0] - p[0]) * t, p[1] + (q[1] - p[1]) * t])
    }
  }
  return out
}

function roughen(a: Pt, b: Pt, seed: number): Pt[] {
  const r = rng(seed)
  const length = dist(a, b)
  const depth = length > 120 ? 5 : length > 50 ? 4 : length > 18 ? 3 : length > 6 ? 2 : 0
  let points: Pt[] = [a, b]
  for (let level = 0; level < depth; level++) {
    const next: Pt[] = [points[0]]
    for (let i = 0; i < points.length - 1; i++) {
      const p = points[i]
      const q = points[i + 1]
      const dx = q[0] - p[0]
      const dy = q[1] - p[1]
      const l = Math.hypot(dx, dy) || 1
      const offset = (r() * 2 - 1) * 0.17 * l
      next.push([(p[0] + q[0]) / 2 - (dy / l) * offset, (p[1] + q[1]) / 2 + (dx / l) * offset], q)
    }
    points = next
  }
  return points
}

function buildZones() {
  const vertices: Pt[] = []
  const buckets = new Map<string, number[]>()
  const vertexId = (p: Pt) => {
    const gx = Math.round(p[0] * 10)
    const gy = Math.round(p[1] * 10)
    for (let ox = -1; ox <= 1; ox++) {
      for (let oy = -1; oy <= 1; oy++) {
        for (const id of buckets.get(`${gx + ox},${gy + oy}`) ?? []) {
          if (Math.abs(vertices[id][0] - p[0]) < 0.02 && Math.abs(vertices[id][1] - p[1]) < 0.02) return id
        }
      }
    }
    const id = vertices.length
    vertices.push(p)
    const key = `${gx},${gy}`
    const bucket = buckets.get(key)
    if (bucket) bucket.push(id)
    else buckets.set(key, [id])
    return id
  }

  const cells = zoneDefs.map((zone, i) => {
    let poly = landmass
    zoneDefs.forEach((other, j) => {
      if (j !== i && poly.length) poly = clipToBisector(poly, zone.seed, other.seed)
    })
    const ids = poly.map(vertexId)
    return ids.filter((id, k) => id !== ids[(k + 1) % ids.length])
  })

  const edgeKey = (a: number, b: number) => (a < b ? `${a}:${b}` : `${b}:${a}`)
  const edgeCells = new Map<string, number[]>()
  cells.forEach((ids, cell) =>
    ids.forEach((a, k) => {
      const key = edgeKey(a, ids[(k + 1) % ids.length])
      const list = edgeCells.get(key)
      if (list) list.push(cell)
      else edgeCells.set(key, [cell])
    }),
  )

  const roughEdges = new Map<string, Pt[]>()
  const edgePoints = (a: number, b: number): Pt[] => {
    const key = edgeKey(a, b)
    if ((edgeCells.get(key)?.length ?? 0) < 2) return [vertices[a], vertices[b]]
    let points = roughEdges.get(key)
    if (!points) {
      const lo = Math.min(a, b)
      const hi = Math.max(a, b)
      points = roughen(vertices[lo], vertices[hi], lo * 7919 + hi * 104729)
      roughEdges.set(key, points)
    }
    return a < b ? points : [...points].reverse()
  }

  const zones: Zone[] = zoneDefs.map((zone, cell) => {
    const ids = cells[cell]
    const points: Pt[] = []
    ids.forEach((a, k) => points.push(...edgePoints(a, ids[(k + 1) % ids.length]).slice(0, -1)))
    return {
      ...zone,
      points,
      d: toPath(points, true),
      centroid: centroid(points),
      bounds: bounds(points),
      area: Math.abs(signedArea(points)),
    }
  })

  const internal: string[] = []
  edgeCells.forEach((list, key) => {
    if (list.length !== 2) return
    const [a, b] = key.split(":").map(Number)
    internal.push(toPath(edgePoints(a, b)))
  })

  const orgBoundary = (org: Exclude<ZoneOrg, null>) => {
    let d = ""
    zones.forEach((zone, cell) => {
      if (zone.org !== org) return
      const ids = cells[cell]
      const flags = ids.map((a, k) => {
        const other = edgeCells.get(edgeKey(a, ids[(k + 1) % ids.length]))?.find((c) => c !== cell)
        return other === undefined || zoneDefs[other].org !== org
      })
      const start = flags.indexOf(false)
      if (start === -1) {
        d += zone.d
        return
      }
      let run: Pt[] = []
      for (let s = 1; s <= ids.length; s++) {
        const k = (start + s) % ids.length
        if (flags[k]) {
          const segment = edgePoints(ids[k], ids[(k + 1) % ids.length])
          run.push(...(run.length ? segment.slice(1) : segment))
        } else if (run.length) {
          d += toPath(run)
          run = []
        }
      }
      if (run.length) d += toPath(run)
    })
    return d
  }

  return { zones, zoneBoundaryPath: internal.join(""), orgBoundary }
}

const built = buildZones()
export const zones = built.zones
export const zoneBoundaryPath = built.zoneBoundaryPath
export const zoneById = new Map(zones.map((zone) => [zone.id, zone]))

export interface OrgGeometry {
  zones: Zone[]
  fillPath: string
  boundaryPath: string
  bounds: Extent
  anchor: Pt
}

function orgGeometry(org: Exclude<ZoneOrg, null>, anchor: Pt): OrgGeometry {
  const own = zones.filter((zone) => zone.org === org)
  return {
    zones: own,
    fillPath: own.map((zone) => zone.d).join(""),
    boundaryPath: built.orgBoundary(org),
    bounds: bounds(own.flatMap((zone) => zone.points)),
    anchor,
  }
}

export const orgGeometries: Record<Exclude<ZoneOrg, null>, OrgGeometry> = {
  WGEC: orgGeometry("WGEC", [238, 236]),
  MetroWater: orgGeometry("MetroWater", [760, 138]),
  CCMN: orgGeometry("CCMN", [815, 600]),
}

/* ------------------------------------------------------------------------ */
/* Building footprints (revealed at facility zoom)                           */
/* ------------------------------------------------------------------------ */

/** Settlement clusters: x, y, building count, spread, street angle. */
export const VILLAGES: Array<[number, number, number, number, number]> = [
  [190, 412, 16, 17, 0.1],
  [292, 428, 12, 14, -0.15],
  [470, 402, 18, 18, -0.08],
  [560, 412, 14, 16, 0.12],
  [526, 156, 9, 12, 0.35],
  [640, 430, 14, 15, 0.3],
  [150, 292, 8, 12, 0.5],
  [858, 132, 7, 10, -0.6],
  [548, 300, 9, 12, 0.2],
  [430, 540, 7, 11, 0.25],
]

function buildFootprints(): string {
  const r = rng(99)
  const parts: string[] = []
  const main = rivers[0].points
  const majorRoads = roads.filter((item) => item.tier < 3)
  const nearRoad = (p: Pt, d: number) => majorRoads.some((item) => distToPolyline(p, item.points) < d)
  const rect = (cx: number, cy: number, w: number, h: number, angle: number) => {
    const ca = Math.cos(angle)
    const sa = Math.sin(angle)
    const corners: Pt[] = [
      [-w / 2, -h / 2],
      [w / 2, -h / 2],
      [w / 2, h / 2],
      [-w / 2, h / 2],
    ]
    parts.push(toPath(corners.map(([x, y]): Pt => [cx + x * ca - y * sa, cy + x * sa + y * ca]), true))
  }

  const angle = -0.3
  const ca = Math.cos(angle)
  const sa = Math.sin(angle)
  const [ccx, ccy] = [808, 468]
  for (let gx = -17; gx <= 17; gx++) {
    for (let gy = -13; gy <= 13; gy++) {
      const u = gx * 10.5
      const v = gy * 9
      const p: Pt = [ccx + u * ca - v * sa, ccy + u * sa + v * ca]
      if (!pointInPolygon(p, cityArea) || distToPolyline(p, main) < 9 || nearRoad(p, 4)) continue
      const core = Math.max(0, 1 - Math.hypot(p[0] - ccx, (p[1] - ccy) * 1.3) / 140)
      if (r() > 0.42 + core * 0.62) continue
      const count = 1 + Math.floor(r() * (2 + core * 3))
      for (let i = 0; i < count; i++) {
        const f = (i + 0.5) / count - 0.5
        rect(p[0] + f * 8 * ca, p[1] + f * 8 * sa, 8 / count - 0.9, 4.4 + r() * 2, angle)
      }
    }
  }

  for (const [vx, vy, count, spread, base] of VILLAGES) {
    for (let i = 0; i < count; i++) {
      const radius = Math.sqrt(r()) * spread
      const theta = r() * Math.PI * 2
      const p: Pt = [vx + Math.cos(theta) * radius, vy + Math.sin(theta) * radius * 0.8]
      if (distToPolyline(p, main) < 6) continue
      rect(p[0], p[1], 2.4 + r() * 2.6, 2 + r() * 1.8, base + (r() - 0.5) * 0.25)
    }
  }

  for (let i = 0; i < 16; i++) {
    const p: Pt = [568 + (i % 4) * 14 + r() * 3, 526 + Math.floor(i / 4) * 11 + r() * 3]
    if (r() > 0.8) continue
    rect(p[0], p[1], 8 + r() * 4, 5 + r() * 2, 0.18)
  }
  return parts.join("")
}

export const footprintPath = buildFootprints()
