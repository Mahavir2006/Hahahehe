// Geography for the threat map. India: @svg-maps/india (CC BY 4.0, official outline incl. all of J&K and Ladakh),
// drawn in its own 612x696 Mercator space. Neighbouring countries: world-atlas (Natural Earth 110m), projected
// into the same space so they line up around India.
import india from "@svg-maps/india"
import { geoMercator, geoPath } from "d3-geo"
import { feature } from "topojson-client"
import type { Topology, GeometryCollection } from "topojson-specification"
import world from "world-atlas/countries-110m.json"

// India's extremes in the source SVG: x 0..612 = 68.18°E..97.41°E, y 0 = 37.09°N (Mercator).
const K = 612 / (((97.41 - 68.18) * Math.PI) / 180)
const base = geoMercator().scale(K).translate([0, 0])
const [x0, y0] = base([68.18, 37.09])!
export const projection = geoMercator().scale(K).translate([-x0, -y0])
export const project = (lng: number, lat: number) => projection([lng, lat]) as [number, number]

export const INDIA = { w: 612, h: 696 }
const indiaMap = india as unknown as { locations: { id: string; name: string; path: string }[] }
export const statePaths = indiaMap.locations.map((l) => ({ id: l.id, name: l.name, d: l.path }))

const topo = world as unknown as Topology<{ countries: GeometryCollection }>
const path = geoPath(projection)
export const neighbourPaths = (feature(topo, topo.objects.countries) as unknown as GeoJSON.FeatureCollection).features
  .filter((f) => String(f.id) !== "356") // everything except India, which comes from the official outline
  .map((f) => path(f))
  .filter((d): d is string => !!d)

/** City coordinates for the demo asset locations (lat, lng). */
const CITY: Record<string, [number, number]> = {
  "New Delhi": [28.61, 77.21],
  "Delhi NCR": [28.57, 77.32],
  Delhi: [28.65, 77.23],
  Dehradun: [30.32, 78.03],
  Agra: [27.18, 78.01],
  Lucknow: [26.85, 80.95],
  Tehri: [30.38, 78.48],
  Jaipur: [26.91, 75.79],
  Bhopal: [23.26, 77.41],
  Sambalpur: [21.47, 83.97],
  Kanpur: [26.45, 80.33],
  Haridwar: [29.95, 78.16],
  Varanasi: [25.32, 82.97],
  // cities used by the live backend's illustrative asset placement (data/live.ts)
  Kota: [25.18, 75.83],
  Panipat: [29.39, 76.97],
  Prayagraj: [25.43, 81.85],
  Mathura: [27.49, 77.67],
  Gwalior: [26.22, 78.18],
  Chandigarh: [30.73, 76.78],
  Indore: [22.72, 75.86],
}
export function locate(location: string): [number, number] {
  const [lat, lng] = CITY[location] ?? CITY.Delhi
  return project(lng, lat)
}

export const CITY_LABELS = (["Delhi", "Lucknow", "Jaipur", "Bhopal", "Sambalpur", "Dehradun", "Varanasi", "Kanpur", "Agra"] as const).map((c) => {
  const [lat, lng] = CITY[c]
  return { name: c, at: project(lng, lat) }
})
