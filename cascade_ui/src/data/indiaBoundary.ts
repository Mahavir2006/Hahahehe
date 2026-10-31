// India outline in the map's 1000x840 coordinate space (from the original IndiaMap component).
export const INDIA_BOUNDARY: [number, number][] = [
  // Siachen & Karakoram
  [380, 52], [405, 62], [425, 76], [445, 102], [460, 126], [445, 150], [465, 160], [475, 180],
  // Aksai Chin & Ladakh eastern border
  [485, 192], [495, 215],
  // Himachal / Uttarakhand border with Tibet/Nepal
  [515, 230], [540, 250], [575, 275],
  // Nepal northern border to Sikkim
  [615, 285], [645, 290], [675, 280], [685, 260], [700, 280],
  // Bhutan border
  [715, 280], [745, 275],
  // Arunachal Pradesh & Himalayan border
  [765, 260], [805, 240], [840, 245], [865, 265], [855, 290],
  // Nagaland / Manipur / Myanmar border
  [835, 315], [820, 360], [810, 400], [805, 435],
  // Mizoram / Tripura south
  [785, 445], [775, 415], [765, 390],
  // Meghalaya & Bangladesh border
  [745, 375], [720, 335], [690, 335],
  // Siliguri corridor & West Bengal
  [660, 325], [675, 360], [700, 395],
  // Ganges delta / Kolkata / Sundarbans
  [690, 430], [670, 445],
  // Odisha coast (Bay of Bengal)
  [645, 470], [615, 505], [580, 550],
  // Andhra Pradesh coast
  [555, 590], [525, 630],
  // Tamil Nadu coast
  [505, 665], [490, 715],
  // Southern tip (Kanyakumari)
  [455, 770], [445, 755],
  // Kerala (Malabar coast)
  [435, 700], [420, 645],
  // Karnataka & Goa coast
  [400, 595], [375, 555], [355, 515],
  // Maharashtra coast (Mumbai)
  [335, 465], [320, 425], [310, 415],
  // Gujarat (Gulf of Khambhat & Kathiawar/Saurashtra peninsula)
  [290, 405], [260, 415], [225, 410], [215, 380], [240, 360],
  // Gulf of Kutch & Rann of Kutch
  [205, 345], [190, 320], [230, 300],
  // Rajasthan (Thar Desert / Pakistan border)
  [250, 290], [270, 250], [295, 220],
  // Punjab / Jammu border with Pakistan
  [305, 200], [295, 170], [280, 130], [300, 95], [330, 75], [360, 55]
]
export const INDIA_PATH_D = INDIA_BOUNDARY.reduce(
  (acc, [x, y], i) => (i === 0 ? `M ${x} ${y}` : `${acc} L ${x} ${y}`),
  ""
) + " Z"

