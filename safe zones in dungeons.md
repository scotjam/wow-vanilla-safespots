# Dungeon Safe Zones

Safe spots where mobs stop pursuing and reset if the player waits ~5-10 seconds (out of LoS or beyond leash range). Coordinates are from the CMaNGOS `characters` DB (logout position). Each zone is defined by two opposite corners of a rectangle.

---

## Zul'Farrak (Map 209)

### Safe Zone ZF-1
| Corner | X | Y | Z |
|--------|---------|---------|-------|
| 1 | 1483.09 | 777.97 | 21.21 |
| 2 | 1526.83 | 800.85 | 21.34 |

> **Dimensions:** ~44 × 23 units

### Safe Zone ZF-2 (irregular quad)
| Point | X | Y | Z |
|-------|---------|---------|-------|
| 1 | 1564.62 | 877.80 | 11.60 |
| 2 | 1568.04 | 880.69 | 11.75 |
| 3 | 1568.42 | 877.75 | 10.37 |
| 4 | 1567.21 | 878.08 | 10.82 |

> **Shape:** Irregular quadrilateral (~4 × 3 units, slight slope on Z)

### Safe Zone ZF-3 (triangle)
| Point | X | Y | Z |
|-------|---------|---------|-------|
| 1 | 1686.82 | 850.63 | 9.23 |
| 2 | 1687.24 | 849.92 | 9.36 |
| 3 | 1687.76 | 851.17 | 9.36 |

> **Shape:** Triangle (~1 × 1.3 units — very small spot)

### Safe Zone ZF-4 (rectangle)
| Corner | X | Y | Z |
|--------|---------|---------|-------|
| 1 | 1809.56 | 879.65 | 9.75 |
| 2 | 1809.80 | 876.49 | 10.18 |

> **Dimensions:** ~0.2 × 3.2 units (very narrow strip, slight slope)

### Safe Zone ZF-5 (rectangle)
| Corner | X | Y | Z |
|--------|---------|---------|-------|
| 1 | 1809.81 | 876.47 | 10.57 |
| 2 | 1812.64 | 877.52 | 13.36 |

> **Dimensions:** ~2.8 × 1.1 units (notable Z rise of ~2.8 — on a ramp/slope)

### Safe Zone ZF-6 (rectangle)
| Corner | X | Y | Z |
|--------|---------|---------|-------|
| 1 | 1810.91 | 875.28 | 12.26 |
| 2 | 1809.67 | 873.15 | 12.77 |

> **Dimensions:** ~1.2 × 2.1 units

### Safe Zone ZF-7 (rectangle)
| Corner | X | Y | Z |
|--------|---------|---------|-------|
| 1 | 1808.34 | 864.77 | 10.24 |
| 2 | 1810.98 | 861.05 | 10.82 |

> **Dimensions:** ~2.6 × 3.7 units

### Safe Zone ZF-8 (rectangle)
| Corner | X | Y | Z |
|--------|---------|---------|-------|
| 1 | 1803.47 | 864.53 | 10.97 |
| 2 | 1801.69 | 863.38 | 10.73 |

> **Dimensions:** ~1.8 × 1.2 units

### Safe Zone ZF-9 (rectangle)
| Corner | X | Y | Z |
|--------|---------|---------|-------|
| 1 | 1800.27 | 864.70 | 12.29 |
| 2 | 1798.41 | 864.95 | 13.01 |

> **Dimensions:** ~1.9 × 0.3 units (narrow strip on a slope)

### Safe Zone ZF-10 (irregular quad / rhombus)
| Point | X | Y | Z |
|-------|---------|---------|-------|
| 1 | 1794.59 | 862.65 | 10.38 |
| 2 | 1792.47 | 862.00 | 12.73 |
| 3 | 1794.22 | 858.97 | 13.36 |
| 4 | 1795.98 | 860.16 | 13.36 |

> **Shape:** Irregular quad (~3.5 × 3.7 units, significant Z variation — sloped terrain)

### Safe Zone ZF-11 (irregular quad / rhombus)
| Point | X | Y | Z |
|-------|---------|---------|-------|
| 1 | 1842.42 | 1053.04 | 9.14 |
| 2 | 1841.49 | 1053.40 | 9.21 |
| 3 | 1844.62 | 1056.03 | 9.80 |
| 4 | 1843.47 | 1056.77 | 9.79 |

> **Shape:** Irregular quad (~3.1 × 3.7 units)

### Safe Zone ZF-12 (rectangle, multi-level) — SEMI-SAFE SPOT
| Corner | X | Y | Z |
|--------|---------|---------|-------|
| 1 | 1912.15 | 1001.53 | 14.02 |
| 2 | 1893.97 | 1004.27 | 18.96 |

> **Dimensions:** ~18.2 × 2.6 units, Z range 14.02–18.96 (spans ground level up to higher ledge)
>
> ⚠️ **Semi-safe spot.** Previously mapped as a regular safe zone; confirmed as a semi-safe spot via path series. Approach path points P → Q show the distance required to reach this zone from ZF-13.

### Safe Zone ZF-13 (rectangle) — SEMI-SAFE SPOT
| Corner | X | Y | Z |
|--------|---------|---------|-------|
| 1 | 1917.56 | 1001.56 | 20.50 |
| 2 | 1891.05 | 962.49 | 20.26 |

> **Dimensions:** ~26.5 × 39.1 units (large area, relatively flat at Z ~20.26–20.50)
>
> ⚠️ **Semi-safe / conditional safe zone.** Safe only if zombies are *not* pulled too far into this area. If pulled beyond a certain point within the zone, they stop leashing and continue pursuing — it becomes unsafe. This zone is useful for calibrating the exact distance threshold at which mobs transition from leashing/stopping to full pursuit. Pinpointing that boundary will help us tune leash evade range for the implementation.
>
> 📍 **Point O (1915.93, 999.96, 20.55) lies within this zone** — the primary semi-safe spot destination reachable via the approach path (A → O).

### Safe Zone ZF-14 (rectangle)
| Corner | X | Y | Z |
|--------|---------|---------|-------|
| 1 | 1884.60 | 958.31 | 20.70 |
| 2 | 1871.47 | 972.24 | 20.72 |

> **Dimensions:** ~13.1 × 13.9 units (roughly square, flat)

### Safe Zone ZF-15 (rectangle)
| Corner | X | Y | Z |
|--------|---------|---------|-------|
| 1 | 1868.95 | 966.44 | 20.25 |
| 2 | 1854.63 | 953.74 | 20.18 |

> **Dimensions:** ~14.3 × 12.7 units (roughly square, flat)

### Safe Zone ZF-16 (rectangle)
| Corner | X | Y | Z |
|--------|---------|---------|-------|
| 1 | 1858.10 | 951.00 | 20.29 |
| 2 | 1857.17 | 946.42 | 20.17 |

> **Dimensions:** ~0.9 × 4.6 units (narrow strip)

### Safe Zone ZF-17 (rhombus)
| Point | X | Y | Z |
|-------|---------|---------|-------|
| 1 | 1477.78 | 834.60 | 11.49 |
| 2 | 1472.42 | 833.40 | 11.16 |
| 3 | 1470.64 | 835.60 | 12.59 |
| 4 | 1472.83 | 838.36 | 10.17 |
| 5 | 1474.11 | 838.28 | 9.96 |

### Safe Zone ZF-18 (rhombus)
| Point | X | Y | Z |
|-------|---------|---------|-------|
| 1 | 1911.19 | 1029.10 | 18.91 |
| 2 | 1904.70 | 1033.00 | 13.92 |
| 3 | 1894.01 | 1032.97 | 13.84 |
| 4 | 1894.27 | 1027.25 | 13.93 |

### Pillar ZF-P1 (impassable square pillar, corners calculated from 2 points per side)
| Corner | X | Y |
|--------|---------|---------|
| 1 (S4∩S1) | 1865.18 | 1055.04 |
| 2 (S1∩S2) | 1869.79 | 1063.00 |
| 3 (S2∩S3) | 1863.79 | 1066.46 |
| 4 (S3∩S4) | 1859.21 | 1058.56 |

> **Z range:** ~9.94–20.92 (pillar extends full height).
> **Pathfinding note:** The X,Y footprint of this pillar is impassable. Mobs cannot path through it — if the player is on the far side, mobs must navigate around it. This increased path length is what makes nearby safe spots work: the detour pushes the mob's required travel distance beyond its leash threshold, causing it to evade rather than follow.

### Pillar ZF-P2 (impassable pillar, corners calculated from 2 points per side)
| Corner | X | Y |
|--------|---------|---------|
| 1 (S1∩S2) | 1888.67 | 964.22 |
| 2 (S2∩S4) | 1883.57 | 956.82 |
| 3 (S4∩S3) | 1893.62 | 949.93 |
| 4 (S3∩S1) | 1898.79 | 957.36 |

> **Z range:** ~13.41–20.70 (pillar extends full height).
> **Survey points used:**
> - Side 1: (1896.01, 959.24) → (1891.39, 962.37)
> - Side 2: (1887.85, 963.03) → (1884.55, 958.24)
> - Side 3: (1897.18, 955.05) → (1894.28, 950.88)
> - Side 4: (1892.30, 950.83) → (1886.27, 954.97)

---

### Approach Path to ZF-13 (straight-line waypoints)

Series of points tracing the approach path to the conditional safe zone (ZF-13). Used to determine the exact distance threshold at which mobs transition from leashing/evading to full pursuit.

| Point | X | Y | Z |
|-------|---------|---------|-------|
| A | 1873.78 | 1088.75 | 9.52 |
| B | 1893.11 | 1075.90 | 20.85 |
| C | 1911.68 | 1036.68 | 18.69 |
| D | 1909.84 | 1037.43 | 20.46 |
| E | 1922.90 | 1029.44 | 20.61 |
| F | 1924.35 | 1028.81 | 23.78 |
| G | 1915.50 | 1028.08 | 23.82 |
| I | 1915.92 | 1024.67 | 23.88 |
| J | 1919.83 | 1023.22 | 23.76 |
| K | 1919.94 | 1007.16 | 24.13 |
| L | 1916.24 | 1006.61 | 24.17 |
| M | 1916.37 | 1002.97 | 24.17 |
| N | 1919.68 | 1002.09 | 24.10 |
| O | 1915.93 |  999.96 | 20.55 |
| P | 1912.34 | 1001.52 | 20.38 |  ← path continues toward ZF-12 (optional)
| Q | 1909.93 | 1000.90 | 14.21 |  ← on the border of ZF-13/ZF-12; marks the distance needed to reach ZF-12 (optional)

> Points A→O trace the approach to **ZF-13** (primary semi-safe spot, upper level Z ~20.5). Points P→Q continue down the staircase to **ZF-12** (secondary semi-safe spot, lower level Z ~14.2). O is the last point needed to reach ZF-13; P and Q are optional and lead to ZF-12.

---

## Maraudon (Map 349)

*To be mapped.*

---

## Dire Maul East (Map 429)

*To be mapped.*
