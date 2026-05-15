# Competitive benchmark — results summary

Generated: 2026-05-15T17:03:16.492Z

| Target | conc | n | p50 (ms) | p95 (ms) | p99 (ms) | RPS | errors | rejected | client LoC | server LoC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| dpop | 1 | 1000 | 1.00 | 2.00 | 4.00 | 677.0 | 0 | 0 | 28 | 55 |
| dpop | 10 | 1000 | 9.00 | 14.00 | 21.00 | 862.8 | 0 | 0 | 28 | 55 |
| dpop | 100 | 1000 | 77.00 | 159.00 | 189.00 | 916.6 | 0 | 0 | 28 | 55 |
| http-sig | 1 | 1000 | 1.00 | 2.00 | 2.00 | 998.0 | 0 | 0 | 22 | 60 |
| http-sig | 10 | 1000 | 7.00 | 10.00 | 12.00 | 1074.1 | 0 | 0 | 22 | 60 |
| http-sig | 100 | 1000 | 68.00 | 157.00 | 175.00 | 1019.4 | 0 | 0 | 22 | 60 |
| sauron | 1 | 1000 | 1.00 | 2.00 | 75.00 | 244.1 | 0 | 0 | 25 | 0 |
| sauron | 10 | 1000 | 7.00 | 36.00 | 57.00 | 315.2 | 0 | 0 | 25 | 0 |
| sauron | 100 | 1000 | 50.00 | 2087.00 | 2100.00 | 306.7 | 0 | 0 | 25 | 0 |

Host info from latest run:
  - CPU: AMD Ryzen 7 7735HS with Radeon Graphics x14
  - RAM: 14 GB
  - Node: 20.20.0
  - Platform: linux 6.6.114.1-microsoft-standard-WSL2
