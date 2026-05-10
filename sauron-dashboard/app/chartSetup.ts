"use client";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Filler,
  Tooltip,
  Legend,
  Title,
} from "chart.js";

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Filler,
  Tooltip,
  Legend,
  Title,
);

/* ── Brand-aligned chart defaults ─────────────────────────────────────
 * Sauron lives on dark — every label, grid line, tooltip must shift to
 * the cool-gray scale. Setting these once globally avoids per-chart drift.
 */
ChartJS.defaults.color = "rgba(255,255,255,0.55)";
ChartJS.defaults.font.family =
  "Satoshi, 'Inter Tight', system-ui, -apple-system, sans-serif";
ChartJS.defaults.font.size = 11;
ChartJS.defaults.borderColor = "rgba(255,255,255,0.06)";

ChartJS.defaults.plugins.legend.labels.color = "rgba(255,255,255,0.65)";
ChartJS.defaults.plugins.legend.labels.boxWidth = 8;
ChartJS.defaults.plugins.legend.labels.boxHeight = 8;

ChartJS.defaults.plugins.tooltip.backgroundColor = "rgba(3,17,35,0.95)";
ChartJS.defaults.plugins.tooltip.borderColor = "rgba(79,140,254,0.25)";
ChartJS.defaults.plugins.tooltip.borderWidth = 1;
ChartJS.defaults.plugins.tooltip.titleColor = "#F1F5F9";
ChartJS.defaults.plugins.tooltip.bodyColor = "#C8D8E1";
ChartJS.defaults.plugins.tooltip.padding = 10;
ChartJS.defaults.plugins.tooltip.cornerRadius = 4;
ChartJS.defaults.plugins.tooltip.titleFont = {
  family: "'Space Mono', monospace",
  size: 9,
  weight: "normal",
};

export const BRAND = {
  blue:    "#4F8CFE",
  blueRgb: "79,140,254",
  cyan:    "#00C8FF",
  cyanRgb: "0,200,255",
  navy:    "#2563EB",
  amber:   "#FCD34D",
  red:     "#F87171",
  emerald: "#34D399",
  violet:  "#A78BFA",
  white12: "rgba(255,255,255,0.06)",
  white25: "rgba(255,255,255,0.25)",
};

export default ChartJS;
