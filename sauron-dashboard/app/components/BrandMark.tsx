"use client";

/**
 * SauronID brand mark — animated eye + orbital ring.
 *
 * BRANDING.md §2: "the orbital ring around the eye represents the mandate
 * boundary — what the agent is allowed to do." The ring rotates 360°/14s
 * (orbit-spin); the iris breathes 3.5s (iris-pulse). On dark only.
 */
export default function BrandMark({ size = 36 }: { size?: number }) {
  const px = `${size}px`;
  return (
    <span
      aria-hidden
      className="relative inline-block flex-shrink-0"
      style={{ width: px, height: px }}
    >
      {/* Outer mandate ring — slow rotation; breaks into segments */}
      <svg
        viewBox="0 0 40 40"
        className="absolute inset-0 animate-orbit-spin"
        style={{ filter: "drop-shadow(0 0 6px rgba(0,200,255,0.35))" }}
      >
        <defs>
          <linearGradient id="ring-g" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%"  stopColor="#4F8CFE" />
            <stop offset="100%" stopColor="#00C8FF" />
          </linearGradient>
        </defs>
        <circle
          cx="20" cy="20" r="17.5"
          fill="none"
          stroke="url(#ring-g)"
          strokeWidth="0.9"
          strokeDasharray="22 6 4 6"
          strokeLinecap="round"
          opacity="0.85"
        />
      </svg>

      {/* Inner pupil glow — pulses */}
      <svg
        viewBox="0 0 40 40"
        className="absolute inset-0 animate-iris-pulse"
      >
        <defs>
          <radialGradient id="iris-g" cx="50%" cy="50%" r="50%">
            <stop offset="0%"  stopColor="#FFFFFF" stopOpacity="0.95" />
            <stop offset="35%" stopColor="#4F8CFE" stopOpacity="0.95" />
            <stop offset="100%" stopColor="#011032" stopOpacity="0" />
          </radialGradient>
        </defs>
        {/* Eye almond shape — two arcs meeting in points */}
        <path
          d="M 6 20 Q 20 6 34 20 Q 20 34 6 20 Z"
          fill="none"
          stroke="rgba(79,140,254,0.55)"
          strokeWidth="0.8"
        />
        <circle cx="20" cy="20" r="6.5" fill="url(#iris-g)" />
        <circle cx="20" cy="20" r="2.2" fill="#06090F" />
        <circle cx="21.4" cy="18.6" r="0.7" fill="#FFFFFF" opacity="0.9" />
      </svg>
    </span>
  );
}
