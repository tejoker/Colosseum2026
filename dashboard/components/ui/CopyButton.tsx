"use client";

import { useEffect, useRef, useState } from "react";

interface CopyButtonProps {
  /** Text to copy — or a lazy producer when the text is built per-click. */
  text: string | (() => string);
  label: string;
  copiedLabel: string;
  className?: string;
}

/** Clipboard button with a short "copied" flash. */
export function CopyButton({ text, label, copiedLabel, className = "" }: CopyButtonProps) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
  }, []);

  function copy() {
    const value = typeof text === "function" ? text() : text;
    navigator.clipboard
      .writeText(value)
      .then(() => {
        setCopied(true);
        if (timer.current) clearTimeout(timer.current);
        timer.current = setTimeout(() => setCopied(false), 1500);
      })
      .catch(() => {});
  }

  return (
    <button
      type="button"
      onClick={copy}
      className={`px-3 py-1.5 text-xs rounded border border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-[var(--border-hover)] transition-colors duration-150 ease-out focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] ${
        copied ? "text-[var(--status-ok)]" : ""
      } ${className}`}
      aria-live="polite"
    >
      {copied ? copiedLabel : label}
    </button>
  );
}
