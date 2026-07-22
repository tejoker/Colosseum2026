// ESLint 9 flat config. eslint-config-next@16 ships flat-config arrays via its
// sub-exports, so we spread them directly (no @eslint/eslintrc FlatCompat shim).
import coreWebVitals from "eslint-config-next/core-web-vitals";
import typescript from "eslint-config-next/typescript";

const config = [
  { ignores: [".next/**", "node_modules/**", "public/**", "next-env.d.ts"] },
  ...coreWebVitals,
  ...typescript,
  {
    // Keep React 19 purity rules release-blocking. A genuine force-dynamic
    // Server Component clock snapshot is suppressed at its call site with a
    // narrow explanation; client effects must remain cascade-free.
    rules: {
      "react-hooks/set-state-in-effect": "error",
      "react-hooks/purity": "error",
    },
  },
];

export default config;
