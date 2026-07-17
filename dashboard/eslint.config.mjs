// ESLint 9 flat config. eslint-config-next@16 ships flat-config arrays via its
// sub-exports, so we spread them directly (no @eslint/eslintrc FlatCompat shim).
import coreWebVitals from "eslint-config-next/core-web-vitals";
import typescript from "eslint-config-next/typescript";

const config = [
  { ignores: [".next/**", "node_modules/**", "public/**", "next-env.d.ts"] },
  ...coreWebVitals,
  ...typescript,
  {
    // Calibration, NOT suppression: these two are React-Compiler *advisories*
    // from eslint-plugin-react-hooks v6 (perf / purity hints), which Next 16
    // ships as errors. They are surfaced as warnings so they stay visible but
    // don't gate the release build — every correctness, security, and Next
    // best-practice rule still errors. Flip to "error" if you adopt the React
    // Compiler and want them enforced.
    rules: {
      "react-hooks/set-state-in-effect": "warn",
      "react-hooks/purity": "warn",
    },
  },
];

export default config;
