// Resolves the bundled agent-action-tool binary for the current platform.
// Release CI populates bin/<platform>-<arch>/ from the cargo build matrix.
// ponytail: one fat package (~2 MB per target); split into per-platform
// optionalDependencies packages if install size ever matters.
"use strict";

const path = require("path");
const fs = require("fs");

const exe = process.platform === "win32" ? "agent-action-tool.exe" : "agent-action-tool";
const candidate = path.join(__dirname, "bin", `${process.platform}-${process.arch}`, exe);

if (!fs.existsSync(candidate)) {
  throw new Error(
    `@sauronid/agent-action-tool has no prebuilt binary for ${process.platform}-${process.arch}; ` +
      "build from source (cd core && cargo build --release) and set $SAURONID_AGENT_ACTION_TOOL"
  );
}

module.exports = { binaryPath: candidate };
