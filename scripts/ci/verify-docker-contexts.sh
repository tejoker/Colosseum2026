#!/usr/bin/env bash
# Assert every COPY source in every Dockerfile exists relative to the build
# context the compose files actually pass, and that a Rust manifest's path
# dependencies are inside that context.
#
# This exists because core/Cargo.toml gained a path dependency on
# ../transparent-zk/types while core/Dockerfile still built with context core/.
# Every image in the repo failed at `cargo fetch --locked` for two months and no
# workflow noticed, because catching it in CI otherwise costs a full docker
# build. This check costs milliseconds and needs no daemon.
set -euo pipefail

cd "$(dirname "$0")/../.."
fail=0
note() { printf '  %s\n' "$*"; }
bad() {
    printf '  FAIL %s\n' "$*"
    fail=1
}

# context|dockerfile — the pairs the compose files and run scripts use.
# Override with arguments to check a single pair (used by this script's own
# negative test against the pre-fix Dockerfile).
PAIRS="${*:-"
.|core/Dockerfile
.|deploy/nitro/Dockerfile.enclave
dashboard|dashboard/Dockerfile
"}"

for pair in $PAIRS; do
    [ -n "$pair" ] || continue
    ctx="${pair%%|*}"
    dockerfile="${pair##*|}"
    echo "== $dockerfile (context: $ctx)"
    [ -f "$dockerfile" ] || {
        bad "$dockerfile does not exist"
        continue
    }

    # COPY sources, skipping --from=<stage> copies (those resolve inside the
    # image, not the context) and skipping flags.
    while read -r line; do
        case "$line" in *--from=*) continue ;; esac
        # Drop the COPY keyword and the destination (last field).
        set -- $line
        shift
        n=$#
        i=0
        for src in "$@"; do
            i=$((i + 1))
            [ "$i" -lt "$n" ] || break # last field is the destination
            case "$src" in --*) continue ;; esac
            if [ -e "$ctx/$src" ]; then
                note "ok   $src"
            else
                # Expand as a glob; an unmatched pattern stays literal, so the
                # -e test below still fails. (compgen -G is unusable here: it
                # echoes non-glob words back as literal completions.)
                # shellcheck disable=SC2206
                matches=($ctx/$src)
                if [ -e "${matches[0]}" ]; then
                    note "ok   $src (glob)"
                else
                    bad "COPY $src is outside the build context $ctx/"
                fi
            fi
        done
    done < <(grep -E '^[[:space:]]*COPY[[:space:]]' "$dockerfile" || true)
done

# Cargo path dependencies must also live inside the context that builds them.
echo "== cargo path dependencies reachable from context ."
while read -r dep; do
    resolved="core/$dep"
    if [ -f "$(realpath -m "$resolved")/Cargo.toml" ] &&
        case "$(realpath -m "$resolved")" in "$(pwd)"/*) true ;; *) false ;; esac then
        note "ok   core -> $dep"
    else
        bad "core path dependency $dep is not inside the repository root context"
    fi
done < <(grep -oE 'path = "[^"]+"' core/Cargo.toml | sed 's/path = "//; s/"//')

if [ "$fail" -ne 0 ]; then
    echo "docker context verification FAILED"
    exit 1
fi
echo "docker context verification passed"
