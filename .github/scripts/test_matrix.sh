#!/usr/bin/env bash
# Run all feature-flag combinations sequentially, collect every failure, and
# print a pytest-style summary at the end.  Exits 0 only when every step passes.
#
# Usage (from the typhoon/ cargo workspace directory):
#   bash ../.github/scripts/test_matrix.sh
set -uo pipefail

# Treat every compiler warning as an error, matching the default behaviour of
# actions-rust-lang/setup-rust-toolchain on GitHub runners.
export RUSTFLAGS="${RUSTFLAGS:+${RUSTFLAGS} }-D warnings"

CRYPTO_IMPLS=(fast_software fast_hardware full_software full_hardware)
PROTOCOL_PARTS=(server client "server,client")
ASYNC_LIBS=(async-std tokio)
DEBUG_IMPLS=(debug "")

# ── Pre-generate server key pairs (McEliece keygen is expensive) ──────────────
# One key per cipher-mode family (fast / full).  Tests load via
# TYPHOON_TEST_SERVER_KEY_FAST / TYPHOON_TEST_SERVER_KEY_FULL instead of
# calling ServerKeyPair::generate() on every test-binary invocation.
KEY_DIR="$(pwd)/.test_keys"
export TYPHOON_TEST_SERVER_KEY_FAST="${KEY_DIR}/server_fast.key"
export TYPHOON_TEST_SERVER_KEY_FULL="${KEY_DIR}/server_full.key"

generate_key_if_missing() {
    local key_file="$1" features="$2"
    [[ -f "${key_file}" ]] && return
    echo "::group::KeyGen [${features}] → ${key_file}"
    cargo run --quiet --bin typhoon-gen-key --no-default-features --features "${features}" -- "${key_file}"
    echo "::endgroup::"
}

generate_key_if_missing "${TYPHOON_TEST_SERVER_KEY_FAST}" "fast_software,server,tokio"
generate_key_if_missing "${TYPHOON_TEST_SERVER_KEY_FULL}" "full_software,server,tokio"

failures=()
passes=()

# run_step <phase> <label> <cmd...>
# Wraps the command in a collapsible log group, records failures, returns the
# command's exit code so callers can decide whether to skip dependent steps.
run_step() {
    local phase="$1" label="$2"; shift 2
    echo "::group::${phase} ${label}"
    if "$@"; then
        echo "::endgroup::"
        return 0
    else
        local rc=$?
        echo "::endgroup::"
        failures+=("${phase}: ${label}")
        return "${rc}"
    fi
}

for crypto in "${CRYPTO_IMPLS[@]}"; do
  for proto in "${PROTOCOL_PARTS[@]}"; do
    for async_lib in "${ASYNC_LIBS[@]}"; do
      for debug in "${DEBUG_IMPLS[@]}"; do

        features="${crypto},${proto},${async_lib}"
        [[ -n "${debug}" ]] && features="${features},${debug}"
        label="[${features}]"

        # Build — skip test/network if it fails to avoid misleading errors.
        if run_step "Build" "${label}" cargo build --no-default-features --features "${features}"; then

            run_step "Test" "${label}" cargo test --no-default-features --features "${features}" --lib || true

            passes+=("${label}")
        fi

      done
    done
  done
done

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
total=$(( ${#CRYPTO_IMPLS[@]} * ${#PROTOCOL_PARTS[@]} * ${#ASYNC_LIBS[@]} * ${#DEBUG_IMPLS[@]} ))
echo "Results: ${#passes[@]}/${total} combinations built+tested"

if [[ ${#failures[@]} -gt 0 ]]; then
    echo ""
    echo "FAILED (${#failures[@]}):"
    for f in "${failures[@]}"; do
        echo "  FAILED  ${f}"
    done
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit 1
fi

echo "All ${total} combinations passed."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
