#!/usr/bin/env bash
# build_pyz.sh — Bundle Kopacz v3 client into a single executable zipapp (clients/python/kopacz.pyz)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUT_FILE="${1:-${SCRIPT_DIR}/kopacz.pyz}"
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "${BUILD_DIR}"' EXIT

cp -r "${REPO_ROOT}/kopacz" "${BUILD_DIR}/kopacz"
find "${BUILD_DIR}" -name "__pycache__" -exec rm -rf {} +

python3 -m zipapp "${BUILD_DIR}" \
    --output "${OUT_FILE}" \
    --python "/usr/bin/env python3" \
    --main "kopacz.cli:main" \
    --compress

chmod +x "${OUT_FILE}"
echo "Built single-file client archive: ${OUT_FILE}"
