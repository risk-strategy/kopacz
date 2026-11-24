#!/usr/bin/env bash
# Bundle clients/javascript/kopacz.js + clients/javascript/web/app.js + index.html
# into a single self-contained web.html artifact.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JS_LIB="${DIR}/../kopacz.js"
APP_JS="${DIR}/app.js"
INDEX_HTML="${DIR}/index.html"
OUT_HTML="${DIR}/web.html"
LEGACY_HTML="${DIR}/../../../kopacz/apps/clients/web.html"

python3 - "${INDEX_HTML}" "${JS_LIB}" "${APP_JS}" "${OUT_HTML}" <<'PY'
import sys
from pathlib import Path

index = Path(sys.argv[1]).read_text(encoding="utf-8")
lib = Path(sys.argv[2]).read_text(encoding="utf-8")
app = Path(sys.argv[3]).read_text(encoding="utf-8")

bundled = index.replace(
    '<script src="../kopacz.js"></script>\n<script src="app.js"></script>',
    f"<script>\n{lib}\n{app}\n</script>",
)
script_body = f"{lib}\n{app}"
if "</script" in script_body.lower():
    raise SystemExit("ERROR: Unescaped </script> found inside inline script bundle!")
Path(sys.argv[4]).write_text(bundled, encoding="utf-8")
PY

if command -v node >/dev/null 2>&1; then
    node --check "${JS_LIB}"
    node --check "${APP_JS}"
fi

cp "${OUT_HTML}" "${LEGACY_HTML}"
echo "Built standalone bundle: ${OUT_HTML} ($(wc -c < "${OUT_HTML}") bytes)"
