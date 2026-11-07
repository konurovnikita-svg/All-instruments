#!/usr/bin/env bash
# Локальный запуск единого security-пайплайна (зеркало GitHub Actions workflow).
#
#   scripts/run_local.sh <путь-или-git-url> [каталог-результатов]
#
# Инструменты ищутся в PATH; каталог с бинарными файлами можно подсказать:
#   TOOLS_BIN=/path/to/bin scripts/run_local.sh ./my-project
# Порог quality gate: GATE=high|critical|medium|none (по умолчанию none).
set -uo pipefail

TARGET_IN="${1:?Укажите путь к проекту или git URL}"
OUT="${2:-security-results}"
GATE="${GATE:-none}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ -n "${TOOLS_BIN:-}" ] && export PATH="$TOOLS_BIN:$PATH"

# --- цель: локальный путь или клон ---------------------------------------
if [[ "$TARGET_IN" =~ ^https?:// || "$TARGET_IN" =~ ^git@ ]]; then
  TARGET="$OUT/target-src"
  mkdir -p "$OUT"
  [ -d "$TARGET/.git" ] || git clone --quiet "$TARGET_IN" "$TARGET"
else
  TARGET="$(cd "$TARGET_IN" && pwd)"
fi
PROJECT="$(basename "$TARGET")"
REF="$(git -C "$TARGET" rev-parse --short HEAD 2>/dev/null || echo 'working tree')"

OUT="$(mkdir -p "$OUT" && cd "$OUT" && pwd)"
RAW="$OUT/raw"
mkdir -p "$RAW"/{semgrep,codeql,gitleaks,trufflehog,osv,grype,sbom/cdxgen,sbom/syft}
echo "== Проект: $PROJECT ($REF) =="

# --- 1. Детектор: языки, структура, выбор инструментов --------------------
python3 "$ROOT/scripts/detect.py" --target "$TARGET" --out "$OUT/plan.json" > /dev/null
plan() { python3 -c "import json,sys; d=json.load(open('$OUT/plan.json')); print(eval(sys.argv[1]))" "$1"; }
RUN_SEMGREP=$(plan "d['tools']['semgrep']['run']")
RUN_CODEQL=$(plan "d['tools']['codeql']['run']")
RUN_CDXGEN=$(plan "d['tools']['cdxgen']['run']")
RUN_OSV=$(plan "d['tools']['osv-scanner']['run']")
GIT_COMMITS=$(plan "d['facts']['git']['commits']")
jq -r '.tools | to_entries[] | "  \(.key): \(if .value.run then "запуск" else "пропуск" end) — \(.value.reason)"' "$OUT/plan.json" 2>/dev/null || true

# --- 2. Secret scanning -----------------------------------------------------
if command -v gitleaks >/dev/null; then
  if [ "$GIT_COMMITS" -gt 0 ] 2>/dev/null; then
    gitleaks git --redact --no-banner --report-format json \
      --report-path "$RAW/gitleaks/results.json" "$TARGET" >/dev/null 2>&1 || true
  else
    gitleaks dir --redact --no-banner --report-format json \
      --report-path "$RAW/gitleaks/results.json" "$TARGET" >/dev/null 2>&1 || true
  fi
  [ -s "$RAW/gitleaks/results.json" ] || echo '[]' > "$RAW/gitleaks/results.json"
fi
if command -v trufflehog >/dev/null; then
  if [ "$GIT_COMMITS" -gt 0 ] 2>/dev/null; then
    trufflehog git "file://$TARGET" --json --no-update --no-verification \
      > "$RAW/trufflehog/raw.jsonl" 2>/dev/null || true
  else
    trufflehog filesystem "$TARGET" --json --no-update --no-verification \
      > "$RAW/trufflehog/raw.jsonl" 2>/dev/null || true
  fi
fi

  if [ -s "$RAW/trufflehog/raw.jsonl" ]; then
    jq -R -c 'fromjson? | {DetectorName, SourceMetadata, Verified}' \
      "$RAW/trufflehog/raw.jsonl" > "$RAW/trufflehog/results.json" || true
    rm -f "$RAW/trufflehog/raw.jsonl"
  fi
  [ -f "$RAW/trufflehog/results.json" ] || : > "$RAW/trufflehog/results.json"

# --- 3. SAST ----------------------------------------------------------------
if [ "$RUN_SEMGREP" = "True" ] && command -v semgrep >/dev/null; then
  CONFIGS=()
  while IFS= read -r c; do CONFIGS+=(--config "$c"); done \
    < <(python3 -c "import json; [print(c) for c in json.load(open('$OUT/plan.json'))['tools']['semgrep']['configs']]")
  semgrep scan "${CONFIGS[@]}" --json --output "$RAW/semgrep/semgrep.json" \
    --exclude node_modules --exclude .git --exclude dist --exclude build \
    "$TARGET" >/dev/null 2>&1 || true
fi
if [ "$RUN_CODEQL" = "True" ] && command -v codeql >/dev/null; then
  while IFS= read -r lang; do
    pack="${lang%%-*}"
    db="$OUT/codeql-db-$lang"
    codeql database create "$db" --language="$lang" --source-root="$TARGET" \
      --build-mode=none --overwrite >/dev/null 2>&1 \
      || codeql database create "$db" --language="$lang" --source-root="$TARGET" \
           --overwrite >/dev/null 2>&1 || continue
    codeql database analyze "$db" --format=sarif-latest --threads="${CODEQL_THREADS:-2}" \
      --output="$RAW/codeql/$lang.sarif" --download \
      "codeql/$pack-queries:codeql-suites/$pack-security-and-quality.qls" \
      >/dev/null 2>&1 || true
    rm -rf "$db"
  done < <(python3 -c "import json; [print(l) for l in json.load(open('$OUT/plan.json'))['tools']['codeql']['languages']]")
fi

# --- 4. SBOM ------------------------------------------------------------------
if [ "$RUN_CDXGEN" = "True" ] && command -v cdxgen >/dev/null; then
  cdxgen --recurse --output "$RAW/sbom/cdxgen/sbom.cdx.json" "$TARGET" >/dev/null 2>&1 || true
fi
if command -v syft >/dev/null; then
  syft packages "dir:$TARGET" -o "cyclonedx-json=$RAW/sbom/syft/sbom.cdx.json" >/dev/null 2>&1 || true
fi

# --- 5. SCA -------------------------------------------------------------------
if [ "$RUN_OSV" = "True" ] && command -v osv-scanner >/dev/null; then
  (cd "$TARGET" && osv-scanner scan source -r . --no-ignore --format json \
     --output-file "$RAW/osv/osv.json" >/dev/null 2>&1) || true
fi
if command -v grype >/dev/null; then
  if [ -s "$RAW/sbom/syft/sbom.cdx.json" ]; then
    grype "sbom:$RAW/sbom/syft/sbom.cdx.json" -o json --file "$RAW/grype/grype.json" >/dev/null 2>&1 || true
  else
    grype "dir:$TARGET" -o json --file "$RAW/grype/grype.json" >/dev/null 2>&1 || true
  fi
fi

# --- 6. Единый отчёт ------------------------------------------------------------
python3 "$ROOT/scripts/normalize_report.py" --raw "$RAW" --plan "$OUT/plan.json" \
  --out "$OUT" --project "$PROJECT" --ref "$REF" --fail-on "$GATE" --target "$TARGET"
STATUS=$?
echo
echo "Отчёт:  $OUT/report.html"
echo "        $OUT/report.md"
echo "Реестр: $OUT/findings.json"
exit $STATUS
