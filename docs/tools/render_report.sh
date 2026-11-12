#!/bin/sh
# Regenerates the report DOCX and PDF with the course file naming.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
NAME="于豪杰"
STUDENT_ID="202628015059027"
DOCX="$ROOT/docs/${NAME}_${STUDENT_ID}_ex1A_report.docx"
PYTHON=${PYTHON:-python3}
SOFFICE=${SOFFICE:-/Applications/LibreOffice.app/Contents/MacOS/soffice}
FONTCONFIG_FILE="$ROOT/docs/tools/fonts.conf"
export FONTCONFIG_FILE

"$PYTHON" "$ROOT/docs/tools/build_report.py"
if [ ! -x "$SOFFICE" ]; then
    echo "LibreOffice not found at $SOFFICE; DOCX generated, PDF skipped" >&2
    exit 0
fi
"$SOFFICE" --headless --convert-to pdf --outdir "$ROOT/docs" "$DOCX"
