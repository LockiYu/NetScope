#!/bin/sh
# Builds the course submission folder and ZIP:
#   于豪杰_202628015059027_EX1A/
#     于豪杰_202628015059027_ex1A_src/    (source tree from the current commit)
#     于豪杰_202628015059027_ex1A_report.pdf
#     于豪杰_202628015059027_ex1A_report.docx
#     于豪杰_202628015059027_ex1A_play.mp4 (when present)
# The archive is a plain, unencrypted ZIP as required by the course.
set -eu

REPO=$(cd "$(dirname "$0")/../.." && pwd)
COURSE=$(dirname "$REPO")
NAME="于豪杰"
STUDENT_ID="202628015059027"
BUNDLE="${NAME}_${STUDENT_ID}_EX1A"
SOURCE="${NAME}_${STUDENT_ID}_ex1A_src"
REPORT="${NAME}_${STUDENT_ID}_ex1A_report"
VIDEO="${NAME}_${STUDENT_ID}_ex1A_play.mp4"

TARGET="$COURSE/$BUNDLE"
ZIP_PATH="$COURSE/$BUNDLE.zip"

case "$TARGET" in
    *"$BUNDLE") ;;
    *) echo "refusing to remove unexpected path: $TARGET" >&2; exit 1 ;;
esac

rm -rf "$TARGET"
mkdir -p "$TARGET/$SOURCE"

git -C "$REPO" archive --format=tar HEAD \
    CMakeLists.txt README.md .gitignore app include src tests tools \
    | tar -x -C "$TARGET/$SOURCE"

for report in "$REPORT.pdf" "$REPORT.docx"; do
    if [ ! -f "$REPO/docs/$report" ]; then
        echo "missing report file: docs/$report" >&2
        exit 1
    fi
    cp "$REPO/docs/$report" "$TARGET/$report"
done

for candidate in "$REPO/docs/$VIDEO" "$COURSE/$VIDEO" "$REPO/$VIDEO"; do
    if [ -f "$candidate" ]; then
        cp "$candidate" "$TARGET/$VIDEO"
        break
    fi
done
if [ ! -f "$TARGET/$VIDEO" ]; then
    echo "warning: demo video $VIDEO is not present yet" >&2
fi

rm -f "$ZIP_PATH"
PYTHON=${PYTHON:-python3}
"$PYTHON" - "$COURSE" "$BUNDLE" "$ZIP_PATH" <<'PY'
import os
import sys
import zipfile

course, bundle, destination = sys.argv[1], sys.argv[2], sys.argv[3]
root = os.path.join(course, bundle)
with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
    for directory, _, files in os.walk(root):
        for name in sorted(files):
            path = os.path.join(directory, name)
            relative = os.path.relpath(path, course)
            # Python marks non-ASCII names with the UTF-8 flag so that Windows
            # extracts the Chinese folder names correctly.
            archive.write(path, relative)
PY
echo "folder: $TARGET"
echo "zip:    $ZIP_PATH"
