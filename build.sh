#!/bin/bash
# ============================================================
#  s2tool build script (Linux/Mac)
#
#  What it does: build target/s2tool.jar (fat-jar).
#  It does NOT scan anything.
#
#  Usage: chmod +x build.sh && ./build.sh
#
#  Note: This script is provided for non-Windows environments.
#        It has NOT been tested by the author (development/test
#        was done on Windows only).
#
#  Maven repository:
#    - Default: Maven's standard local repo (~/.m2/repository).
#    - If the environment variable M2_REPO is set, it is used
#      instead.
# ============================================================

set -e

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

# Maven local repo: use M2_REPO env var if set, else Maven default
if [ -n "$M2_REPO" ]; then
    echo "[*] Maven local repository: ${M2_REPO} (from env M2_REPO)"
    export MAVEN_OPTS="-Dmaven.repo.local=${M2_REPO}"
else
    echo "[*] Maven local repository: default (~/.m2/repository)"
    export MAVEN_OPTS=""
fi

echo "[*] Building: mvn clean package -DskipTests"
mvn clean package -DskipTests

echo ""
echo "[*] BUILD OK: ${PROJECT_DIR}/target/s2tool.jar"
echo "[*] Try:"
echo "    java -jar target/s2tool.jar --help"
echo "    java -jar target/s2tool.jar scan http://YOUR-TARGET/action"
