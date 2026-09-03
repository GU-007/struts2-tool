@echo off
REM ============================================================
REM  s2tool build script (Windows)
REM
REM  What it does: build target\s2tool.jar (fat-jar).
REM  It does NOT scan anything.
REM
REM  Usage:
REM    1) Double-click this file:
REM       - builds the jar
REM       - then opens a cmd prompt in the project folder,
REM         so you can type tool commands right away
REM       - type  exit  to close the window
REM    2) In PowerShell:  .\build.bat
REM       - builds the jar, then enters a cmd prompt
REM       - type  exit  to return to PowerShell
REM
REM  Maven repository:
REM    - Default: Maven's standard local repo (~/.m2/repository).
REM    - If the environment variable M2_REPO is set, it is used
REM      instead (e.g. for environments without write permission
REM      to the user home).
REM ============================================================

setlocal

REM ---- Locate project root (script directory) ----
set "PROJECT_DIR=%~dp0"
cd /d "%PROJECT_DIR%"

REM ---- Check dependencies ----
where java >nul 2>nul
if errorlevel 1 goto :no_java

where mvn >nul 2>nul
if errorlevel 1 goto :no_mvn

REM ---- Maven local repo: use M2_REPO env var if set, else Maven default ----
if not "%M2_REPO%"=="" (
    echo [*] Maven local repository: %M2_REPO% ^(from env M2_REPO^)
    set "MAVEN_OPTS=-Dmaven.repo.local=%M2_REPO%"
) else (
    echo [*] Maven local repository: default ^(%%USERPROFILE%%\.m2\repository^)
    set "MAVEN_OPTS="
)

echo [*] Building: mvn clean package -DskipTests
call mvn clean package -DskipTests
if errorlevel 1 goto :build_failed

echo.
echo [*] BUILD OK: %PROJECT_DIR%target\s2tool.jar
echo.
echo ============================================================
echo  Window stays open. Type tool commands below, for example:
echo.
echo     java -jar target\s2tool.jar --help
echo     java -jar target\s2tool.jar scan http://YOUR-TARGET/action
echo.
echo  If Chinese text is garbled, run this first:
echo     set JAVA_TOOL_OPTIONS=-Dfile.encoding=UTF-8 -Dstdout.encoding=UTF-8
echo.
echo  Type  exit  to close this window.
echo ============================================================
echo.
REM Open an interactive cmd session in the project dir so the
REM window survives after this script ends (double-click case).
cmd /k
exit /b 0

:no_java
echo [!] java not found. Please install JDK 8+ and add it to PATH.
echo     Verify with: java -version
goto :end_fail

:no_mvn
echo [!] mvn not found. Please install Maven 3.x and add it to PATH.
echo     Verify with: mvn -version
goto :end_fail

:build_failed
echo.
echo [!] BUILD FAILED. Check Maven environment or network.
echo     Common causes:
echo       1. Cannot reach Maven Central - check network or proxy.
echo       2. Maven local repository is not writable.
echo          Set M2_REPO to a writable directory, e.g.:
echo          set M2_REPO=D:\some\writable\folder
goto :end_fail

:end_fail
echo.
pause
exit /b 1
