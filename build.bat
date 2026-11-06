@echo off
rem ===== logids 一键编译（Windows） =====
chcp 65001 >nul
cd /d "%~dp0"

rem 1) 优先用 PATH 里的 gcc
where gcc >nul 2>nul
if %errorlevel%==0 goto :build

rem 2) 回退：winget 安装的 WinLibs(MinGW-w64)
set "GCC="
for /d %%i in ("%LOCALAPPDATA%\Microsoft\WinGet\Packages\BrechtSanders.WinLibs*") do (
    if exist "%%i\mingw64\bin\gcc.exe" set "GCC=%%i\mingw64\bin\gcc.exe"
)
if not defined GCC goto :nogcc

:build
setlocal enabledelayedexpansion
set "CC=gcc"
if defined GCC set "CC=!GCC!"
if "%1"=="demo" goto :demo

echo [编译] %CC% ...
"%CC%" -std=c99 -O2 -Wall -Wextra -Isrc -o logids.exe src\*.c
if errorlevel 1 goto :fail
echo [完成] 生成 logids.exe
echo.
echo 用法示例：
echo   logids.exe -c config.ini samples\auth.log samples\access.log samples\firewall.log -o report.csv
goto :eof

:demo
call "%~f0"
if not exist logids.exe goto :fail
echo [演示] 分析样例日志 ...
logids.exe -c config.ini samples\auth.log samples\access.log samples\firewall.log -o report.csv
echo.
echo 报告已生成：report.csv
start "" report.csv
goto :eof

:nogcc
echo [错误] 未找到 gcc。请安装 MinGW-w64 后重试，例如：
echo   winget install -e --id BrechtSanders.WinLibs.POSIX.UCRT
exit /b 1

:fail
echo [错误] 编译失败，请检查源码和编译器版本
exit /b 1
