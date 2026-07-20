@echo off
setlocal
cd /d "%~dp0"
if not exist build mkdir build
if not exist tests\fixtures mkdir tests\fixtures

where cl >nul 2>nul
if errorlevel 1 (
  for %%P in (
    "%ProgramFiles%\Microsoft Visual Studio\2022\Community"
    "%ProgramFiles%\Microsoft Visual Studio\2022\BuildTools"
    "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise"
  ) do (
    if exist "%%~P\VC\Auxiliary\Build\vcvars64.bat" (
      call "%%~P\VC\Auxiliary\Build\vcvars64.bat" >nul
      goto :got
    )
  )
  echo [!] no cl; run from a VS x64 prompt
  exit /b 1
)
:got

cl /nologo /std:c++17 /EHsc /O2 /W3 /MT /DUNICODE /D_UNICODE ^
   /D_WIN32_WINNT=0x0A00 /Isrc /Fe:build\bootvars.exe src\bootvars.cpp advapi32.lib
if errorlevel 1 goto :fail

echo [*] selftest
build\bootvars.exe --selftest
if errorlevel 1 goto :fail

echo [*] fixture
build\bootvars.exe --emit tests\fixtures\boot0001.bin >nul
if errorlevel 1 goto :fail

echo [*] offline parse
build\bootvars.exe --offline tests\fixtures\boot0001.bin
if errorlevel 1 goto :fail

echo.
echo [+] build\bootvars.exe
exit /b 0

:fail
echo [!] failed
exit /b 1
