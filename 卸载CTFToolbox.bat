@echo off
cd /d "%~dp0"
title CTFToolbox Uninstall
echo ============================================================
echo            CTFToolbox  自动卸载程序
echo  将彻底删除本文件夹内的所有内容（含本卸载程序自身）：
echo    %~dp0
echo  包含 CTFToolbox.exe、_internal、tools、workspace、reports、exports、samples
echo  请先关闭 Ghidra / x64dbg / dnSpy / MobaXterm 等已打开的工具。
echo ============================================================
set /p CONFIRM=确认彻底卸载请输入 Y 并回车（其它键取消）：
if /i not "%CONFIRM%"=="Y" (
  echo 已取消，未删除任何内容。
  pause
  exit /b 0
)
echo.
echo [1/2] 正在关闭 CTFToolbox 及播放/转码进程 ...
taskkill /F /IM CTFToolbox.exe /T >nul 2>&1
taskkill /F /IM ffplay.exe /T >nul 2>&1
taskkill /F /IM ffmpeg.exe /T >nul 2>&1
taskkill /F /IM ffprobe.exe /T >nul 2>&1
echo [2/2] 已安排静默自删除，本窗口即将关闭，无需任何操作。
set "TARGET=%~dp0"
if "%TARGET:~-1%"=="\" set "TARGET=%TARGET:~0,-1%"
set "VBS=%TEMP%\ctfuninst_%RANDOM%.vbs"
> "%VBS%" echo Set sh = CreateObject("WScript.Shell")
>> "%VBS%" echo Set fso = CreateObject("Scripting.FileSystemObject")
>> "%VBS%" echo WScript.Sleep 800
>> "%VBS%" echo For i = 1 To 30
>> "%VBS%" echo   sh.Run "cmd /c cd /d %SystemRoot% && rd /s /q ""%TARGET%""", 0, True
>> "%VBS%" echo   If Not fso.FolderExists("%TARGET%") Then Exit For
>> "%VBS%" echo   WScript.Sleep 700
>> "%VBS%" echo Next
>> "%VBS%" echo On Error Resume Next
>> "%VBS%" echo fso.DeleteFile WScript.ScriptFullName, True
rem 以 TEMP 为工作目录启动 wscript，避免其占用待删目录导致根目录无法删除
start "" /d "%TEMP%" wscript.exe "%VBS%"
exit /b 0
