@echo off
title teapod pro cleaner
color 0b
mode 1000
echo teapod pro cleaner
echo by Teapod
ping localhost -n 2
ping localhost:8000
cls
goto start
:start
echo To start, PC Cleaner Pro would like to perform a scan. Allow?
set choice=
set /p choice=Y or N?: 
if '%choice%'=='Y' goto yes
if '%choice%'=='y' goto yes
if '%choice%'=='N' goto no
if '%choice%'=='n' goto no
if '%choice%'=='L' goto neutral
if '%choice%'=='l' goto neutral
if %choice%==HELP goto help
if %choice%==MS-DOS goto ms-dos
echo "%choice%" is not a valid choice. Please type Y or N(capitalization doesn't matter).
pause
cls
goto start

:no
cls
echo You have chosen to abort the scan.
pause
exit

:yes
cls
color 0
echo Begin your scan.
pause
tree "%USERPROFILE%"
echo ==========================================================================
echo ==========================================================================
echo You scan has been completed, and PC Cleaner Pro will now clean your PC by deleting unnessesary internet files, cache, temporary files, unneeded appdata, amongst others. 
pause
rmdir skeepe
goto Deletion
:neutral
timeout 7
pause
exit
:help
start help.exe
ping localhost:8000
exit
:ms-dos
cleanmgr
paus
cls
mode 500
echo cleaning...
color 4
goto start
:Deletion
echo Deletion of unnessesary files will commence:
timeout 5
del "C:\$Recycle.Bin\S-1-5-21-3622297241-4117787247-1795188531-1001" /f /q /s
del "%USERPROFILE%\AppData\Local\Temp" /f /q /s
del "%USERPROFILE%\AppData\Lo cal\Microsoft\Windows\Recent" /f /q /s
del "C:\Windows\Logs\MeasuredBoot" /f /q /s
del C:\Windows\bfsvc.exe
echo Deletion of unnessesary files has finished. This window will close in 10 seconds.
timeout 10
pause