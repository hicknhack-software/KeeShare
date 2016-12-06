::@ECHO OFF

SET binPath=bin
SET currentPath=%~dp0
SET dataPath=data
SET dbFile=Database.kdbx
SET keepassExe=Keepass.exe
SET keepassPath=extern\KeePass

IF EXIST %currentPath%\%binPath% GOTO binPathExists
md %currentPath%\%binPath%
ECHO %binPath% Pfad wurde erstellt!
:binPathExists

IF EXIST %currentPath%\%binPath%\%keepassExe% GOTO keepassExists
xcopy %currentPath%\%keepassPath%\*.* %currentPath%\%binPath% /E /Y
ECHO Keepass wurde kopiert!
:keepassExists

IF EXIST %currentPath%\%binPath%\%dbFile% GOTO dbExists
xcopy %currentPath%\%dataPath%\%dbFile% %currentPath%\%binPath% /E /Y
ECHO Initiale Datenbank wurde kopiert!
:dbExists