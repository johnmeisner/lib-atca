@echo off
rem fix DOS/Unix EOL-Style
rem unix2dos.exe from MSYS: mingw.sourceforge.net
call :treeProcess
goto :eof

:treeProcess
rem fix all the specific files of this subdirectory:
for %%f in (*.c) do (
    unix2dos.exe "%%f"
)
for %%f in (*.h) do (
    unix2dos.exe "%%f"
)
for %%f in (*.bat) do (
    unix2dos.exe "%%f"
)
for %%f in (*.txt) do (
    unix2dos.exe "%%f"
)
rem loop over all directories and sub directories
for /D %%d in (*) do (
    cd %%d
    call :treeProcess
    cd ..
)
exit /b
