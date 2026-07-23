@echo off
timeout /t 8 /nobreak >NUL
C:\Panda\guest_launcher.exe C:\Panda\sample.exe 30 /work/empirical_results/panda_runtime/pilot/upx395 C:\Panda\status.txt
shutdown /s /t 5
