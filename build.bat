rmdir /s /q venv
python -m venv venv
call ./venv/Scripts/activate.bat
python -m pip install pyinstaller==6.13.0 tqdm==4.62.3 cryptography==36.0.0
pyinstaller encript.py
pause
cls
call ./venv/Scripts/deactivate.bat
dist\encript\encript.exe
pause