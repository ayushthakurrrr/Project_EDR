#NOTE use following commands to bundle .exe files
# for frontend : pyinstaller --onefile --noconsole --name="EdrAgentGUI" --icon="assets/guard.ico" --add-data "assets/guard.ico;assets" .\FRONTEND\frontend_gui.py
# for backend : pyinstaller --onefile --name="EdrAgentSERVICE"  .\BACKEND\backend_daemon.py


# Compile inno_script.iss using inno compiler and run the installer(EDRAgentInstaller.exe) created in dist/

# Congrats EDR Agent will be installed in your pc!!!!!!!!
