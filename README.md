# ENDPOINT DETECTION AND RESPONSE 

## NOTE: use following commands to bundle .exe files

### #first make sure your local environment has absolutely everything it needs, run this command in your terminal: 
pip install -r requirements.txt

#### for frontend :
 pyinstaller --onefile --noconsole --name="EdrAgentGUI" --icon="assets/guard.ico" --add-data "assets/guard.ico;assets" .\FRONTEND\frontend_gui.py
#### for backend :
 pyinstaller --onefile --name="EdrAgentSERVICE"  .\BACKEND\backend_daemon.py


#### Compile inno_script.iss using inno compiler and run the installer(EDRAgentInstaller.exe) created in dist/

### Congrats EDR Agent IS installed in your pc!!!!!!!!
