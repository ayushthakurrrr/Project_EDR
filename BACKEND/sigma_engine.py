import os
import sys
import yaml


# =====================================================================
# SIGMA ENGINE CONFIGURATION
# =====================================================================

# # ---> FIX: Universal path resolution for PyInstaller & Standalone <---
# ---> THE ULTIMATE PYINSTALLER PATH RESOLVER <---
if getattr(sys, 'frozen', False):
    # 1. Check if PyInstaller bundled the rules inside the .exe (extracts to _MEIPASS)
    if hasattr(sys, '_MEIPASS'):
        BASE_DIR = sys._MEIPASS
    else:
        # 2. Check if Inno Setup copied the rules directly next to the .exe
        BASE_DIR = os.path.dirname(sys.executable)
else:
    # 3. Running normally as a Python script in VS Code
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SIGMA_RULES_DIR = os.path.join(BASE_DIR, "rules", "sigma")


# OPTIMIZATION: Group rules by category in RAM for instant O(1) routing
COMPILED_SIGMA_RULES = {
    "process_creation": [],
    "network_connection": [],
    "file_event": [],
    "registry_event": []
}

def load_sigma_rules():
    """Reads all .yml Sigma files and categorizes them into RAM on startup."""
    global COMPILED_SIGMA_RULES
    
    try:
        loaded_count = 0
        for filename in os.listdir(SIGMA_RULES_DIR):
            if filename.endswith(".yml") or filename.endswith(".yaml"):
                file_path = os.path.join(SIGMA_RULES_DIR, filename)
                with open(file_path, 'r', encoding='utf-8') as f:
                    try:
                        rule = yaml.safe_load(f)
                        if rule and "detection" in rule and "logsource" in rule:
                            category = rule["logsource"].get("category", "").lower()
                            
                            # Map Sigma categories to our EDR's internal event types
                            if category == "process_creation":
                                COMPILED_SIGMA_RULES["process_creation"].append(rule)
                            elif category == "network_connection":
                                COMPILED_SIGMA_RULES["network_connection"].append(rule)
                            loaded_count += 1
                            
                    except Exception as parse_error:
                        print(f"[SIGMA ERROR] Could not parse {filename}: {parse_error}")

        print(f"[*] Successfully loaded {loaded_count} Sigma behavioral rules into RAM categorised arrays.")
    except Exception as e:
        print(f"[SIGMA ERROR] Failed to access rules directory: {e}")

load_sigma_rules()

def evaluate_against_sigma(payload):
    """
    Ultra-fast evaluator. Uses Category Pre-Filtering to only scan relevant rules.
    """
    event_type = payload.get("type", "").lower()
    
    # 1. CATEGORY PRE-FILTERING: Only fetch rules that match this exact event type
    rules_to_check = COMPILED_SIGMA_RULES.get(event_type, [])
    
    if not rules_to_check:
        return None # Instantly skip if we have no rules for this category!

    # Safely extract and clean strings to prevent hidden space bugs
    proc_name = payload.get("process_name", "").strip().lower()
    cmd_line = payload.get("command_line", "").strip().lower()
    path = payload.get("path", "").strip().lower()

    for rule in rules_to_check:
        try:
            selections = rule.get("detection", {}).get("selection", {})
            match_found = True 

            for key, condition in selections.items():
                key = key.lower()
                
                if isinstance(condition, list):
                    cond_list = [str(c).strip().strip("'").strip('"').lower() for c in condition]
                else:
                    cond_list = [str(condition).strip().strip("'").strip('"').lower()]
                
                field_matched = False
                
                if "image" in key:
                    target_value = path if path and path != "unknown" else proc_name
                    for c_str in cond_list:
                        # ---> FIX: Strip slashes to avoid Windows backslash escape issues <---
                        clean_cond = c_str.strip("\\") 
                        if "endswith" in key and target_value.endswith(clean_cond):
                            field_matched = True
                            break
                        elif target_value == c_str or target_value == clean_cond:
                            field_matched = True
                            break
                
                elif "commandline" in key:
                    for c_str in cond_list:
                        if "contains" in key and c_str in cmd_line:
                            field_matched = True
                            break

                if not field_matched:
                    match_found = False
                    break 

            if match_found:
                print(f"[SIGMA ALERT] Triggered Rule: {rule.get('title')}")
                return {
                    "title": rule.get("title", "Unknown Sigma Rule"),
                    "level": rule.get("level", "medium").upper()
                }

        except Exception as e:
            print(f"[SIGMA ERROR] Failed evaluating rule: {e}")
            continue

    return None