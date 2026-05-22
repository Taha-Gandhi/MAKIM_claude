import json
import os


class ConfigLoader:

    @staticmethod
    def load_allowlist():
        config_path = os.path.join("config", "allowlist.json")

        if not os.path.exists(config_path):
            return {
                "allowed_modules": [],
                "allowed_processes": [],
                "allowed_memory_processes": [],
                "allowed_ports": []
            }

        with open(config_path, "r") as f:
            return json.load(f)