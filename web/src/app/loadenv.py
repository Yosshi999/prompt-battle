from pathlib import Path
import os

def load_env():
    envfile = Path(__file__).parent.parent / ".env"
    if envfile.exists():
        envdata = envfile.read_text()
        for line in envdata.splitlines():
            if line.strip() and not line.startswith("#"):
                key, value = line.split("=", 1)
                os.environ[key.strip()] = value.strip()