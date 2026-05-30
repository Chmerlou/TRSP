import sys
from pathlib import Path

TASK_DIR = Path(__file__).resolve().parent.parent
if str(TASK_DIR) not in sys.path:
    sys.path.insert(0, str(TASK_DIR))
