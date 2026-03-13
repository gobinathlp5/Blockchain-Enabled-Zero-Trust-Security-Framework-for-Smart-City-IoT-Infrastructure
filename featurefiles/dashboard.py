import os
import sys

SRC_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
if SRC_PATH not in sys.path:
    sys.path.insert(0, SRC_PATH)

from zero_trust_iot.dashboard import main


if __name__ == "__main__":
    main()