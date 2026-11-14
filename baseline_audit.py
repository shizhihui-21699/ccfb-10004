#!/usr/bin/env python3
"""核查器启动脚本。

设计为在 ``python3 -I``(隔离模式,忽略 PYTHONPATH/当前目录注入)下运行:

    python3 -I baseline_audit.py audit snapshots/host-rhel8-messy
    python3 -I baseline_audit.py diff snapshots/host-ubuntu2204 snapshots/host-ubuntu2204-fixed
    python3 -I baseline_audit.py selftest
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from baseline_checker.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
