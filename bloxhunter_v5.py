#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bloxhunter_v5.py - legacy entry point (compat shim)

실제 구현은 bloxhunter_v5_final.py에 있다. 이 파일은 예전 명령과 바로가기를
깨지 않기 위해 그대로 위임만 한다. 새 기능은 전부 본체에 있다.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import bloxhunter_v5_final as core

if __name__ == "__main__":
    sys.exit(core.main())
