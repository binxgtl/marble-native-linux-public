#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Load preserved implementations without patching their globals or contracts."""
import importlib.util
import sys
from pathlib import Path

M15=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(M15/'phaseb'))
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

o3=load('m15_integrated_o3_replay',M15/'o3/replay.py')
legacy_topology=load('m15_integrated_legacy_topology',M15/'phaseb/topology.py')
legacy_compare=load('m15_integrated_legacy_compare',M15/'phaseb/compare.py')
restrictions=legacy_topology.restrictions
