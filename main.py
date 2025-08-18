#!/usr/bin/env python3
import importlib

def _run():
	mod = importlib.import_module("try")
	getattr(mod, "main")()

if __name__ == "__main__":
	_run()