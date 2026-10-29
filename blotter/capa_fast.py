"""Run capa with one speed fix for vivisect (the disassembler capa uses). Only used in capa's own process.

Vivisect builds a fresh emulator for every function it analyses, and every emulator rebuilds the
register tables of every processor family vivisect knows (ARM64, ARM, MSP430, ...) through
envi.getArchModules(): about 0.1 s each time. For a DLL with ~4,000 functions that alone took ~4
minutes. The fix builds those modules once per process and hands out a fresh list each time (callers
change the list itself, so it isn't shared). The analysis and capa's results stay exactly the same;
tests/test_trusted_files.py (CapaSpeedTests) compares them on real programs.

    python -m blotter.capa_fast <capa arguments>
"""

import runpy
import sys
from importlib import metadata

# The fix was measured against this vivisect only. Any other version runs capa without it (slower, same
# results) and says so on stderr, which the capa check turns into a note on the card.
VIVISECT = "1.3.2"
WARNING = "BLOTTER-WARNING:"


def install() -> bool:
    """Apply the fix; False (with a warning) when vivisect isn't the version it was made for."""
    try:
        found = metadata.version("vivisect")
    except metadata.PackageNotFoundError:
        found = "not installed"
    if found != VIVISECT:
        print(f"{WARNING} vivisect is {found}, not {VIVISECT}; capa ran without Blotter's speed fix.",
              file=sys.stderr)
        return False
    import envi

    if getattr(envi.getArchModules, "_blotter_cached", False):
        return True
    original = envi.getArchModules
    cache = {}

    def get_arch_modules(default=envi.ARCH_DEFAULT):
        if default not in cache:
            cache[default] = original(default)
        return list(cache[default])  # a new list: MemoryObject.setMemArchitecture changes it in place

    get_arch_modules._blotter_cached = True
    envi.getArchModules = get_arch_modules
    import envi.memory
    if hasattr(envi.memory, "envi"):
        envi.memory.envi.getArchModules = get_arch_modules
    return True


def main() -> None:
    install()
    sys.argv = ["capa"] + sys.argv[1:]
    runpy.run_module("capa.main", run_name="__main__")


if __name__ == "__main__":
    main()
