"""Only what `pyproject.toml` cannot say: the wheel ships the engine, not its suites.

THE SUITES STAY IN THE REPOSITORY. They need `tools/`, `site/` and `out/`, none of which an
install has, and they were 3.5 MB of a 6.7 MB wheel -- and `qatration/__init__.py` puts the
package directory first on `sys.path`, so fifty-odd `test_*` modules became top-level names in
every process that imported qatration. `exclude-package-data` filters data files, not modules,
so the filter is here. Found by an independent review.
"""
from setuptools import setup
from setuptools.command.build_py import build_py


class _EngineOnly(build_py):
    def find_package_modules(self, package, package_dir):
        return [m for m in super().find_package_modules(package, package_dir)
                if not m[1].startswith("test_")]


setup(cmdclass={"build_py": _EngineOnly})
