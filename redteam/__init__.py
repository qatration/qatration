"""QAtration: adversarial testing for AI chatbots and agents.

This directory is a flat set of modules that import each other by bare name — `from target
import Probe`, `from oracle import DETECTORS`. That is what you get when a tool grows from a
script, it is how every file in here is written, and rewriting sixty files into relative
imports to satisfy a packaging convention would be a large diff whose only purpose is to look
conventional. The risk is not theoretical: a missed import in a detector module fails at the
moment a detector runs, which is the middle of somebody's sweep.

So the directory goes on the path instead, once, here. Invoking a module by its path — which is
how these files were run for the whole life of the project before there was a command — already
put it there; importing `qatration.anything` now does the same, and both work without a single
import statement changing anywhere else.

`insert(0, ...)` rather than `append`, because a package that resolves `target` to some other
`target` on the path is a bug nobody would find quickly.
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

__all__ = ["__version__"]

# The distribution version, which is NOT the engine version. `target.engine_version()` reports
# the commit that produced an artifact and is what gets stamped into evidence; this is what pip
# resolves. Keeping them separate is deliberate: two installs of 0.1.0 can be different commits,
# and a stored result has to say which one wrote it.
__version__ = "0.2.0"
