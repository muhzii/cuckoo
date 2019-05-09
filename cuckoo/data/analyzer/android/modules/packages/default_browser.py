# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd.

import logging
import subprocess

from lib.common.abstracts import Package
from lib.common.exceptions import CuckooPackageError

log = logging.getLogger(__name__)

class default_browser(Package):
    """Default Browser analysis package."""

    def start(self, target):
        """Start URL intent on the emulator."""
        p = subprocess.Popen(
                ["/system/bin/sh", "/system/bin/am", "start",
                "-a", "android.intent.action.VIEW", "-d", target],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        out, err = p.communicate()
        if p.returncode != 0:
            raise CuckooPackageError("Error starting browser intent: %r" % err)
        log.info("Intent returned: %r", out)

    def check(self):
        return True

    def finish(self):
        return True
