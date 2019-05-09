# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd.

import logging
import subprocess

from lib.common.abstracts import Package
from lib.common.exceptions import CuckooPackageError

log = logging.getLogger(__name__)

class Apk(Package):
    """Apk analysis package."""
    def __init__(self, options={}):
        Package.__init__(self, options)
        self.package, self.activity = options.get("apk_entry", ":").split(":")

    def start(self, path):
        self.install_app(path)
        self.execute_app()

    def check(self):
        return True

    def finish(self):
        return True

    def install_app(self, path):
        """Install the sample on the emulator via package manager"""
        log.info("Installing sample on the device: %s", path)
        
        p = subprocess.Popen(
            ["/system/bin/sh", "/system/bin/pm", "install", "-r", path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        out, err = p.communicate()
        if p.returncode != 0:
            raise CuckooPackageError("Error installing sample: %r" % err)
        log.info("Installed sample successfully")
    
    def execute_app(self):
        """Execute the sample on the emulator via activity manager"""
        log.info("Executing sample on the device with activity manager..")

        package_activity = "%s/%s" % (self.package, self.activity)
        p = subprocess.Popen(
            ["/system/bin/sh", "/system/bin/am", "start",
            "-n", package_activity], stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE
        )

        out, err = p.communicate()
        if p.returncode != 0:
            raise CuckooPackageError(
                "Error executing package activity: %s" % err
            )
        log.info("Executed package activity: %r", out)
