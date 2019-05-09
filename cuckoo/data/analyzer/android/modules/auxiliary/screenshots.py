# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd.

import io
import time
import shutil
import logging
import tempfile
import threading

from lib.api.screenshot import Screenshot
from lib.common.abstracts import Auxiliary
from lib.common.results import upload_to_host

log = logging.getLogger(__name__)

SHOT_DELAY = 1

class Screenshots(threading.Thread, Auxiliary):
    """Take screenshots."""

    def __init__(self, options={}):
        threading.Thread.__init__(self)
        Auxiliary.__init__(self, options)
        self.do_run = True
        self.temp_dir = tempfile.mkdtemp()

    def stop(self):
        """Stop screenshotting."""
        self.do_run = False
        self.join()

        shutil.rmtree(self.temp_dir)

    def run(self):
        """Run screenshotting.
        @return: operation status.
        """
        scr = Screenshot()
        img_counter = 0
        img_last = None
        img_current = self.temp_dir+"/"+str(img_counter)+".jpg"

        while self.do_run:
            time.sleep(SHOT_DELAY)

            try:
                scr.take(img_current)
            except IOError as e:
                log.error("Cannot take screenshot: %s", e)
                continue

            if img_last and scr.equal(img_last, img_current):
                continue

            upload_to_host(
                img_current, "shots/%s.jpg" % str(img_counter)
            )

            img_counter += 1
            img_last = img_current
            img_current = self.temp_dir+"/"+str(img_counter)+".jpg"

        return True
