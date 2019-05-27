# Copyright (C) 2014-2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd.

import os
import json
import logging

from lib.api.process import Process
from lib.core.Frida import Application
from lib.common.results import upload_to_host
from lib.common.exceptions import CuckooFridaError

log = logging.getLogger(__name__)

class Package(object):
    """Base analysis package."""

    def __init__(self, options={}):
        """@param options: options dict."""
        self.options = options
        self.pids = []
        self.frida_app = None

    def add_pid(self, pid):
        """Update list of monitored PIDs in the package context.
        @param pid: Process id.
        """
        if pid not in self.pids:
            self.pids.append(pid)
    
    def remove_pid(self, pid):
        """Update list of monitored PIDs in the package context.
        @param pid: Process id.
        """
        if pid in self.pids:
            self.pids.remove(pid)

    def start(self, target):
        """Run analysis package.
        @param path: sample path.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

    def execute(self, target):
        """Execute the sample.
        @param target: List of arguments.
        @return: True for success, False otherwise.
        """
        pid = None
        try:
            # Try spawning the process with Frida..
            self.frida_app = Application()
            pid = self.frida_app.spawn(target)
        except CuckooFridaError as e:
            log.warning(
                "Failed to spawn application process with Frida: %s" % e
            )
            if os.path.exists(target[0]):
                # Create a new process for our target..
                pid = Process.execute(target).pid

        success = pid is not None
        if success:
            self.add_pid(pid)
        return success

    def check(self):
        """Check."""
        # Check the status of monitored PIDs
        for pid in self.pids:
            if not Process(pid).is_alive():
                self.remove_pid(pid)

        return len(self.pids) != 0
    
    def instrument(self):
        """Start analysis package instrumentation."""
        if self.frida_app:
            self.frida_app.on_child_added_callback = self._instrument
            self.frida_app.on_child_removed_callback = self.remove_pid

        # First pid in the list denotes the parent.
        pid = self.pids[0]

        # Instrument the process.
        self._instrument(pid)

    def _instrument(self, pid):
        """Instrument a new process.
        @param pid: Process id.
        """
        # Add pid to the list of monitored processes.
        self.add_pid(pid)

        # Apply instrumentation with Frida.
        if self.frida_app:
            self.frida_app.load_agent(pid)

    def finish(self):
        """Finish run."""
        # Dump memory of monitored processes.
        for pid in self.pids:
            if self.frida_app:
                frida_agent = self.frida_app.get_agent(pid)
                Process(pid).dump_memory(frida_agent)

        # Terminate all attached Frida sessions.
        for pid in self.pids:
            if self.frida_app:
                self.frida_app.terminate_session(pid)

class Auxiliary(object):
    def __init__(self, options={}):
        self.options = options

    def start(self):
        raise NotImplementedError
    
    def stop(self):
        raise NotImplementedError