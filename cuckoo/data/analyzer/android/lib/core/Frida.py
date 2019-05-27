# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import json
import logging

from lib.common.constants import FRIDA_LOGS_PATH
from lib.common.exceptions import CuckooFridaError
from lib.common.utils import create_file_logger, load_configs

try:
    import frida
    HAVE_FRIDA = True
except ImportError:
    HAVE_FRIDA = False

FRIDA_CONFIGS_PATH = "config/frida"
AGENT_SCRIPT_PATH = "lib/core/agent.js"

log = logging.getLogger(__name__)

class Application(object):
    """Interface of Frida-based applications. Used for sample instrumentation.
    https://github.com/frida/frida
    """

    def __init__(self):
        if not HAVE_FRIDA:
            raise CuckooFridaError(
                "Failed to import Frida's Python bindings.. Check "
                "your guest installation."
            )

        self.sessions = {}
        self.scripts = {}
        self.device = frida.get_local_device()

        self.device.on(
            "child-added",
            lambda child: self._on_child_added(child.pid)
        )
        self.device.on(
            "child-removed",
            lambda child: self._on_child_removed(child.pid)
        )

        self._on_child_added_callback = None
        self._on_child_removed_callback = None

    @property
    def on_child_added_callback(self):
        return self._on_child_added_callback

    @on_child_added_callback.setter
    def on_child_added_callback(self, callback):
        self._on_child_added_callback = callback

    @property
    def on_child_removed_callback(self):
        return self._on_child_removed_callback

    @on_child_removed_callback.setter
    def on_child_removed_callback(self, callback):
        self._on_child_removed_callback = callback

    def spawn(self, pkg):
        """Start a target Android application.
        This is essentially a wrapper for frida.spawn's call.
        @param pkg: target application entry point.
        """
        try:
            pid = self.device.spawn(pkg)
            log.info("Target application package (%s) spawned.", pkg)
        except frida.NotSupportedError:
            raise CuckooFridaError(
                "No application with package name %s installed." % pkg
            )
        except frida.TimedOutError:
            raise CuckooFridaError("Timeout while spawning application.")
        except frida.TransportError:
            raise CuckooFridaError(
                "Connection with the Frida agent is closed, spawning failed."
            )
        return pid

    def load_agent(self, pid):
        """Load our instrumentation agent into the process and start it.
        @param pid: Target process.
        """
        if not os.path.exists(AGENT_SCRIPT_PATH):
            raise CuckooFridaError(
                "Agent script not found at '%s', unable to inject into "
                "process.." % AGENT_SCRIPT_PATH
            )

        self._start_session(pid)
        self._load_script(pid, AGENT_SCRIPT_PATH)
        script = self.scripts[pid]

        arg = load_configs(FRIDA_CONFIGS_PATH)
        script.exports.start(arg)
        self._resume(pid)

    def terminate_session(self, pid):
        """Terminate the currently attached Frida session"""
        if pid in self.scripts:
            try:
                self.scripts[pid].unload()
            except frida.InvalidOperationError:
                pass
            del self.scripts[pid]
        
        if pid in self.sessions:
            self.sessions[pid].detach()
            del self.sessions[pid]

        log.info("Frida session is terminated")

    def get_agent(self, pid):
        """Get the agent injected in a process.
        @param pid: Process id.
        @return: agent instance.
        """
        if pid not in self.scripts:
            return None

        return Agent(pid, self.scripts[pid])

    def _on_child_added(self, pid):
        """A callback function invoked when a new child is added.
        @param pid: PID of child process.
        """
        if self._on_child_added_callback:
            self._on_child_added_callback(pid)

    def _on_child_removed(self, pid):
        """A callback function invoked when a child is removed.
        @param pid: PID of child process.
        """
        if pid in self.sessions:
            del self.sessions[pid]
        
        if pid in self.scripts:
            del self.sessions[pid]
        
        if self._on_child_removed_callback:
            self._on_child_removed_callback(pid)

    def _resume(self, pid):
        """Resume the spawned application process.
        @param pid: Process id.
        """
        try:
            self.device.resume(pid)
        except (frida.InvalidArgumentError, frida.ProcessNotFoundError):
            log.warning(
                "Attempted to resume a non-resumable process %d." % pid
            )
        log.debug("Process with id: %d is resumed" % pid)

    def _start_session(self, pid):
        """Initiate a frida session with the application
        @param pid: Process id.
        """
        try:
            session = self.device.attach(pid)
        except frida.ProcessNotFoundError:
            raise CuckooFridaError("Failed to initiate a frida session "
                                   "with the application process")
        log.info("Frida session established!")

        session.enable_child_gating()
        self.sessions[pid] = session

    def _load_script(self, pid, script_path):
        """Inject a JS script into the process
        @param pid: Process id.
        @param script_path: Path to JS script file.'
        """
        if pid not in self.sessions:
            raise CuckooFridaError(
                "Cannot inject into process, Frida is not attached."
            )

        session = self.sessions[pid]
        with open(script_path, "r") as fd:
            _script = fd.read()

        try:
            script = session.create_script(_script, runtime='v8')
            script.on("message", AgentHandler.on_receive)
            script.load()
        except frida.TransportError:
            raise CuckooFridaError("Failed to inject instrumentation script")
        log.info("Script loaded successfully")

        self.scripts[pid] = script

class Agent(object):
    """Interface of Frida's agent."""

    def __init__(self, pid, script):
        """@param pid: Process id.
        @param script: Script object to communicate with agent.
        """
        self.pid = pid
        self.script = script

    def call(self, func_name, args=None):
        """Call an exported function from our agent script
        @param func_name: Name of exported function.
        @param args: function arguments.
        """
        if args is not None and not isinstance(args, list):
            args = [args]

        self.script.exports.api(func_name, args)

class AgentHandler(object):
    """Handles logging of messages received from Frida's agent."""

    cached_loggers = {}

    @staticmethod
    def on_receive(message, payload):
        """A callback function invoked upon receiving a message from
        Frida's agent.
        """
        if message["type"] == "send":
            if "payload" in message:
                source, msg = message["payload"].split(":")
                logger = AgentHandler._get_logger(source)
                logger.info(msg)
        elif message["type"] == "error":
            logger = AgentHandler._get_logger("error")
            logger.error(message)

    @staticmethod
    def _get_logger(name):
        """Get file logging handler"""
        if name in AgentHandler.cached_loggers:
            return AgentHandler.cached_loggers[name]

        dir_path = FRIDA_LOGS_PATH

        logger = create_file_logger(dir_path, name)
        AgentHandler.cached_loggers[name] = logger
        return logger
