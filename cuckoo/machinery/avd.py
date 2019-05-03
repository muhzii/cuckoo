# Copyright (C) 2015-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd.

import logging
import os
import shutil
import subprocess
import time

from cuckoo.common.abstracts import Machinery
from cuckoo.common.exceptions import CuckooCriticalError

log = logging.getLogger(__name__)

class Avd(Machinery):
    """Virtualization layer for Android Emulator."""

    def _initialize_check(self):
        """Runs all checks when a machine manager is initialized.
        @raise CuckooMachineError: if the android emulator is not found.
        """
        self.emulator_processes = {}

        if not self.options.avd.emulator_path:
            raise CuckooCriticalError(
                "emulator path missing, please add it to the config file"
            )

        if not os.path.exists(self.options.avd.emulator_path):
            raise CuckooCriticalError(
                "emulator not found at specified path \"%s\""
                % self.options.avd.emulator_path
            )

        if not self.options.avd.adb_path:
            raise CuckooCriticalError(
                "adb path missing, please add it to the config file"
            )

        if not os.path.exists(self.options.avd.adb_path):
            raise CuckooCriticalError(
                "adb not found at specified path \"%s\""
                % self.options.avd.adb_path
            )

        if not self.options.avd.avd_path:
            raise CuckooCriticalError(
                "avd path missing, please add it to the config file"
            )

        if not os.path.exists(self.options.avd.avd_path):
            raise CuckooCriticalError(
                "avd not found at specified path \"%s\""
                % self.options.avd.avd_path
            )

        if not self.options.avd.reference_machine:
            raise CuckooCriticalError(
                "reference machine path missing, please add it "
                "to the config file"
            )

        machine_path = os.path.join(
            self.options.avd.avd_path, 
            self.options.avd.reference_machine
        )
        if not os.path.exists("%s.avd" % machine_path) or \
                not os.path.exists("%s.ini" % machine_path):
            raise CuckooCriticalError(
                "reference machine not found at specified "
                "path \"%s\"" % machine_path
            )

    def start(self, label, task):
        """Start a virtual machine.
        @param label: virtual machine name.
        @param task: task object.
        @raise CuckooMachineError: if unable to start.
        """
        log.debug("Starting vm %s" % label)

        self.duplicate_reference_machine(label)
        self.start_emulator(label, task)
        self.port_forward(label)
        self.start_agent(label)

    def stop(self, label):
        """Stops a virtual machine.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to stop.
        """
        log.debug("Stopping vm %s" % label)

        # Kill process.
        cmd = [
            self.options.avd.adb_path,
            "-s", "emulator-%s" % self.options.get(label)["emulator_port"],
            "emu", "kill",
        ]
        execute(cmd)

    def _list(self):
        """Lists virtual machines installed.
        @return: virtual machine names list.
        """
        return self.options.avd.machines

    def _status(self, label):
        """Gets current status of a vm.
        @param label: virtual machine name.
        @return: status string.
        """
        log.debug("Getting status for %s" % label)

    def restart_adb_server(self):
        """Restarts ADB server. This function is not used because we have to
        verify we don't have multiple devices.
        """
        log.debug("Restarting ADB server...")

        cmd = [self.options.avd.adb_path, "kill-server"]
        execute(cmd)
        log.debug("ADB server has been killed.")

        cmd = [self.options.avd.adb_path, "start-server"]
        execute(cmd)
        log.debug("ADB server has been restarted.")

    def duplicate_reference_machine(self, label):
        """Creates a new emulator based on a reference one."""
        ref_machine = self.options.avd.reference_machine
        log.debug("Duplicating Reference Machine '%s'.", ref_machine)

        # Clean/delete if emulator with the same label already exists.
        self.delete_old_emulator(label)

        # Define paths for both the reference and the new machines
        avd_path = self.options.avd.avd_path
        ref_conf_path = os.path.join(avd_path, ref_machine+".ini")
        new_conf_path = os.path.join(avd_path, label+".ini")

        ref_machine_path = os.path.join(avd_path, ref_machine+".avd/")
        new_machine_path = os.path.join(avd_path, label+".avd/")
        hw_qemu_conf = os.path.join(new_machine_path, "hardware-qemu.ini")

        # First we copy the template.
        log.debug(
            "Copying AVD reference config file '%s' in '%s'..", 
            ref_conf_path, new_conf_path
        )
        shutil.copyfile(ref_conf_path, new_conf_path)

        # Copy the internal files of the reference avd.
        log.debug(
            "Duplicating the AVD internal content from '%s' in '%s'..",
            ref_machine_path, new_machine_path
        )
        shutil.copytree(ref_machine_path, new_machine_path)

        # Than adapt the content of the copied files.
        self.replace_file_content(new_conf_path, ref_machine, label)
        self.replace_file_content(hw_qemu_conf, ref_machine, label)

    def delete_old_emulator(self, label):
        """Deletes any trace of an emulator that would have the same 
        name as the one of the current emulator."""
        avd_path = self.options.avd.avd_path

        # Delete the old configuration file
        old_config_path = os.path.join(avd_path, label+".ini")
        if os.path.exists(old_config_path):
            log.debug(
                "Deleting old emulator config file '%s'",
                old_config_path
            )
            os.remove(old_config_path)

        # Delete old machine image files
        old_machine_path = os.path.join(avd_path, label+".avd/")
        if os.path.isdir(old_machine_path):
            log.debug("Deleting old emulator image '%s'", old_machine_path)
            shutil.rmtree(old_machine_path)

    def replace_file_content(self, fname, original, replacement):
        """Replaces the specified motif by a specified value  
        in the specified file.
        """
        log.debug(
            "Replacing '%s' with '%s' in '%s'", 
            original, replacement, fname
        )
        
        newLines = []
        with open(fname, 'r') as fd:
            lines = fd.readlines()
            for line in lines:
                newLines.append(line.replace(original, replacement))

        with open(fname, 'w') as fd:
            fd.writelines(newLines)

    def start_emulator(self, label, task):
        """Starts the emulator."""
        emulator_port = self.options.get(label)["emulator_port"]

        cmd = [
            self.options.avd.emulator_path,
            "@%s" % label,
            "-no-snapshot-save",
            "-netspeed",
            "full",
            "-netdelay",
            "none",
            "-port",
            "%s" % emulator_port,
            "-tcpdump",
            self.pcap_path(task.id),
        ]

        # In headless mode we remove the skin, audio, and window support.
        if self.options.avd.mode == "headless":
            cmd += ["-no-skin", "-no-audio", "-no-window"]

        # If a proxy address has been provided for this analysis, then we have
        # to pass the proxy address along to the emulator command. The
        # mitmproxy instance is not located at the resultserver's IP address
        # though, so we manually replace the IP address by localhost.
        if "proxy" in task.options:
            _, port = task.options["proxy"].split(":")
            cmd += ["-http-proxy", "http://127.0.0.1:%s" % port]

        self.emulator_processes[label] = execute(cmd, async=True)
        time.sleep(10)
        # if not self.__checkADBRecognizeEmu(label):
        self.restart_adb_server()
        # Waits for device to be ready.
        self.wait_for_device_ready(label)

    def wait_for_device_ready(self, label):
        """Analyzes the emulator and returns when it's ready."""

        emulator_port = str(self.options.get(label)["emulator_port"])
        adb = self.options.avd.adb_path

        log.debug("Waiting for device emulator-"+emulator_port+" to be ready.")
        cmd = [
            adb,
            "-s", "emulator-%s" % emulator_port,
            "wait-for-device",
        ]
        execute(cmd)

        log.debug("Waiting for the emulator to be ready")
        log.debug(" - (dev.bootcomplete)")
        ready = False
        while not ready:
            cmd = [
                adb,
                "-s", "emulator-%s" % emulator_port,
                "shell", "getprop", "dev.bootcomplete",
            ]
            result = execute(cmd)
            if result is not None and result.strip() == "1":
                ready = True
            else:
                time.sleep(1)

        log.debug("- (sys_bootcomplete)")
        ready = False
        while not ready:
            cmd = [
                adb,
                "-s", "emulator-%s" % emulator_port,
                "shell", "getprop", "sys.boot_completed",
            ]
            result = execute(cmd)
            if result is not None and result.strip() == "1":
                ready = True
            else:
                time.sleep(1)

        log.debug(" - (init.svc.bootanim)")
        ready = False
        while not ready:
            cmd = [
                adb,
                "-s", "emulator-%s" % emulator_port,
                "shell", "getprop", "init.svc.bootanim",
            ]
            result = execute(cmd)
            if result is not None and result.strip() == "stopped":
                ready = True
            else:
                time.sleep(1)

        time.sleep(5)
        log.debug("Emulator emulator-"+emulator_port+" is ready !")

    def start_agent(self, label):
        cmd = [
            self.options.avd.adb_path,
            "-s", "emulator-%s" % self.options.get(label)["emulator_port"],
            "shell", "/data/local/agent.sh",
        ]
        execute(cmd, async=True)
        # Sleep 10 seconds to allow the agent to startup properly
        time.sleep(10)

    def port_forward(self, label):
        cmd = [
            self.options.avd.adb_path,
            "-s", "emulator-%s" % self.options.get(label)["emulator_port"],
            "forward", "tcp:8000", "tcp:8000",
        ]
        execute(cmd)

def execute(command, async=False):
    """Executes a command"""
    p = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    if not async:
        out, err = p.communicate()

        if p.returncode != 0:
            return None
        return out
