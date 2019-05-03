# Copyright (C) 2015-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd.

import logging
import os
import shutil
import subprocess
import time
import telnetlib

from cuckoo.common.abstracts import Machinery
from cuckoo.common.exceptions import CuckooCriticalError

log = logging.getLogger(__name__)

class Avd(Machinery):
    """Virtualization layer for Android Emulator."""

    def _initialize_check(self):
        """Runs all checks when a machine manager is initialized.
        @raise CuckooMachineError: if the android emulator is not found.
        """
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

        # We restart the adb server just once at startup. This is important
        # in case either the server is not running or has some leftover 
        # settings that we might want to discard.
        self.adb_cmd("kill-server")
        self.adb_cmd("start-server")

    def start(self, label, task):
        """Start a virtual machine.
        @param label: virtual machine name.
        @param task: task object.
        @raise CuckooMachineError: if unable to start.
        """
        self.duplicate_reference_machine(label)

        log.debug("Starting vm %s" % label)
        emulator_port = self.start_emulator(label, task)

        self.start_agent(emulator_port)

    def stop(self, label):
        """Stops a virtual machine.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to stop.
        """
        log.debug("Stopping vm %s" % label)
        emulator_port = self.get_emulator_port(label)

        log.info("Stopping avd listening on port %s" % emulator_port)
        self.adb_cmd(["emu", "kill"], emulator_port)

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

    def _get_adb_cmd(self, args, emulator_port=None, shell=False):
        """Returns a formatted adb command"""
        cmd = [self.options.avd.adb_path]

        if emulator_port:
            cmd += ["-s", "emulator-%s" % emulator_port]

        if shell:
            cmd += ["shell"]

        if isinstance(args, (str, unicode)):
            args = args.split()

        return cmd + args

    def adb_cmd(self, args, emulator_port=None, async=False):
        """Runs an adb command"""
        cmd = self._get_adb_cmd(args, emulator_port)
        return execute(cmd, async)

    def adb_shell(self, args, emulator_port, async=False):
        """Runs a command on the shell"""
        cmd = self._get_adb_cmd(args, emulator_port, True)
        return execute(cmd, async)
    
    def get_emulator_port(self, label):
        """Returns the emulator port for the given label by Telnet'ing 
        into all the connected emulator consoles and see if one of them
        is our emulator.
        """
        output = self.adb_cmd("devices").splitlines()[1:-1]
        telnet = telnetlib.Telnet()

        for line in output:
            port = int(line.split('\t')[0].split('-')[1])
            
            try:
                telnet.open("127.0.0.1", port)
            except:
                # In case the emulator is offline
                continue

            telnet.read_until("OK")
            telnet.write("avd name\r\n")
            avd_name = telnet.read_until("OK").splitlines()[1]
            telnet.close()

            if avd_name == label:
                return port

    def start_emulator(self, label, task):
        """Starts the emulator."""
        cmd = [
            self.options.avd.emulator_path,
            "@%s" % label,
            "-no-snapshot-save",
            "-netspeed",
            "full",
            "-netdelay",
            "none",
            "-tcpdump",
            self.pcap_path(task.id),
        ]

        # In headless mode we remove the audio, and window support.
        if self.options.avd.mode == "headless":
            cmd += ["-no-audio", "-no-window"]

        # If a proxy address has been provided for this analysis, then we have
        # to pass the proxy address along to the emulator command. The
        # mitmproxy instance is not located at the resultserver's IP address
        # though, so we manually replace the IP address by localhost.
        if "proxy" in task.options:
            _, port = task.options["proxy"].split(":")
            cmd += ["-http-proxy", "http://127.0.0.1:%s" % port]
        
        # Start the emulator process ..
        execute(cmd, async=True)

        # We wait untill the emulator shows up for the adb server.
        while True:
            emulator_port = self.get_emulator_port(label)
            if emulator_port is not None:
                break
            time.sleep(1)
        log.debug("Emulator has been found!")

        # Wait for device to be ready.
        self.wait_for_device_ready(emulator_port)
        return emulator_port

    def wait_for_device_ready(self, emulator_port):
        """Analyzes the emulator and checks if booting and other
        stuff has finished.
        """
        log.debug("Waiting for device emulator-%s to be ready." % emulator_port)
        self.adb_cmd("wait-for-device", emulator_port)

        log.debug(" - (dev.bootcomplete)")
        while True:
            out = self.adb_shell(["getprop", "dev.bootcomplete"], emulator_port)
            if out is not None and out.strip() == "1":
                break
            time.sleep(1)

        log.debug(" - (sys_bootcomplete)")
        while True:
            out = self.adb_shell(["getprop", "sys.boot_completed"], emulator_port)
            if out is not None and out.strip() == "1":
                break
            time.sleep(1)

        log.debug(" - (init.svc.bootanim)")
        while True:
            out = self.adb_shell(["getprop", "init.svc.bootanim"], emulator_port)
            if out is not None and out.strip() == "stopped":
                break
            time.sleep(1)
        
        log.debug("Device emulator-%s is ready!" % emulator_port)

    def start_agent(self, emulator_port):
        """Starts the cuckoo agent"""
        log.debug('Starting the cuckoo agent on emulator-%s' % emulator_port)

        # Obtain root access
        self.adb_cmd("root", emulator_port)

        # Set SELinux to permissive..
        # For now, this is required for frida to work properly
        # on some versions of Android
        # https://github.com/frida/frida-core/tree/master/lib/selinux
        self.adb_shell(["setenforce", "0"], emulator_port)
        
        shell_arg = "/data/local/tmp/android-agent.sh"
        self.adb_shell(shell_arg, emulator_port, async=True)

    def port_forward(self, label, src, dest):
        """Configures port forwarding for a vm.
        @param label: virtual machine name.
        @param src: port on host.
        @param dest: port on guest.
        """
        emulator_port = self.get_emulator_port(label)
        args = ["forward", "tcp:%s" % src, "tcp:%s" % dest]
        
        self.adb_cmd(args, emulator_port)

        # TODO: we'll see
        time.sleep(10)

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
