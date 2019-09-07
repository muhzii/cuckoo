# Copyright (C) 2014-2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd.

import os
import logging
import pkgutil
import sys
import urllib.request
import urllib.parse
import traceback
import time
import hashlib
import tempfile

from lib.core.packages import choose_package
from lib.common.abstracts import Package, Auxiliary
from lib.common.results import upload_to_host
from lib.core.config import Config
from lib.core.startup import init_logging
from lib.common.exceptions import CuckooError, CuckooPackageError
from lib.common.utils import hash_file
from modules import auxiliary

log = logging.getLogger("analyzer")

class BehavioralLogs(object):

    def __init__(self):
        self.logs = []

    def add_log(self, filename):
        """Add a new log file to the list of behavioral logs.
        @param filename: name of log file.
        @return: absolute path to file.
        """
        filepath = "%s/%s" % (tempfile.gettempdir(), filename)

        if filepath not in self.logs:
            self.logs.append(filepath)
            log.info(
                "Added new behavioral log '%s' to the list.", filename
            )
        return filepath

    def dump_logs(self):
        """Dump all behavioral logs to host."""
        for filepath in self.logs:
            filename = os.path.basename(filepath)

            upload_to_host(filepath, "logs/%s" % filename)
            os.unlink(filepath)

class Files(object):

    def __init__(self):
        self.files = []
        self.dumped = []

    def add_file(self, filepath):
        """Add filepath to the list of files and track the pid."""
        if filepath not in self.files:
            self.files.append(filepath)

            log.info(
                "Added new file to with path %s to the list.", filepath
            )

    def _dump_file(self, filepath):
        """Dump a file to the host."""
        if not os.path.isfile(filepath):
            log.warning("File at path %s does not exist, skip.", filepath)
            return

        sha256 = None
        try:
            sha256 = hash_file(hashlib.sha256, filepath)
        except IOError as e:
            log.error(
                "Error calculating hash of file '%s': %s", filepath, e
            )

        # Check if we already dumped the file.
        if sha256 in self.dumped:
            return

        upload_to_host(filepath, "files/" + os.path.basename(filepath))
        if sha256:
            self.dumped.append(sha256)

    def move_file(self, oldfilepath, newfilepath):
        """Update files list, as file is being relocated."""
        if oldfilepath in self.files:
            self.files.pop(self.files.index(oldfilepath))

        self.files.append(newfilepath)

    def dump_files(self):
        """Dump all pending files."""
        for filepath in self.files:
            self._dump_file(filepath)

class Analyzer(object):
    """Cuckoo Android analyzer.

    This class handles the initialization, execution, and termination of
    the analysis routine. It includes running auxiliary modules, starting
    an analysis package, instrumenting it, and keeping track of the analysis
    status.
    """

    def __init__(self):
        self.config = None
        self.target = None

        self.files = Files()
        self.logs = BehavioralLogs()

    def complete(self):
        """End analysis."""
        # Upload dropped files.
        self.files.dump_files()

        # Upload behavioral logs.
        self.logs.dump_logs()

        log.info("Analysis completed")

    def prepare(self):
        # Initialize logging.
        init_logging()

        # Parse the analysis configuration file generated by the agent.
        self.config = Config(cfg="analysis.conf")

        # We update the target according to its category. If it's a file, then
        # we store the path.
        if self.config.category == "file":
            self.target = os.path.join(
                tempfile.gettempdir(), self.config.file_name
            )
        # If it's a URL, well.. we store the URL.
        else:
            self.target = self.config.target

    def run(self):
        self.prepare()

        log.info("Starting analyzer from: {0}".format(os.getcwd()))
        log.info("Target is: {0}".format(self.target))

        # If no analysis package was specified at submission, we try to select
        # one automatically.
        if not self.config.package:
            log.info("No analysis package specified, trying to "
                     "detect it automagically")
            # If the analysis target is a file, we choose the package according
            # to the file format.
            if self.config.category == "file":
                package = choose_package(
                    self.config.file_type, self.config.file_name
                )
            # If it's an URL, we'll just use the default Internet Explorer
            # package.
            else:
                package = "default_browser"

            # If we weren't able to automatically determine the proper package,
            # we need to abort the analysis.
            if not package:
                raise CuckooError("No valid package available for file "
                                  "type: {0}".format(self.config.file_type))

            log.info("Automatically selected analysis package \"%s\"", package)
        # Otherwise just select the specified package.
        else:
            package = self.config.package

        # Generate the package path.
        package_name = "modules.packages.%s" % package

        # Try to import the analysis package.
        try:
            __import__(package_name, globals(), locals(), ["dummy"])
        # If it fails, we need to abort the analysis.
        except ImportError:
            raise CuckooError("Unable to import package \"{0}\", does "
                              "not exist.".format(package_name))

        # Initialize the package parent abstract.
        Package()

        # Enumerate the abstract's subclasses.
        try:
            package_class = Package.__subclasses__()[0]
        except IndexError as e:
            raise CuckooError("Unable to select package class "
                              "(package={0}): {1}".format(package_name, e))

        # Initialize the analysis package.
        package = package_class(self.config.options, self)

        # Initialize Auxiliary modules
        Auxiliary()
        prefix = auxiliary.__name__ + "."
        for loader, name, ispkg in pkgutil.iter_modules(auxiliary.__path__, prefix):
            if ispkg:
                continue

            # Import the auxiliary module.
            try:
                __import__(name, globals(), locals(), ["dummy"])
            except ImportError as e:
                log.warning("Unable to import the auxiliary module "
                            "\"%s\": %s", name, e)

        # Walk through the available auxiliary modules.
        aux_enabled = []
        for module in Auxiliary.__subclasses__():
            # Try to start the auxiliary module.
            try:
                aux = module(self.config.options)
                aux.start()
            except (NotImplementedError, AttributeError):
                log.warning("Auxiliary module %s was not implemented",
                            aux.__class__.__name__)
                continue
            except Exception as e:
                log.warning("Cannot execute auxiliary module %s: %s",
                            aux.__class__.__name__, e)
                continue
            else:
                log.info("Started auxiliary module %s",
                         aux.__class__.__name__)
                aux_enabled.append(aux)

        # Start analysis package. If for any reason, the execution of the
        # analysis package fails, we have to abort the analysis.
        package.start(self.target)

        # Instrument the analysis package.
        package.instrument()

        time_counter = 0
        while True:
            time_counter += 1
            if time_counter == int(self.config.timeout):
                log.info("Analysis timeout hit, terminating analysis")
                break

            try:
                # The analysis packages are provided with a function that
                # is executed at every loop's iteration. If such function
                # returns False, it means that it requested the analysis
                # to be terminate.
                if not package.check():
                    log.info("The analysis package requested the "
                             "termination of the analysis...")
                    break

                # If the check() function of the package raised some exception
                # we don't care, we can still proceed with the analysis but we
                # throw a warning.
            except Exception as e:
                log.warning("The package \"%s\" check function raised "
                            "an exception: %s", package_name, e)
            finally:
                # Zzz.
                time.sleep(1)

        try:
            # Before shutting down the analysis, the package can perform some
            # final operations through the finish() function.
            package.finish()
        except Exception as e:
            log.warning("The package \"%s\" finish function raised an "
                        "exception: %s", package_name, e)

        # Terminate the Auxiliary modules.
        for aux in aux_enabled:
            try:
                aux.stop()
            except (NotImplementedError, AttributeError):
                continue
            except Exception as e:
                log.warning("Cannot terminate auxiliary module %s: %s",
                            aux.__class__.__name__, e)

        # Let's invoke the completion procedure.
        self.complete()
        return True

if __name__ == "__main__":
    success = False
    error = ""

    try:
        # Initialize the main analyzer class.
        analyzer = Analyzer()
        # Run it and wait for the response.
        success = analyzer.run()

        data = {
            "status": "complete",
            "description": success,
        }
    # This is not likely to happen.
    except KeyboardInterrupt:
        error = "Keyboard Interrupt"
    # If the analysis process encountered a critical error, it will raise a
    # CuckooError exception, which will force the termination of the analysis
    # weill notify the agent of the failure. Also catched unexpected
    # exceptions.
    except Exception as e:
        # Store the error.
        error_exc = traceback.format_exc()

        # Just to be paranoid.
        if len(log.handlers):
            log.critical(error_exc)
        else:
            sys.stderr.write("{0}\n".format(error_exc))

        data = {
            "status": "exception",
            "description": error_exc
        }
    # Once the analysis is completed or terminated for any reason, we report
    # back to the agent, notifying that it can report back to the host.
    finally:
        # Establish connection with the new agent.
        urllib.request.urlopen("http://127.0.0.1:8000/status",
                               urllib.parse.urlencode(data).encode()).read()
