#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 - Present Sepine Tam, Inc. All Rights Reserved
#
# @Author : Sepine Tam (谭淞)
# @Email  : sepinetam@gmail.com
# @File   : ram_monitor.py

"""
Notes:
    This monitor feature was coded by Claude Code with GLM-4.7.

    By default, monitoring is disabled. If you want to control the maximum
    performance on your device, we suggest you review the code carefully
    before using it in production.
"""

import logging
import threading
from typing import Optional

import psutil

from ..core.types import RAMLimitExceededError
from .base import MonitorBase


class RAMMonitor(MonitorBase):
    """Monitor subprocess RAM usage during Stata execution.

    This monitor runs in a separate thread and checks the RAM usage of the
    Stata process at regular intervals. If the RAM usage exceeds the configured
    limit, it will kill the process and raise RAMLimitExceededError.

    Attributes:
        max_ram_mb: Maximum RAM allowed in MB (None = no limit)

    Example:
        >>> # Create monitor instance with configuration
        >>> monitor = RAMMonitor(max_ram_mb=8192)
        >>> # Start monitoring (called by StataDo)
        >>> monitor.start(process)
        >>> # ... process runs ...
        >>> # Stop monitoring (called by StataDo)
        >>> monitor.stop()
    """

    def __init__(self, max_ram_mb: Optional[int] = None):
        """
        Initialize the RAM monitor.

        Args:
            max_ram_mb: Maximum RAM allowed in MB. If None, no monitoring is done.
        """
        self.max_ram_mb = max_ram_mb
        self.process = None
        self._stop_event = threading.Event()
        self._monitor_thread: Optional[threading.Thread] = None
        self._exceeded_with_error: Optional[RAMLimitExceededError] = None

    def start(self, process) -> None:
        """Start monitoring the given process.

        Args:
            process: subprocess.Popen object to monitor
        """
        self.process = process

        if self.max_ram_mb is None:
            # No limit configured, don't start monitoring
            logging.debug("No RAM limit configured, skipping monitoring")
            return

        def monitor_loop():
            """Main monitoring loop that runs in a separate thread."""
            while not self._stop_event.is_set():
                # Check if process is still running
                if self.process.poll() is not None:
                    # Process has finished
                    logging.debug(f"Process (PID: {self.process.pid}) has finished")
                    break

                # Check RAM usage
                try:
                    # Get the process object
                    psutil_process = psutil.Process(self.process.pid)

                    # Get RAM usage in MB (RSS - Resident Set Size)
                    ram_mb = psutil_process.memory_info().rss / 1024 / 1024

                    # Check if exceeded
                    if ram_mb > self.max_ram_mb:
                        # Store the exception to be raised later
                        self._exceeded_with_error = RAMLimitExceededError(
                            ram_used_mb=ram_mb,
                            ram_limit_mb=self.max_ram_mb
                        )

                        logging.warning(
                            f"RAM limit exceeded: {ram_mb:.0f}MB > {self.max_ram_mb}MB. "
                            f"Killing Stata process (PID: {self.process.pid})"
                        )

                        # Kill the process
                        self.process.kill()
                        break

                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    # Process may have finished or we don't have access
                    logging.debug(f"Could not monitor process RAM: {e}")
                    break
                except Exception as e:
                    logging.error(f"Unexpected error monitoring process RAM: {e}")
                    break

                # Wait before next check (0.5 seconds)
                self._stop_event.wait(0.5)

        # Start daemon thread (will be killed when main thread exits)
        self._monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self._monitor_thread.start()

        logging.info(
            f"Started RAM monitoring for Stata process (PID: {self.process.pid}), "
            f"limit: {self.max_ram_mb}MB"
        )

    def stop(self) -> None:
        """Stop monitoring and check if RAM limit was exceeded.

        Raises:
            RAMLimitExceededError: If RAM limit was exceeded during monitoring
        """
        self._stop_event.set()
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=1.0)
        logging.debug("RAM monitor stopped")

        # If RAM limit was exceeded, raise the exception
        if self._exceeded_with_error:
            raise self._exceeded_with_error
