#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2026 - Present Sepine Tam, Inc. All Rights Reserved
#
# @Author : Sepine Tam (谭淞)
# @Email  : sepinetam@gmail.com
# @File   : base.py

from abc import ABC, abstractmethod
from typing import Any


class MonitorBase(ABC):
    """Abstract base class for all process monitors.

    All monitors (RAMMonitor, TimeoutMonitor, etc.) should inherit from this class
    and implement the required methods.

    The monitor lifecycle is:
    1. Create instance with configuration
    2. Call start(process) to begin monitoring
    3. Call stop() when process finishes
    """

    @abstractmethod
    def start(self, process: Any) -> None:
        """Start monitoring the given process.

        Args:
            process: subprocess.Popen object to monitor
        """
        pass

    @abstractmethod
    def stop(self) -> None:
        """Stop monitoring.

        This should be called when the process finishes normally.
        """
        pass
