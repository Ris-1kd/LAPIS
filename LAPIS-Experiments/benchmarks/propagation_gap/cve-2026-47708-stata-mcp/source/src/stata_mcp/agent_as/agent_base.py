#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 - Present Sepine Tam, Inc. All Rights Reserved
#
# @Author : Sepine Tam (谭淞)
# @Email  : sepinetam@gmail.com
# @File   : agent_base.py

import os
from abc import ABC

from agents import Agent, Model, set_tracing_disabled


class AgentBase(ABC):
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", None)
    NAME: str
    agent_instructions: str

    def __init__(self,
                 name: str = None,
                 instructions: str = None,
                 model: Model = None,
                 mcp_servers: list = None,
                 tools: list = None,
                 max_turns: int = 30,  # If the task is not easy, set larger number
                 DISABLE_TRACING: bool = False,
                 *args,
                 **kwargs):
        # Disable tracing while not found openai_api_key and set tracing disable.
        set_tracing_disabled(
            (not kwargs.get("OPENAI_API_KEY", self.OPENAI_API_KEY)) or DISABLE_TRACING
        )

        self.agent = Agent(
            name=name or self.NAME,
            instructions=instructions or self.agent_instructions,
        )

        self.max_turns = max_turns

        if model:
            self.agent.model = model

        if mcp_servers:
            self.agent.mcp_servers = mcp_servers

        if tools:  # if exist tools, register tools
            self.agent.tools = tools
