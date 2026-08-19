#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 - Present Sepine Tam, Inc. All Rights Reserved
#
# @Author : Sepine Tam (谭淞)
# @Email  : sepinetam@gmail.com
# @File   : handoff.py

from typing import List

from agents import Agent
from agents.handoffs import Handoff

from ..agent_base import AgentBase
from .base import KnowledgeBase


class HandoffAgent(AgentBase):
    NAME: str = "Knowledge Fetch Agent"
    agent_instructions: str = """
    You are a professional researcher for handoff.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.handoffs = []
        _handoffs = kwargs.get("handoffs")
        if _handoffs:
            self.register_agents(_handoffs, is_typing_warning=True)

    def register_agents(self,
                        agents: KnowledgeBase | Agent | Handoff | List[Agent | Handoff],
                        is_typing_warning: bool = False) -> List:
        if not isinstance(agents, List):
            agents = [agents]
        for agent in agents:
            if isinstance(agent, KnowledgeBase):
                self.handoffs.append(agent.TO_HANDOFF_AGENT)
            elif isinstance(agent, (Agent, Handoff)):
                self.handoffs.append(agent)
            else:
                if is_typing_warning:
                    print(f"Warning: {agent} is not a valid agent for handoff")
        return self.handoffs

    @property
    def HANDOFF_AGENT(self):
        handoff_agent = self.agent
        handoff_agent.handoffs = self.handoffs
        return handoff_agent

    @property
    def as_tool(self):
        return self.HANDOFF_AGENT.as_tool(
            tool_name="Knowledge fetch",
            tool_description="Fetch knowledge from the previous setting.",
            max_turns=self.max_turns
        )
