#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 - Present Sepine Tam, Inc. All Rights Reserved
#
# @Author : Sepine Tam (谭淞)
# @Email  : sepinetam@gmail.com
# @File   : any_as_tools.py

from typing import Any, Dict, List, Optional, Union

from agents import Agent, FunctionTool

from ..agent_base import AgentBase


def agent_list_to_tools(agents: List[Union[Agent, AgentBase]], descriptions: Optional[List[str]] = None, raise_on_error: bool = False) -> List[FunctionTool]:
    """
    Convert a list of Agent objects to their tool representations.

    Args:
        agents: List of Agent objects to convert
        descriptions: Optional list of descriptions for each agent tool
        raise_on_error: If True, raise exceptions on errors. If False, print error and skip.

    Returns:
        List[FunctionTool]: List of agent tools
    """
    tools = []

    for i, agent in enumerate(agents):
        if isinstance(agent, AgentBase):
            # Custom AgentBase wrapper - use agent.agent.as_tool
            if not hasattr(agent.agent, 'as_tool'):
                error_msg = f"AgentBase at index {i} does not have as_tool property"
                if raise_on_error:
                    raise ValueError(error_msg)
                else:
                    print(f"Warning: {error_msg}. Skipping...")
                    continue

            # Get tool name from agent or generate default
            tool_name = getattr(agent, 'NAME', f"agent_{i}")

            tool = agent.agent.as_tool(
                tool_name=tool_name,
                tool_description=descriptions[i] if descriptions and i < len(descriptions) else f"Tool for {tool_name}",
                max_turns=getattr(agent, 'max_turns', 30)
            )
        else:
            # Direct OpenAI Agents SDK Agent - use as_tool directly
            if not hasattr(agent, 'as_tool'):
                error_msg = f"Agent at index {i} does not have as_tool property"
                if raise_on_error:
                    raise ValueError(error_msg)
                else:
                    print(f"Warning: {error_msg}. Skipping...")
                    continue

            # Get tool name from agent or generate default
            tool_name = getattr(agent, 'name', f"agent_{i}")

            tool = agent.as_tool(
                tool_name=tool_name,
                tool_description=descriptions[i] if descriptions and i < len(descriptions) else f"Tool for {tool_name}",
                max_turns=getattr(agent, 'max_turns', 30)
            )

        tools.append(tool)

    return tools


def dict_to_agent_tools(agents_dict: Dict[str, Dict[str, Any]], raise_on_error: bool = False) -> List[FunctionTool]:
    """
    Convert a dictionary of agents to their tool representations.

    Args:
        agents_dict: Dictionary where keys are tool names and values contain agents and metadata
        raise_on_error: If True, raise exceptions on errors. If False, print error and skip.

    Returns:
        List[FunctionTool]: List of agent tools
    """
    tools = []

    for tool_name, agent_data in agents_dict.items():
        if isinstance(agent_data, dict):
            agent = agent_data.get('agent')
            description = agent_data.get('description')
            max_turns = agent_data.get('max_turns', 30)
        else:
            agent = agent_data
            description = None
            max_turns = 30

        # Check if agent is None
        if agent is None:
            error_msg = f"Agent for '{tool_name}' is None"
            if raise_on_error:
                raise ValueError(error_msg)
            else:
                print(f"Warning: {error_msg}. Skipping...")
                continue

        if isinstance(agent, AgentBase):
            # Custom AgentBase wrapper - use agent.agent.as_tool
            if not hasattr(agent.agent, 'as_tool'):
                error_msg = f"AgentBase for '{tool_name}' does not have as_tool property"
                if raise_on_error:
                    raise ValueError(error_msg)
                else:
                    print(f"Warning: {error_msg}. Skipping...")
                    continue

            tool = agent.agent.as_tool(
                tool_name=tool_name,
                tool_description=description or f"Tool for {tool_name}",
                max_turns=max_turns
            )
        else:
            # Direct OpenAI Agents SDK Agent - use as_tool directly
            if not hasattr(agent, 'as_tool'):
                error_msg = f"Agent for '{tool_name}' does not have as_tool property"
                if raise_on_error:
                    raise ValueError(error_msg)
                else:
                    print(f"Warning: {error_msg}. Skipping...")
                    continue

            tool = agent.as_tool(
                tool_name=tool_name,
                tool_description=description or f"Tool for {tool_name}",
                max_turns=max_turns
            )

        tools.append(tool)

    return tools
