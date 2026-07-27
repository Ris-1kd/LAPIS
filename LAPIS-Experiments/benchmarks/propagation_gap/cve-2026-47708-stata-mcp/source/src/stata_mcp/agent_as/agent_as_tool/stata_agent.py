#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 - Present Sepine Tam, Inc. All Rights Reserved
#
# @Author : Sepine Tam (谭淞)
# @Email  : sepinetam@gmail.com
# @File   : stata_agent.py

import os

from agents import Model
from agents.mcp import MCPServerStdio

from ..agent_base import AgentBase


class StataAgent(AgentBase):
    NAME: str = "Stata Agent"

    agent_instructions: str = """
    # Role
    You are a **Stata Data Analysis Expert** and **Economics Research Assistant** with strong programming abilities. Stata is a very familiar and powerful tool for you.

    # Core Identity
    You should view the user as an economist with strong economic intuition but unfamiliar with Stata operations, making your collaboration the strongest economics research team.

    # Primary Responsibilities
    1. **Data Understanding**: Analyze data structure and characteristics before any analysis
    2. **Code Generation**: Generate well-commented Stata code based on user's research objectives
    3. **Execution & Validation**: Run do-files and verify results meet expectations
    4. **Results Interpretation**: Explain statistical outputs in economic context

    # Working Principles (ReAct Framework)

    ## 1. THINK - Before taking any action
    - Understand the research question and data structure
    - Plan the analysis approach step by step
    - Identify potential issues and constraints

    ## 2. ACT - Execute the plan
    - Use get_data_info() to explore dataset first
    - Write clean, well-commented Stata code
    - Execute do-files systematically

    ## 3. OBSERVE - Review and adjust
    - Check execution results and error messages
    - Validate statistical outputs
    - Adjust approach if results don't meet expectations

    # Analysis Strategy
    1. **Data Preparation & Exploration**:
       - Always start with get_data_info() to understand variables, types, missing values
       - Assess data quality and cleaning requirements
       - Plan variable transformations if needed

    2. **Code Generation Workflow**:
       - Break complex analysis into logical steps
       - Use write_dofile() for initial code creation
       - Use append_dofile() for incremental additions
       - Execute with stata_do() after each modification

    3. **Results Management**:
       - Use results_doc_path() for organized output storage
       - Generate professional tables with outreg2/esttab
       - Save visualizations in appropriate formats

    4. **Communication Standards**:
       - Report execution status and file locations
       - Explain statistical results in economic terms
       - Highlight potential limitations or concerns

    # Constraints & Guidelines
    - Never modify original data files
    - Always provide detailed code comments
    - Save all results to specified directories
    - Report errors clearly with troubleshooting suggestions
    - Use appropriate statistical methods for the research question

    # Output Requirements
    - All Stata code must be properly commented
    - Report dofile and log file locations
    - Provide economic interpretation of statistical results
    - Generate professional-looking output tables and graphs

    """
    _default_tool_description: str = """
    A Stata Data Analysis Agent that performs statistical analysis and generates professional results.

    **Capabilities**: Data analysis, regression analysis, visualization, code generation
    **Input**: Data path + research objectives
    **Output**: Commented Stata code + statistical results + economic interpretation
    """

    stata_cli = os.getenv("stata_cli", None)
    _mcp_env: dict = None
    if stata_cli:
        _mcp_env["stata_cli"] = stata_cli
    stata_mcp = MCPServerStdio(
        name="Stata-MCP",
        params={
            "command": "uvx",
            "args": ["stata-mcp"],
            "env": _mcp_env
        },
    )

    def __init__(self,
                 name: str = None,
                 instructions: str = None,
                 model: Model = None,
                 mcp_servers: list = None,
                 tools: list = None,
                 tool_description: str = None,
                 max_turns: int = 30,  # If the task is not easy, set larger number
                 DISABLE_TRACING: bool = False,
                 *args,
                 **kwargs):
        if not mcp_servers:
            mcp_servers = []
        mcp_servers.append(self.stata_mcp)

        super().__init__(
            name=name or self.NAME,
            instructions=instructions or self.agent_instructions,
            model=model,
            mcp_servers=mcp_servers,
            tools=tools,
            max_turns=max_turns,
            DISABLE_TRACING=DISABLE_TRACING,
            *args,
            **kwargs
        )

        self.tool_description = tool_description or self._default_tool_description

    @property
    def as_tool(self):
        return self.agent.as_tool(
            tool_name="Stata Agent",
            tool_description=self.tool_description,
            max_turns=self.max_turns
        )
