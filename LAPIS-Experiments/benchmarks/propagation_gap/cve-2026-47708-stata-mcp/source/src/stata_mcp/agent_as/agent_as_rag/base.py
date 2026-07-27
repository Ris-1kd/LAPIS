#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 - Present Sepine Tam, Inc. All Rights Reserved
#
# @Author : Sepine Tam (谭淞)
# @Email  : sepinetam@gmail.com
# @File   : _base.py

from typing import List

from agents import Model, handoff
from agents.handoffs import Handoff
from agents.tool import function_tool

from ..agent_base import AgentBase
from ._tools import FetchFromDocs


class KnowledgeBase(AgentBase):
    NAME = "Knowledge Agent"
    agent_instructions: str = """
    You are a professional researcher on the area of ACADEMIC RESEARCH.
    """

    def __init__(self,
                 name: str = None,
                 instructions: str = None,
                 model: Model = None,
                 mcp_servers: list = None,
                 tools: list = None,
                 max_turns: int = 30,  # If the task is not easy, set larger number
                 DISABLE_TRACING: bool = False,
                 base_path: str = None,
                 *args,
                 **kwargs):
        # Initialize FetchFromDocs if base_path is provided
        self.doc_fetcher = None
        if base_path:
            self.doc_fetcher = FetchFromDocs(base_path)

            tools = tools or []
            tools.extend(self._load_fetch_tools())

        super().__init__(
            name=name or self.NAME,
            instructions=instructions,
            model=model,
            mcp_servers=mcp_servers,
            tools=tools,
            max_turns=max_turns,
            DISABLE_TRACING=DISABLE_TRACING,
            *args,
            **kwargs
        )

    def _load_fetch_tools(self) -> list:
        """
        Load document fetching tools for the agent.

        Returns:
            List of function tools for document knowledge retrieval
        """
        @function_tool()
        def list_knowledge_keywords() -> List[str]:
            """
            List all available knowledge keywords (document filenames).

            Returns:
                List of available document keywords that can be used to fetch knowledge
            """
            if not self.doc_fetcher:
                return []
            return self.doc_fetcher.KEYWORDS

        @function_tool()
        def fetch_knowledge(keyword: str) -> str:
            """
            Fetch knowledge content from document by keyword.

            Args:
                keyword: Document filename to search for and retrieve content from

            Returns:
                Document content as string, or error message if document not found
            """
            if not self.doc_fetcher:
                return "Document fetcher not initialized. Please provide base_path when creating the agent."
            return self.doc_fetcher.fetch_knowledge_from_docs(keyword)

        return [list_knowledge_keywords, fetch_knowledge]

    @property
    def TO_HANDOFF_AGENT(self) -> Handoff:
        return handoff(
            agent=self.agent,
        )
