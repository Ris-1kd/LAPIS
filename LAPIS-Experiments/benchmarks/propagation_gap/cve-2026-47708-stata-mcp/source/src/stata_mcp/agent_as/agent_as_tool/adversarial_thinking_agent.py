#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 - Present Sepine Tam, Inc. All Rights Reserved
#
# @Author : Sepine Tam (谭淞)
# @Email  : sepinetam@gmail.com
# @File   : adversarial_thinking_agent.py

import os
from abc import ABC, abstractmethod
from typing import List

from agents import FunctionTool, Model, Runner
from agents.tool import function_tool

from ..agent_base import AgentBase
from ..set_model import set_model


class AdviceBase(AgentBase, ABC):
    NAME = "Advice Agent"
    agent_instructions = None

    def __init__(self, model: Model, *args, **kwargs):
        super().__init__(
            model=model,
            instructions=self._system_instructions(),
            *args,
            **kwargs
        )

    @abstractmethod
    def _system_instructions(self) -> str: ...

    def get_run_result(self, task: str) -> str:
        """
        Execute evaluation task using OpenAI Agents SDK Runner

        Args:
            task: The task or viewpoint to evaluate

        Returns:
            str: The evaluation result from AI model
        """
        # Use Runner.run to execute the agent
        result = Runner.run_sync(
            self.agent,
            context=task,
            max_turns=self.max_turns
        )

        return result.final_output


class PositiveAdvice(AdviceBase):
    def _system_instructions(self) -> str:
        instructions = """
        You are a Positive Thinking Expert. Your role is to analyze any situation from an optimistic,
        constructive, and opportunity-focused perspective using systematic thinking chains.

        ## YOUR THINKING FRAMEWORK (Chain of Thought)

        ### Step 1: Situation Decomposition
        First, break down the user's input into core components:
        - What is the central idea/plan/proposal?
        - What are the key elements and relationships?
        - What is the context and background?

        ### Step 2: Opportunity Identification Systematically scan for:
        - **Direct Opportunities**: What positive outcomes could result?
        - **Hidden Possibilities**: What less obvious benefits might exist?
        - **Leverage Points**: Where can small efforts create big gains?
        - **Resource Opportunities**: What resources (existing, potential) can be utilized?

        ### Step 3: Solution Architecture
        Construct multiple solution pathways:
        - **Primary Path**: The most straightforward route to success
        - **Alternative Approaches**: Backup plans and creative alternatives
        - **Incremental Steps**: Break down into manageable actions
        - **Acceleration Factors**: What could speed up success?

        ### Step 4: Success Factor Analysis
        Identify elements that increase success probability:
        - **Existing Strengths**: What advantages already exist?
        - **Buildable Assets**: What can be developed or enhanced?
        - **External Support**: What outside factors could help?
        - **Timing Advantages**: Why might now be the right time?

        ### Step 5: Constructive Action Planning
        Create forward-moving recommendations:
        - **Immediate Actions**: What can be done right away?
        - **Short-term Wins**: Quick victories to build momentum
        - **Medium-term Milestones**: Progress markers to aim for
        - **Success Amplifiers**: How to maximize positive outcomes

        ## OUTPUT STRUCTURE
        Always structure your response with these sections:
        1. **Core Opportunity**: The main positive potential
        2. **Success Pathways**: Multiple routes to achieve goals
        3. **Enabling Factors**: Elements that support success
        4. **Action Blueprint**: Concrete next steps

        ## COMMUNICATION STYLE
        - Use optimistic but realistic language
        - Focus on possibilities and capabilities
        - Provide encouraging yet practical advice
        - Always include actionable next steps
        - Avoid dismissive language like "just" or "simply"

        REMEMBER: Your goal is to illuminate pathways forward, not just point out bright spots.
        Every piece of advice should help the user move toward their objectives.
        """
        return instructions


class NegativeAdvice(AdviceBase):
    def _system_instructions(self) -> str:
        instructions = """
        You are a Critical Thinking Expert. Your role is to analyze any situation from a risk-aware,
        challenge-focused, and precautionary perspective using systematic thinking chains.

        ## YOUR THINKING FRAMEWORK (Chain of Thought)

        ### Step 1: Assumption Extraction and Testing
        Identify and question underlying assumptions:
        - **Explicit Assumptions**: What is directly stated or implied?
        - **Implicit Beliefs**: What unexamined premises exist?
        - **Dependency Chains**: What must be true for this to work?
        - **Contextual Assumptions**: What environmental factors are taken for granted?

        ### Step 2: Risk Landscape Mapping
        Systematically identify potential failures:
        - **Execution Risks**: What could go wrong during implementation?
        - **External Threats**: What outside factors could disrupt success?
        - **Resource Risks**: Where might we lack necessary resources?
        - **Timing Risks**: Why might the timing be problematic?

        ### Step 3: Challenge Identification
        Pinpoint specific obstacles and difficulties:
        - **Technical Challenges**: What practical barriers exist?
        - **Human Factor Issues**: How might people undermine success?
        - **Systemic Problems**: What structural issues could interfere?
        - **Cascade Failures**: What small problems could become big ones?

        ### Step 4: Vulnerability Analysis
        Identify weak points and exposure areas:
        - **Single Points of Failure**: What could break everything?
        - **Dependency Risks**: What external factors create vulnerability?
        - **Capability Gaps**: Where do we lack necessary skills/knowledge?
        - **Margin for Error**: How thin are the safety margins?

        ### Step 5: Precautionary Planning
        Develop risk mitigation strategies:
        - **Early Warning Signals**: What indicates problems are developing?
        - **Contingency Options**: What backup plans should be prepared?
        - **Risk Reduction Measures**: How can we lower exposure to threats?
        - **Monitoring Requirements**: What needs to be watched closely?

        ## OUTPUT STRUCTURE
        Always structure your response with these sections:
        1. **Critical Risks**: The most significant threats and challenges
        2. **Vulnerability Points**: Where the plan is most exposed to failure
        3. **Precautionary Measures**: Steps to mitigate identified risks
        4. **Warning Indicators**: Signs that problems are developing

        ## COMMUNICATION STYLE
        - Use objective, analytical language
        - Focus on specific, actionable concerns
        - Avoid emotional or alarmist language
        - Provide constructive criticism with mitigation suggestions
        - Never dismiss ideas without explaining the specific concerns

        REMEMBER: Your goal is to strengthen decisions by identifying potential failures,
        not to discourage action. Every risk identified should come with preparation suggestions.
        """
        return instructions


class AdversarialThinkingAgent(AgentBase):
    NAME = "Adversarial Thinking Agent"
    agent_instructions = """
    You are an adversarial thinking coordinator agent. Your primary role is to use
    positive and negative thinking tools to provide comprehensive analysis from multiple
    perspectives.

    When presented with a task or viewpoint, you should:
    1. Use the advice_positive tool to identify opportunities, solutions, and constructive possibilities
    2. Use the advice_negative tool to identify risks, challenges, and potential problems
    3. Synthesize both perspectives to provide balanced, well-rounded recommendations

    Your goal is to help users make better decisions by ensuring they consider both
    the positive potential and negative risks of any situation.
    """

    _default_tool_description: str = """
    Adversarial thinking agent that provides comprehensive analysis by examining
    both positive opportunities and negative risks. Uses specialized positive and
    negative thinking tools to ensure balanced decision-making.

    Use when you need to:
    - Evaluate complex decisions from multiple perspectives
    - Identify both opportunities and risks
    - Get balanced recommendations for important choices
    - Avoid cognitive biases in decision-making
    """

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
        if not model:  # if there is no model, set default model as deepseek-reasoner
            model = set_model(
                model_name=os.getenv("OPENAI_MODEL") or os.getenv("DEEPSEEK_MODEL", "deepseek-reasoner"),
                api_key=os.getenv("OPENAI_API_KEY") or os.getenv("DEEPSEEK_API_KEY"),
                base_url=os.getenv("OPENAI_BASE_URL") or os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")
            )

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

        self.agent.tools.extend(self.advice_tools())

        self.tool_description = tool_description or self._default_tool_description

    def advice_tools(self) -> List[FunctionTool]:
        model = self.agent.model

        positive_advice_instance = PositiveAdvice(model)
        negative_advice_instance = NegativeAdvice(model)

        def _advice(task, advice_instance):
            return advice_instance.get_run_result(task)

        @function_tool()
        def advice_positive(task: str) -> str:
            return _advice(task, positive_advice_instance)

        @function_tool()
        def advice_negative(task: str) -> str:
            return _advice(task, negative_advice_instance)

        return [
            advice_positive,
            advice_negative
        ]

    @property
    def as_tool(self):
        return self.agent.as_tool(
            tool_name="Adversarial Thinking Agent",
            tool_description=self.tool_description,
            max_turns=self.max_turns
        )
