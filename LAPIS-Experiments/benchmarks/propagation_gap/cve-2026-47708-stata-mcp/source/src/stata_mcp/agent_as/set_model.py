#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 - Present Sepine Tam, Inc. All Rights Reserved
#
# @Author : Sepine Tam (谭淞)
# @Email  : sepinetam@gmail.com
# @File   : set_model.py

import os

from agents import Model, OpenAIChatCompletionsModel
from openai import AsyncOpenAI, OpenAI


class Provider:
    def __init__(self, provider: str = "openai"):
        self.provider_name = provider.lower()

    @property
    def API_KEY(self):
        return os.getenv(f"{self.provider_name.upper()}_API_KEY")

    @property
    def BASE_URL(self):
        return os.getenv(f"{self.provider_name.upper()}_BASE_URL")

    @property
    def client(self):
        return OpenAI(api_key=self.API_KEY, base_url=self.BASE_URL)

    @property
    def async_client(self):
        return AsyncOpenAI(api_key=self.API_KEY, base_url=self.BASE_URL)


def set_model(model_name: str = None,
              api_key: str = None,
              base_url: str = "https://api.openai.com/v1",
              openai_client: AsyncOpenAI = None) -> Model:
    OPENAI_MODEL = os.getenv("OPENAI_MODEL", model_name)
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", api_key)
    OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", base_url)

    OPENAI_CLIENT = openai_client or AsyncOpenAI(
        api_key=OPENAI_API_KEY,
        base_url=OPENAI_BASE_URL
    )
    return OpenAIChatCompletionsModel(
        model=OPENAI_MODEL,
        openai_client=OPENAI_CLIENT
    )
