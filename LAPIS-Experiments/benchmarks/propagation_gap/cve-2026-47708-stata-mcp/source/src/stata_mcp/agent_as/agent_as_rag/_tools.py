#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 - Present Sepine Tam, Inc. All Rights Reserved
#
# @Author : Sepine Tam (谭淞)
# @Email  : sepinetam@gmail.com
# @File   : _tools.py

from pathlib import Path
from typing import Dict, List


class FetchFromDocs:
    """
    When knowledge is clearly categorized and limited in quantity,
    documents can be used as a knowledge base instead of vectorized retrieval
    """

    def __init__(self,
                 documents_base_path: str | Path,
                 allowed_extensions=None):
        self.documents_base_path = Path(documents_base_path)
        # Check whether the path exists
        if not self.documents_base_path.exists():
            raise FileNotFoundError(f"{self.documents_base_path} does not exist")

        self.allowed_extensions = allowed_extensions or [".md", ".txt"]

    @property
    def FILES(self) -> Dict[str, Path]:
        docs_mapping = {}
        files = self.documents_base_path.iterdir()
        for file_path in files:
            if file_path.suffix in self.allowed_extensions:
                docs_mapping[file_path.name] = file_path
        return docs_mapping

    @property
    def KEYWORDS(self) -> List[str]:
        docs_mapping = self.FILES
        keywords_list = []
        for key, value in docs_mapping.items():
            keywords_list.append(key)
        return keywords_list

    def fetch_knowledge_from_docs(self, keyword: str, encoding: str = "utf-8") -> str:
        if keyword in self.KEYWORDS:
            with open(self.FILES[keyword], "r", encoding=encoding) as f:
                knowledge = f.read()
                return knowledge
        else:
            return f"{keyword} not found in documents, you can use keywords in {self.KEYWORDS}"
