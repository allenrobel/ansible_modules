#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/12/17 10:56
# @Author  : arobel
# @Site    : test string length
# @File    : test_string_length
# @Software: VS Code

import pytest

def string_length(string):
    if not isinstance(string, str):
        raise TypeError("Please provide a string argument")
    return len(string)
def test_pos_string_length():
    string = "test"
    assert string_length(string) == 4
    string = ""
    assert string_length(string) == 0
def test_neg_string_length_type():
    string = 10
    with pytest.raises(TypeError):
        string_length(string)
    string = {}
    with pytest.raises(TypeError):
        string_length(string)
