# -*- coding: utf-8 -*-

import json


def reader():
    """Read policy from policies.json"""
    with open('policies.json', 'r') as f:
        policy = json.load(f)
    return policy


def writer(policy):
    """Save policy in policies.json"""
    with open('policies.json', 'w') as f:
        json.dump(policy, f)
