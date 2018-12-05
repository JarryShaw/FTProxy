import json


# Read policy from policies.json
def reader():
    with open('policies.json', 'r') as f:
        policy = json.load(f)
    return policy


# Save policy in policies.json
def writer(policy):
    with open('policies.json', 'w') as f:
        json.dump(policy, f, indent=2)
