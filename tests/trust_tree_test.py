import unittest
from unittest.mock import MagicMock
from unittest.mock import patch

from policyuniverse.arn import ARN
from src.client import IAMPolicyEvaluator

'''
start_node = the node to start searching from
target_role = the role we want to retrieve trust relationship for 
visited = keep track of which nodes we already searched
'''
def search_trust_tree(start_node, target_role, visited=None): 
    if visited is None: 
        visited = set()
    visited.add(start_node.arn)

    if start_node.arn == target_role: 
        return [ node.arn for node in start_node.trust_relationships ]

    for child in start_node.trust_relationships:
        if child.arn not in visited: 
            return search_trust_tree(child, target_role, visited)

class TestTrustTree(unittest.TestCase): 
    def setUp(self): 
        self.dev_role = ARN('arn:aws:iam::123456789012:role/developers') 
        self.jenkins_role = ARN('arn:aws:iam::123456789012:role/jenkins')
        self.incident_role = ARN('arn:aws:iam::123456789012:role/incident')
        self.jenkins_controller_role = ARN('arn:aws:iam::123456789012:role/jenkins-controller')
        self.test_role = ARN('arn:aws:iam::123456789012:role/tests') 

        self.test_params = {
            'resource': 'arn:aws:dynamodb:us-west-2:123456789012:table/test-table',
            'service': 'dynamodb',
            'identity': self.dev_role,
            'action': 'dynamodb:PutItem',
            'aws_profiles': {},
            'role_assumption_only': True,
        }

        self.assume_role_policies = [
            {
                'arn': self.jenkins_role.arn, 
                'relationships': {
                    'Statement': [{
                        'Action': 'sts:AssumeRole',
                        'Effect': 'Allow',
                        'Principal': {
                            'AWS': [
                                self.dev_role.arn,
                                'arn:aws:iam::123456789012:role/jenkins-admin',
                            ]
                        }
                    }]
                }
            },
            {
                'arn': self.incident_role.arn,
                'relationships': {
                    'Statement': [{
                        'Action': 'sts:AssumeRole',
                        'Effect': 'Allow',
                        'Principal': {
                            'AWS': self.dev_role.arn
                        }
                    }]
                }
            },
            {
                'arn': self.jenkins_controller_role.arn,
                'relationships': {
                    'Statement': [{
                        'Action': 'sts:AssumeRole',
                        'Effect': 'Allow',
                        'Principal': {
                            'AWS': self.jenkins_role.arn,
                        }
                    }]
                }
            },
            {
                'arn': 'arn:aws:iam::123456789012:role/tests', 
                'relationships': {
                    'Statement': [{
                        'Action': 'sts:AssumeRole',
                        'Effect': 'Allow',
                        'Principal': {
                            'AWS': self.jenkins_controller_role.arn,
                        }
                    }]
                }
            },
        ]

    def test_trust_tree(self): 
        trusted_roles = [
            self.jenkins_role,
            self.incident_role
        ]

        evaluator = IAMPolicyEvaluator(self.test_params)
        evaluator.build_trust_tree(trusted_roles, self.assume_role_policies, evaluator.trust_tree)

        examined_role = evaluator.arn
        tree = evaluator.trust_tree

        self.assertEqual(tree.arn, examined_role)
        self.assertTrue(tree.is_root_node)
  
        trusted_roles = [node.arn for node in tree.trust_relationships]
        assert self.jenkins_role.arn in trusted_roles
        assert self.incident_role.arn in trusted_roles

    def test_traverse_trust_tree(self): 
        trusted_roles = [
            self.jenkins_role,
            self.incident_role
        ]

        evaluator = IAMPolicyEvaluator(self.test_params)
        evaluator.build_trust_tree(trusted_roles, self.assume_role_policies, evaluator.trust_tree)

        examined_role = evaluator.arn
        tree = evaluator.trust_tree

        jenkins_relationships = search_trust_tree(tree, self.jenkins_role.arn)
        print(jenkins_relationships)
        assert self.jenkins_controller_role.arn in jenkins_relationships

        incident_relationships = search_trust_tree(tree, self.incident_role.arn)
        self.assertEqual(incident_relationships, None)

        jenkins_controller_relationships = search_trust_tree(tree, self.jenkins_controller_role.arn)
        assert self.test_role.arn in jenkins_controller_relationships
