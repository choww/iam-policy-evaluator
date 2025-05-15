import unittest
from unittest.mock import MagicMock
from unittest.mock import patch

from policyuniverse.arn import ARN
from src.client import IAMPolicyEvaluator
from src.tree import Node, RoleAssumptionTree

'''
start_node = the node to start searching from
target_role = the role we want to retrieve trust relationship for 
results = dict that contains the cumulative output of this function--has this structure: 
    { 
        'role': { 
            'assumed-role': { 'assumed-role': {} } 
        }
    }
'''
def search_trust_tree(start_node, target_role, results): 
    # once we found the the role we want to build the trust tree for, iterate through all its trust relationships
    if start_node.arn == target_role: 
        results[start_node.arn] = {}
        root = results[start_node.arn] 

        for relationship in start_node.trust_relationships: 
            search_trust_tree(relationship, relationship.arn, root)

    for child in start_node.trust_relationships:
        search_trust_tree(child, target_role, results)

class TestTrustTree(unittest.TestCase): 
    def setUp(self): 
        self.dev = ARN('arn:aws:iam::123456789012:role/developers') 
        self.app = ARN('arn:aws:iam::123456789012:role/app') 
        jenkins = ARN('arn:aws:iam::123456789012:role/jenkins')
        self.jenkins = Node(jenkins.arn, jenkins.name)
        self.incident = ARN('arn:aws:iam::123456789012:role/incident')
        jenkins_controller = ARN('arn:aws:iam::123456789012:role/jenkins-controller')
        self.jenkins_controller = Node(jenkins_controller.arn, jenkins_controller.name)
        test = ARN('arn:aws:iam::123456789012:role/tests') 
        self.test = Node(test.arn, test.name)

        self.test_params = {
            'resource': 'arn:aws:dynamodb:us-west-2:123456789012:table/test-table',
            'service': 'dynamodb',
            'identity': self.dev,
            'action': 'dynamodb:PutItem',
            'aws_profiles': {},
            'role_assumption_only': True,
        }

        self.assume_role_policies = [
            {
                'arn': self.jenkins.arn, 
                'relationships': {
                    'Statement': [{
                        'Action': 'sts:AssumeRole',
                        'Effect': 'Allow',
                        'Principal': {
                            'AWS': [
                                self.dev.arn,
                                'arn:aws:iam::123456789012:role/jenkins-admin',
                            ]
                        }
                    }]
                }
            },
            {
                'arn': self.incident.arn,
                'relationships': {
                    'Statement': [{
                        'Action': 'sts:AssumeRole',
                        'Effect': 'Allow',
                        'Principal': {
                            'AWS': self.dev.arn
                        }
                    }]
                }
            },
            {
                'arn': self.jenkins_controller.arn,
                'relationships': {
                    'Statement': [{
                        'Action': 'sts:AssumeRole',
                        'Effect': 'Allow',
                        'Principal': {
                            'AWS': self.jenkins.arn,
                        }
                    }]
                }
            },
            {
                'arn': self.test.arn, 
                'relationships': {
                    'Statement': [{
                        'Action': 'sts:AssumeRole',
                        'Effect': 'Allow',
                        'Principal': {
                            'AWS': [
                                self.jenkins_controller.arn,
                                self.app.arn,
                            ]
                        }
                    }]
                }
            },
            {
                'arn': self.app.arn,
                'relationships': {
                    'Statement': [{
                        'Action': 'sts:AssumeRole',
                        'Effect': 'Allow',
                        'Principal': {
                            'AWS': self.dev.arn,
                        }
                    }]
                }
            },
        ]

    def test_trust_tree(self): 
        trusted_roles = [
            self.jenkins,
            self.incident,
            self.app,
        ]

        evaluator = IAMPolicyEvaluator(self.test_params)
        evaluator.trust_tree = Node(evaluator.arn, evaluator.identity.name)

        tree = RoleAssumptionTree()
        tree.build(trusted_roles, self.assume_role_policies, evaluator.trust_tree)

        examined_role = evaluator.arn
        root = evaluator.trust_tree

        self.assertEqual(root.arn, examined_role)
        self.assertTrue(root.is_root_node)
 
        # examine the first level of trust relationships
        trusted_roles = [node.arn for node in root.trust_relationships]
        assert self.jenkins.arn in trusted_roles
        assert self.incident.arn in trusted_roles

        # examine the branches
        # incident branch - 0 layers
        incident_relationships = {}
        search_trust_tree(root, self.incident.arn, incident_relationships)
        self.assertEqual(len(incident_relationships[self.incident.arn].keys()), 0)

        # app branch - 1 layer deep 
        app_relationships = {}
        search_trust_tree(root, self.app.arn, app_relationships)
        assert self.test.arn in app_relationships[self.app.arn].keys()

        # jenkins branch - 2 layers deep
        jenkins_relationships = {}
        search_trust_tree(root, self.jenkins.arn, jenkins_relationships)
        assert self.jenkins_controller.arn in jenkins_relationships[self.jenkins.arn].keys()
        assert self.test.arn in jenkins_relationships[self.jenkins.arn][self.jenkins_controller.arn].keys()

    def test_get_trust_tree(self): 
        trusted_roles = [
            self.jenkins,
            self.incident,
            self.app,
        ]

        evaluator = IAMPolicyEvaluator(self.test_params)
        evaluator.trust_tree = Node(evaluator.arn, evaluator.identity.name)

        tree = RoleAssumptionTree()
        tree.build(trusted_roles, self.assume_role_policies, evaluator.trust_tree)

        examined_role = evaluator.arn
        root = evaluator.trust_tree
        
        results = {}
        tree.get(root, results)
       
        first_branch = list(results[self.dev.arn].keys())
        expected_first_branch = [self.app.arn, self.incident.arn, self.jenkins.arn]
        first_branch.sort()

        self.assertListEqual(first_branch, expected_first_branch)

        second_branch = list(results[self.dev.arn][self.jenkins.arn].keys())
        expected_second_branch = [self.jenkins_controller.arn]

        self.assertListEqual(second_branch, expected_second_branch)

        third_branch = list(results[self.dev.arn][self.jenkins.arn][self.jenkins_controller.arn].keys())
        expected_third_branch = [self.test.arn]

        self.assertListEqual(third_branch, expected_third_branch)

