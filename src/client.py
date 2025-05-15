import boto3
import json
import os
import yaml

import src.helpers as helpers 
from src.tree import RoleAssumptionTree, Node

from policyuniverse.arn import ARN
from policyuniverse.policy import Policy

class IAMPolicyEvaluator: 
    def __init__(self, params): 
        self.params = params 

        # TODO allow selecting more than one action
        self.action = params['action']
        self.identity = params['identity']
        self.resource = params['resource']
        self.service = params['service']
        self.aws_profiles = params['aws_profiles']

        self.arn = self.identity.arn
        self.account_id = self.identity.account_number

        # collect output of policy evaluation 
        self.allow_policies = {}
        self.deny_policies = {}

        self.role_assumption_only = params['role_assumption_only']


    def get_session(self, role_arn):
        role_account_id = role_arn.account_number

        return boto3.Session(profile_name=self.aws_profiles[role_account_id])


    def get_resource_policies(self):
        if self.service not in ['s3', 'iam']: 
            self.service_client = self.session.client(self.service, region_name=self.resource.region)
        else: 
            self.service_client = self.session.client(self.service)

        match self.service: 
            case 's3': 
                bucket = self.resource.name.split('/')[0]
                print(f"\nGetting resource policies for {bucket}...")
                query = self.service_client.get_bucket_policy(
                    Bucket=bucket,
                )
                return json.loads(query.get('Policy'))
            case _:
                print(f"Getting resource policy for {self.service} isn't supported yet")
                return 

    def get_assume_role_policies(self): 
        paginator = self.iam_client.get_paginator('get_account_authorization_details')
        query = paginator.paginate(Filter=['Role'])

        return query.search('RoleDetailList[].{arn: Arn, relationships: AssumeRolePolicyDocument}')


    def get_identity_policy_arns(self, caller_arn, iam_client): 
        query = iam_client.list_policies_granting_service_access(
            Arn=caller_arn,
            ServiceNamespaces=[self.service],
        )
        results = query.get('PoliciesGrantingServiceAccess')
    
        policies = {
            'inline': [],
            'managed': [],
        }
    
        for data in results: 
            policies['managed'] = [policy.get('PolicyArn') for policy in data.get('Policies') if policy.get('PolicyType') == 'MANAGED']
            policies ['inline'] = [policy.get('PolicyName') for policy in data.get('Policies') if policy.get('PolicyType') == 'INLINE']

        return policies

            
    '''
    takes an array of ARN objects as input
    output: 
    {
        '<role-arn>': [policies]
    }
    '''
    def evaluate_trusted_role_policies(self, trusted_roles): 
        for arn in trusted_roles: 
            role_account_id = arn.account_number
            iam_client = self.iam_client

            session = self.get_session(arn)
            iam_client = session.client('iam')

            policy_arns = self.get_identity_policy_arns(arn.arn, iam_client)
            self.get_identity_policies(arn.arn, policy_arns, iam_client)

    
    def get_identity_policies(self, caller_arn, policy_arns, iam_client):

        for arn in policy_arns['managed']: 
            paginator = iam_client.get_paginator('list_policy_versions')
            query = paginator.paginate(PolicyArn=arn)
            results = query.search('Versions[?IsDefaultVersion == `true`].VersionId')
    
            for page in results:
                policy = iam_client.get_policy_version(
                    PolicyArn=arn,
                    VersionId=page
                )
                document = policy.get('PolicyVersion', {}).get('Document', {})
                decisions = self.evaluate_policy(document, self.action, self.resource.arn, caller_arn, iam_client)
    
                for decision in decisions: 
                    match decision.get('decision'):
                        case 'explicitDeny':
                            if not self.deny_policies.get(caller_arn): 
                                self.deny_policies[caller_arn] = []

                            self.deny_policies[caller_arn].append(arn)
                            break 
                        case 'allowed':
                            if not self.allow_policies.get(caller_arn): 
                                self.allow_policies[caller_arn] = []

                            self.allow_policies[caller_arn].append(arn)
    
        for name in policy_arns['inline']:
            role = caller_arn.split(':')[5].split('/')[1] 
            policy = iam_client.get_role_policy(
                PolicyName=name,
                RoleName=role,
            )
            document = policy.get('PolicyDocument')

            decisions = self.evaluate_policy(document, self.action, self.resource.arn, caller_arn, iam_client)
    
            for decision in decisions: 
                match decision.get('decision'):
                    case 'explicitDeny':
                        if not self.deny_policies.get(caller_arn): 
                            self.deny_policies[caller_arn] = []
                        self.deny_policies[caller_arn].append(name)
                        break 
                    case 'allowed':
                        if not self.allow_policies.get(caller_arn): 
                            self.allow_policies[caller_arn] = []

                        self.allow_policies[caller_arn].append(name)

    
    
    def evaluate_policy(self, policies, action, resource_arn, iam_arn, iam_client):
        paginator = iam_client.get_paginator('simulate_principal_policy')
    
        query = paginator.paginate(
            # TODO make this support wildcards 
            ActionNames=[action],
            PolicyInputList=[json.dumps(policies)],
            PolicySourceArn=iam_arn,
            # only supports testing resource base policies for IAM users
            # https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html
            ResourceArns=[resource_arn],
        )
    
        return  query.search('EvaluationResults[].{ decision: EvalDecision, resource: ResourceSpecificResults }')
    
    # TODO get this to work
    def evaluate_resource_policy(self, resource_policies):
        policies = Policy(resource_policies)

        for data in policies.statements:
            statement = data.statement
            conditions = statement.get('Condition')
            resources = data.resources
            not_resources = statement.get('NotResource')
            not_actions = statement.get('NotAction')
            
            # workaround as resource policies aren't supported
            statement.pop('Principal')
            document = {'Version': '2012-10-17', 'Statement': statement}
            context_keys = self.iam_client.get_context_keys_for_custom_policy(PolicyInputList=[json.dumps(document)])

            context_entries = []
            for key in conditions.keys(): 
                for key_name, value in conditions[key].items():

                    value_type = 'string'
                    match key_name: 
                        case 'aws:SourceIp': 
                            value_type = 'ipList'
                        case 'aws:userId': 
                            if type(value) != list:
                                value = [value]
                        case 'aws:MultiFactorAuthAge': 
                            value_type = 'boolean'
                            value = (value,)
                        case 'aws:PrincipalType' | 'aws:PrincipalOrgID': 
                            value = [value]

                    if type(value) == list:  
                        value_type = 'stringList'
                    
                    context_entries.append({
                        'ContextKeyName': key_name, 
                        'ContextKeyValues': value,
                        'ContextKeyType': value_type 
                    }) 

            simulate = self.iam_client.simulate_custom_policy(
                PolicyInputList=[json.dumps(document)],
                ActionNames=[self.action],
                ResourceArns=[self.resource.arn],
                CallerArn=self.arn,
                ContextEntries=context_entries
            )

            print(simulate.get('EvaluationResults'))


            #if data.effect == 'Deny':
            #    # check if resource is exempt from Deny statement
            #    if not_resources and resource in not_resources: 
            #        for key in conditions.keys(): 
            #            match key: 
            #                case 'StringEquals':
            #                    for type, value in conditions[key].items():
            #                        print(type, value)
            #                case 'StringNotEquals': 
            #                    print('todo')
            #                #case 'StringLike': 
            #                #case 'StringNotLike': 
            #                #case 'NotIpAddress': 
            #                #case 'Null': 

            #actions = data.actions_expanded
    
        #    if action in actions and identity in data.principals: 
        #        print(f'{identity} is allowed to {action} on {resource}')
        #    else: 
        #        print(f'{identity} is not allowed to {action} due to lack of resource policy')
    
    
    def main(self):
        self.session = self.get_session(self.identity)
        self.iam_client = self.session.client('iam')
   
        print(f'\nChecking if {self.identity.name} has permissions to `{self.action}` on resource {self.resource.arn}...')
             
        #resource_policies = self.get_resource_policies()
        #resource_decision = self.evaluate_resource_policy(resource_policies)

        # get all assume role policies in the account
        trust_policies = self.get_assume_role_policies()

        self.trust_tree = Node(self.arn, self.identity.name)
        tree = RoleAssumptionTree()
        trusted_roles = tree.get_trust_relationships(self.identity, trust_policies)
        tree.build(trusted_roles, trust_policies, self.trust_tree)


        role_tree = {}
        tree.get(self.trust_tree, role_tree)
        print(f'🌳 Role assumption tree for {self.arn}')
        print(role_tree[self.arn]) # TODO format this nicely

        trusted_roles_decision = self.evaluate_trusted_role_policies(trusted_roles)

        if len(self.deny_policies.keys()) > 0:
            print(f'\n{self.action} on {self.resource.arn} is DENIED by these policies:')
            for role, policy in self.deny_policies.items(): 
                print(f'\t{role}: {policy}')

        if len(self.allow_policies.keys()) > 0:
            print(f'\n✅ {self.action} on {self.resource.arn} is ALLOWED by these policies:')
            for role, policy in self.allow_policies.items(): 
                print(f'\t{role}: {policy}')

        if not self.deny_policies and not self.allow_policies: 
            print(f'\n{self.action} on {self.resource.arn} is implicitly DENIED--please add IAM policies to allow access')

        if self.role_assumption_only: 
            return


    
        identity_policies = {}
        iam_resource = self.identity.name.split('/')[0]
        match iam_resource:
            case 'role':
                policy_arns = self.get_identity_policy_arns(self.arn, self.iam_client)
                identity_policies = self.get_identity_policies(self.arn, policy_arns, self.iam_client) 
                print(identity_policies)
        ##    case 'user':
        ##        identity_policies = iam_client.get_user_policies()
        ##    case 'group':
        ##        identity_policies = iam_client.list_group_policies()
        ##    case 'root': 
        ##        return
        ##    case _:
        ##        return


if __name__ == '__main__':
    params = helpers.get_input()
    evaluator = IAMPolicyEvaluator(params)
    evaluator.main()

