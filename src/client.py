import boto3
import json
import os
import yaml

import helpers

from policyuniverse.arn import ARN
from policyuniverse.policy import Policy

class IAMPolicyEvaluator: 
    def __init__(self): 
        self.session = boto3.Session(profile_name=os.environ['AWS_PROFILE'])

        self.iam_client = self.session.client('iam')

        params = helpers.get_input(self.session)
   
        # TODO allow selecting more than one action
        self.action = params['action']
        self.identity = params['identity']
        self.resource = params['resource']
        self.service_client = params['client']
        self.service = params['service']
        self.aws_profiles = params['aws_profiles']

        self.arn = self.identity.arn
        self.account_id = self.identity.account_number

        self.trust_tree = {}

        self.role_assumption_only = params['role_assumption_only']


    def get_resource_policies(self):
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

    # get all the roles that we're allowed to assume
    def get_trust_relationships(self, role_name, assume_role_policies):
        #paginator = self.iam_client.get_paginator('get_account_authorization_details')
        #query = paginator.paginate(Filter=['Role'])
        #results = query.search('RoleDetailList[].{arn: Arn, relationships: AssumeRolePolicyDocument}')
        trusted_roles = []

        for item in assume_role_policies: 
            statement = item['relationships']['Statement']

            for policy in statement: 
                principal = policy['Principal'].get('AWS')

                if not principal: 
                    continue
                # normalize format of policies
                if type(principal) != list: 
                    principal = [principal]

                for entity in principal:
                    entity_arn = ARN(entity)
                    if entity_arn.name == role_name: 
                        trusted_roles.append(ARN(item['arn']))

        return trusted_roles 

            
    '''
    takes an array of ARN objects as input
    output: 
    {
        '<role-arn>': [policies]
    }
    '''
    def evaluate_trusted_role_policies(self, trusted_roles): 
        decision = []
        for arn in trusted_roles: 
            role_account_id = arn.account_number
            iam_client = self.iam_client

            if role_account_id != self.account_id: 
                session = boto3.Session(profile_name=self.aws_profiles[role_account_id])
                iam_client = session.client('iam')

            decision.append(self.get_identity_policies(arn.arn, self.action, iam_client))

        return decision

    
    def get_identity_policies(self, caller_arn, target_action, iam_client):
        print(f"\nGetting identity policies for {caller_arn}...")
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
    
        # collect the relevant allow & deny policies 
        allow_policies = []
        deny_policies = []
        for arn in policies['managed']: 
            paginator = iam_client.get_paginator('list_policy_versions')
            query = paginator.paginate(PolicyArn=arn)
            results = query.search('Versions[?IsDefaultVersion == `true`].VersionId')
    
            for page in results:
                policy = iam_client.get_policy_version(
                    PolicyArn=arn,
                    VersionId=page
                )
                document = policy.get('PolicyVersion', {}).get('Document', {})
                decisions = self.evaluate_policy(document, target_action, self.resource.arn, caller_arn, iam_client)
    
                for decision in decisions: 
                    match decision.get('decision'):
                        case 'explicitDeny':
                            deny_policies.append(arn)
                            break 
                        case 'allowed':
                            allow_policies.append(arn)
    
        for name in policies['inline']:
            role = caller_arn.split(':')[5].split('/')[1] 
            policy = iam_client.get_role_policy(
                PolicyName=name,
                RoleName=role,
            )
            document = policy.get('PolicyDocument')
            decisions = self.evaluate_policy(document, target_action, self.resource.arn, caller_arn, iam_client)
    
            for decision in decisions: 
                match decision:
                    case 'explicitDeny':
                        deny_policies.append(arn)
                        break 
                    case 'allowed':
                        allow_policies.append(arn)
    
        if deny_policies:
            results = '\n'.join(deny_policies)
            return f'{target_action} on {self.resource.arn} is DENIED by these policies: \n\t{results}'
        elif allow_policies: 
            results = '\n'.join(allow_policies)
            return f'✅ {target_action} on {self.resource.arn} is ALLOWED by these policies: \n\t{results}'
        elif not deny_policies and not allow_policies: 
            return f'{target_action} on {self.resource.arn} is implicitly DENIED--please add IAM policies to allow access'
    
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
        print(f'\nChecking if {self.identity.name} has permissions to `{self.action}` on resource {self.resource.arn}...')
             
        #resource_policies = self.get_resource_policies()
        #resource_decision = self.evaluate_resource_policy(resource_policies)

        # get all roles containing trust relationships in the same account
        #files = helpers.get_iam_role_files(self.iam_dirs)
        assume_role_policies = self.get_assume_role_policies()
        trusted_roles = self.get_trust_relationships(self.identity.name, assume_role_policies)
        print(f'\n{self.identity.arn} is allowed to assume these roles: {[arn.arn for arn in trusted_roles]}')

        if self.role_assumption_only: 
            return

        trusted_roles_decision = self.evaluate_trusted_role_policies(trusted_roles)
        print('\n'.join(trusted_roles_decision))
    
        #identity_policies = {}
        #iam_resource = self.identity.name.split('/')[0]
        #match iam_resource:
        #    case 'role':
        #        identity_policies = self.get_identity_policies(self.arn, self.action, self.iam_client) 
        #        print(identity_policies)
        #    # case 'assumed-role':
        ##    case 'user':
        ##        identity_policies = iam_client.get_user_policies()
        ##    case 'group':
        ##        identity_policies = iam_client.list_group_policies()
        ##    case 'root': 
        ##        return
        ##    case _:
        ##        return


if __name__ == '__main__':
    evaluator = IAMPolicyEvaluator()
    evaluator.main()

