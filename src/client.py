import boto3
import json
import os

import helpers

from policyuniverse.policy import Policy
from policyuniverse.statement import ConditionTuple, PrincipalTuple

def get_resource_policies(service, service_client, resource):
    match service: 
        case 's3': 
            bucket = resource.name.split('/')[0]
            print(f"\nGetting resource policies for {bucket}...")
            query = service_client.get_bucket_policy(
                Bucket=bucket,
            )
            return json.loads(query.get('Policy'))
        case _:
            print(f"Getting resource policy for {service} isn't supported yet")
            return 

def get_identity_policies(client, service, caller_arn, target_action, resource_arn):
    print(f"\nGetting identity policies for {caller_arn}...")
    # TODO handle pagination
    query = client.list_policies_granting_service_access(
        Arn=caller_arn,
        ServiceNamespaces=[service],
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
        paginator = client.get_paginator('list_policy_versions')
        query = paginator.paginate(PolicyArn=arn)
        results = query.search('Versions[?IsDefaultVersion == `true`].VersionId')

        for page in results:
            policy = client.get_policy_version(
                PolicyArn=arn,
                VersionId=page
            )
            document = policy.get('PolicyVersion', {}).get('Document', {})
            decisions = evaluate_policy(client, document, target_action, resource_arn, caller_arn)

            for decision in decisions: 
                match decision.get('decision'):
                    case 'explicitDeny':
                        deny_policies.append(arn)
                        break 
                    case 'allowed':
                        allow_policies.append(arn)

    for name in policies['inline']:
        role = caller_arn.split(':')[5].split('/')[1] 
        policy = client.get_role_policy(
            PolicyName=name,
            RoleName=role,
        )
        document = policy.get('PolicyDocument')
        decisions = evaluate_policy(client, document, target_action, resource_arn, caller_arn)

        for decision in decisions: 
            match decision:
                case 'explicitDeny':
                    deny_policies.append(arn)
                    break 
                case 'allowed':
                    allow_policies.append(arn)

    if deny_policies:
        results = '\n'.join(deny_policies)
        return f'{target_action} on {resource_arn} is DENIED by these policies: \n{results}'
    elif allow_policies: 
        results = '\n'.join(allow_policies)
        return f'{target_action} on {resource_arn} is ALLOWED by these policies: \n{results}'
    elif not deny_policies and not allow_policies: 
        return f'{target_action} on {resource_arn} is implicitly DENIED--please add IAM policies to allow access'

def evaluate_policy(client, policies, action, resource_arn, iam_arn):
    paginator = client.get_paginator('simulate_principal_policy')

    query = paginator.paginate(
        # TODO make this support wildcards 
        ActionNames=[action],
        PolicyInputList=[json.dumps(policies)],
        PolicySourceArn=iam_arn,
        # only supports testing resource base policies for IAM users
        # https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html
        ResourceArns=[resource_arn],
        #ResourcePolicy=resource_policies,
    )

    return  query.search('EvaluationResults[].{ decision: EvalDecision, resource: ResourceSpecificResults }')

def evaluate_resource_policy(resource_policies, action, resource, identity):
    # generate resource policy
    # compare with the provided policy
    # see if any of them are equal
    policies = Policy(resource_policies)
    for data in policies.statements:
        statement = data.statement
        conditions = statement.get('Condition')
        if conditions:
            print('conditions', conditions)
        print(data.effect)
        print(data.principals)
        print('actions', data.actions_expanded)
        print(statement, '\n')


def main():
    session = boto3.Session(profile_name=os.environ['AWS_PROFILE'])

    params = helpers.get_input(session)

    action = params['action']
    identity = params['identity']
    resource = params['resource']
    service_client = params['client']
    service = params['service']
    iam_resource = identity.name.split('/')[0]
    print(f'\nChecking if {identity.name} has permissions to `{action}` on resource {resource.arn}...')

    iam_client = session.client('iam')

    resource_policies = get_resource_policies(service, service_client, resource)
    resource_decision = evaluate_resource_policy(resource_policies, action, resource, identity)

    identity_policies = {}
    match iam_resource:
        case 'role':
            identity_policies = get_identity_policies(iam_client, service, identity.arn, action, resource.arn)
            print('\n', identity_policies)
        # case 'assumed-role':
    #    case 'user':
    #        identity_policies = iam_client.get_user_policies()
    #    case 'group':
    #        identity_policies = iam_client.list_group_policies()
    #    case 'root': 
    #        return
    #    case _:
    #        return


if __name__ == '__main__':
    main()

