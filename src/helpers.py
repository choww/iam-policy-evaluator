import os
import shutil
import sys 

from git import Repo
from policyuniverse.arn import ARN

TMP_PATH = '/tmp/terraform-code-iam-eval'

class InvalidARNException(Exception):
    #sys.tracebacklimit = 0 # omit error trace in error message
    pass

def validate_arn(input):
    arn = ARN(input)
    if arn.error: 
        raise InvalidARNException(f'`{input}` is an invalid AWS ARN')
   
    return arn

# TODO convert this to take YAML configs instead 
def get_input(session):
    # TODO add AWS profile to account mapping
    resource = input("What's the ARN of the AWS resource you would like to access?\n") or 'arn:aws:dynamodb:us-west-1:056083216413:table/gondola-active'
    resource_arn = validate_arn(resource) 
    identity = input("What's the ARN of the IAM identity you're using to access the resource?\n") or 'arn:aws:iam::528741615426:role/gondola'
    iam_arn = validate_arn(identity)
    # TODO add validation
    repo = input("What's the SSH URL of your Terraform repo?\n") or 'git@github.yelpcorp.com:misc/terraform-code.git'

    service = resource_arn.tech
    if service not in ['s3', 'iam']: 
        client = session.client(service, region_name='us-west-2')
    else: 
        client = session.client(service)
    actions = ('\n').join(client.meta.service_model.operation_names)
    print(f"\nHere is a list of available actions for your chosen AWS resource: \n{actions}")
    action = input("\nWhat action would you like to perform on the AWS resource? (default: \'*\')\n") or '*'

    
    params = {
        'resource': resource_arn,
        'client': client, 
        'repo': repo,
        'service': service, 
        'identity': iam_arn,
        'action': f'{service}:{action}',
    }

    return params

def get_tf_repo(repo_url):
    print('⬇ cloning terraform repo...')
    #if os.path.exists(TMP_PATH):
    #    # deletes the tmp dir if it exists
    #    shutil.rmtree(TMP_PATH)

    #Repo.clone_from(repo_url, TMP_PATH, branch='main')

def get_iam_role_files(): 
    iam_role_files = []
    # TODO make this configurable and to other environments 
    iam_roles_dir = f'{TMP_PATH}/projects/iam_roles/dev'
    
    # walk thru all <env>/roles/*.yaml files
    for root, dirs, files, in os.walk(iam_roles_dir):
        for file in files:
            if file.endswith('.yaml'):
                path = os.path.join(root, file)
                iam_role_files.append(path)

    return iam_role_files
