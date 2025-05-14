import argparse
import os
import shutil
import sys
import yaml

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

def get_input(session, args=sys.argv):
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-c",
        "--config", 
        default="config.yaml",
        help="Path to config file. Default is %(default)s",
    )

    parser.add_argument(
        "--skip-tf-repo",
        action="store_true",
        help="Skip cloning terraform repo (useful if the repo is already clone to the tmp path)"
    )

    #parser.add_argument(
    #    "--role-assumption-only",
    #    action="store_true",
    #    help="Skip analyzing permissions on resources, just return role assumption info for the given role"
    #)

    params = parser.parse_args(args[1:])

    with open(params.config, 'r') as config_file: 
        config = yaml.safe_load(config_file)

        role = validate_arn(config['role_arn'])
        resource = validate_arn(config['resource']['arn'])
        service = resource.tech

        if service not in ['s3', 'iam']: 
            client = session.client(service, region_name=resource.region)
        else: 
            client = session.client(service)
        actions = ('\n').join(client.meta.service_model.operation_names)
        #input(f'\n➡️ A list of available actions for your chosen AWS resource (`{service}`) has been retrieved. Press \033[1m⏎ Enter\033[0m to see the list')
        #print('\n', actions)
        #action = input("\nWhat action would you like to perform on the AWS resource? (default: \'*\')\n") or '*'
        action = '*'
        
        params = {
            'resource': resource,
            'client': client, 
            'repo': config['tf_repo']['url'],
            'iam_dirs': config['tf_repo']['iam_directories'],
            'service': service, 
            'identity': role,
            'action': f'{service}:{action}',
            'aws_profiles': config['aws_profiles'],
            'skip_tf': params.skip_tf_repo,
        }

        return params

def get_tf_repo(repo_url, skip=False):
    if skip: 
        return
    
    print('⬇ cloning terraform repo...')
    if os.path.exists(TMP_PATH):
        # deletes the tmp dir if it exists
        shutil.rmtree(TMP_PATH)

    Repo.clone_from(repo_url, TMP_PATH, branch='main')

def get_iam_role_files(iam_role_dirs): 
    iam_role_files = []

    iam_role_paths = [f'{TMP_PATH}/{dir}' for dir in iam_role_dirs]
    
    # walk thru all *.yaml files
    for path in iam_role_paths: 
        for root, dirs, files, in os.walk(path):
            for file in files:
                if file.endswith('.yaml'):
                    path = os.path.join(root, file)
                    iam_role_files.append(path)

    return iam_role_files
