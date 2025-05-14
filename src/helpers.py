import argparse
import sys
import yaml

from policyuniverse.arn import ARN


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

    #parser.add_argument(
    #    "--skip-tf-repo",
    #    action="store_true",
    #    help="Skip cloning terraform repo (useful if the repo is already clone to the tmp path)"
    #)

    parser.add_argument(
        "--role-assumption-only",
        action="store_true",
        help="Skip analyzing permissions on resources, just return role assumption info for the given role"
    )

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
            'service': service, 
            'identity': role,
            'action': f'{service}:{action}',
            'aws_profiles': config['aws_profiles'],
            'role_assumption_only': params.role_assumption_only,
        }

        return params
