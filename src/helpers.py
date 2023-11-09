import sys 

from policyuniverse.arn import ARN

class InvalidARNException(Exception):
    #sys.tracebacklimit = 0 # omit error trace in error message
    pass

def validate_arn(input):
    arn = ARN(input)
    if arn.error: 
        raise InvalidARNException(f'`{input}` is an invalid AWS ARN')
   
    return arn


def get_input(session):
    resource = input("What's the ARN of the AWS resource you would like to access?\n") or 'arn:aws:s3:::yelp-scribe-logs-dev-us-west-2'
    resource_arn = validate_arn(resource)
    identity = input("What's the ARN of the IAM identity you're using to access the resource?\n") or 'arn:aws:iam::528741615426:role/security'
    iam_arn = validate_arn(identity)

    service = resource_arn.tech
    client = session.client(service)
    actions = ('\n').join(client.meta.service_model.operation_names)
    print(f"\nHere is a list of available actions for your chosen AWS resource: \n{actions}")
    action = input("\nWhat action would you like to perform on the AWS resource? (default: \'*\')\n") or '*'

    
    params = {
        'resource': resource_arn,
        'client': client, 
        'service': service, 
        'identity': iam_arn,
        'action': f'{service}:{action}',
    }

    return params

