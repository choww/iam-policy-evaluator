from policyuniverse.arn import ARN

class RoleAssumptionTree:
    '''
    trusted_roles = list of roles the root node is allowed to assume
    trust_policies = all trust policies in the AWS account
    start_node = the role to which trust relationships should be associated with 
    '''
    def build(self, trusted_roles, trust_policies, start_node): 
        for role in trusted_roles: 
            node = Node(role.arn, role.name)
            node.parent = start_node 
            
            start_node.add_trust_relationship(node)

            child_trusted_roles = self.get_trust_relationships(node, trust_policies)
            self.build(child_trusted_roles, trust_policies, node)

    def search(self, start, target, searched=None):
        print('TODO')

    '''
    start_node = the node whose trust tree we want to get 
    returns a nested dict
    '''
    def get(self, start_node, results): 
        results[start_node.arn] = {}
        root = results[start_node.arn]
    
        for relationship in start_node.trust_relationships: 
            self.get(relationship, root)
    
    '''
    get all the roles that we're allowed to assume

    role_name = role we want to get trust relationships for 
    trust_policies = all trust policies in the AWS account
    returns a list of policyuniverse.ARN objects
    '''
    def get_trust_relationships(self, role, trust_policies):
        trusted_roles = []

        for item in trust_policies: 
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

                    if entity_arn.name == role.name and entity_arn.account_number == role.account_number: 
                        trusted_roles.append(ARN(item['arn']))

        return trusted_roles 


class Node:
    def __init__(self, arn, name): 
        self.arn = arn
        self.name = name

        self.trust_relationships = []

        self.parent = None # a Node object

    def add_trust_relationship(self, node): 
        self.trust_relationships.append(node)

    def is_root_node(self): 
        return self.parent == None
