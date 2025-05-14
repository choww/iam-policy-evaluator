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
