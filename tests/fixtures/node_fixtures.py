class NodeFixture:
    def __init__(self):
        self.node_data = {"id": "node1", "name": "Test Node", "status": "active"}

    def get_node_data(self):
        return self.node_data


def node_fixture():
    return NodeFixture()
