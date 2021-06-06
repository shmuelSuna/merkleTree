import sys, hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


class MerkleTreeNode:
    def __init__(self, number_leaf=-1, hashed_value=0, parent=None, left=None, right=None, is_leaf=False):
        self.number_leaf = number_leaf
        self.hashed_value = hashed_value
        self.parent = parent
        self.left = left
        self.right = right
        self.is_leaf = is_leaf

    def get_sibling(self):
        # if there is no sibling
        if self.parent.left is None or self.parent.right is None:
            return None

        if self.parent.left.hashed_value == self.hashed_value:
            return self.parent.right, '1' # 1 because the node is the left one

        return self.parent.left, '0' # 0 because the node is the right one


class MerkleTree:
    def __init__(self, root=None):
        self.root = root
        self.leaf_counter = 0
        self.all_nodes = []
        self.leafs = []

    def activate_correct_function(self, list):
        choice = list[0]
        if int(choice) == 1:
            self.add_leaf(list[1:])
        elif int(choice) == 2:
            print(self.root.hashed_value)  # TODO: check if hex is needed?
        elif int(choice) == 3:
            leaf_num = int(list[1])
            # self.create_proof_of_inclusion(leaf_num)
        elif int(choice) == 4:
            self.check_proof_of_inclusion(list[1:])

    def print_root(self):
        if self.root:
            print(self.root.hashed_value)

    def add_leaf(self, list):
        data = list.encode('utf-8')
        h = hashlib.sha256(data)  # TODO: check if h needs to be same h during the whole program

        # hash the data of new leaf
        hased_data = h.hexdigest()
        leaf = MerkleTreeNode(self.leaf_counter, hased_data, is_leaf=True)
        # updates
        self.all_nodes.append(leaf)
        self.leafs.append(leaf)

        if int(self.leaf_counter) == 0:
            # update tree root
            self.root = leaf
        elif int(self.leaf_counter) == 1:
            # concatenating hashes
            concatenated_hashes_str = str(self.root.hashed_value) + str(hased_data)
            h2 = hashlib.sha256(concatenated_hashes_str.encode())
            concatenated_hashes = h2.hexdigest()
            new_root = MerkleTreeNode(-1, concatenated_hashes, None, left=self.root, right=leaf, is_leaf=False)
            leaf.parent = new_root
            self.root.parent = new_root
            # updates
            self.root = new_root
            self.all_nodes.append(new_root)

        # check if number of leafs is power of 2
        elif (int(self.leaf_counter) & (int(self.leaf_counter) - 1) == 0) and int(self.leaf_counter) != 0:
            # concatenating hashes
            concatenated_hashes_str = str(self.root.hashed_value) + str(hased_data)
            h3 = hashlib.sha256(concatenated_hashes_str.encode())
            concatenated_hashes = h3.hexdigest()
            new_root = MerkleTreeNode(-1, concatenated_hashes, None, left=self.root, right=leaf, is_leaf=False)
            leaf.parent = new_root
            self.root.parent = new_root
            # updates
            self.root = new_root
            self.all_nodes.append(new_root)
        # check if number of leafs is even
        elif (int(self.leaf_counter) & 1) == 0:
            # find parent of most right leaf. Maybe use list to find last leaf?
            temp = self.root
            while not temp.right.is_leaf:
                temp = temp.right
            temps_parent = temp.parent
            # concatenating hashes
            concatenated_hashes_str = str(temp.hashed_value) + str(hased_data)
            h4 = hashlib.sha256(concatenated_hashes_str.encode())
            concatenated_hashes = h4.hexdigest()

            new_interior_node = MerkleTreeNode(-1, concatenated_hashes, None, left=temp, right=leaf,
                                               parent=temps_parent, is_leaf=False)
            # updates
            temps_parent.right = new_interior_node
            temp.parent = new_interior_node
            leaf.parent = new_interior_node
            self.all_nodes.append(new_interior_node)
        # number of leafs is odd and not 1
        else:
            # find most right leaf
            temp = self.root
            while not temp.is_leaf:
                temp = temp.right
            temps_parent = temp.parent
            # concatenating hashes
            concatenated_hashes_str = str(temp.hashed_value) + str(hased_data)
            h5 = hashlib.sha256(concatenated_hashes_str.encode())
            concatenated_hashes = h5.hexdigest()

            new_interior_node = MerkleTreeNode(-1, concatenated_hashes, None, left=temp, right=leaf,
                                               parent=temps_parent, is_leaf=False)
            # updates
            temps_parent.right = new_interior_node
            temp.parent = new_interior_node
            leaf.parent = new_interior_node
            self.all_nodes.append(new_interior_node)

        self.leaf_counter = self.leaf_counter + 1

    def create_proof_of_inclusion(self, leaf_num):
        # find the wanted leaf
        leaf = None
        for l in self.leafs:
            if int(leaf_num) == l.number_leaf:
                leaf = l
                break

        proof = []
        print(self.root.hashed_value, end=" ")
        while leaf != self.root:
            sibling, right_or_left = leaf.get_sibling()
            if sibling is None:
                # todo implement
                pass
            else:
                proof.append(right_or_left + sibling.hashed_value)
                print(right_or_left + sibling.hashed_value, end=" ")
                leaf = leaf.parent

        return proof

    def check_proof_of_inclusion(self, list):
        leaf_before_hash = list[0]
        roots_hash = list[1]
        list = list[2:]
        list_len = len(list)

        h = hashlib.sha256(str(leaf_before_hash).encode('utf-8'))  # TODO: check if h needs to be same h during the whole program

        # hash the data of leaf
        hashed_leaf_value = h.hexdigest()

        for i in range (0,list_len):

            if list[i][0] == str(1):
                # concatenating hashes
                concatenated_hashes_str = str(hashed_leaf_value) + str(list[i][1:])
            else :
                # concatenating hashes
                concatenated_hashes_str = str(list[i][1:]) + str(hashed_leaf_value)

            h5 = hashlib.sha256(concatenated_hashes_str.encode('utf-8'))
            concatenated_hashes = h5.hexdigest()
            hashed_leaf_value = concatenated_hashes

        if hashed_leaf_value == roots_hash:
            return True
        else:
            return False


def get_input_from_user():
    print(sys.argv)
    print(sys.argv[1])
    # info_input = sys.argv[1].replace('\\n', '\n').split(sep='\n')
    # print(info_input)

    # choice = sys.argv[1]
    n = len(sys.argv)
    s = ""
    for i in range(1, n):
        s += sys.argv[i]
    input_list = s.split(sep='\\n')
    # input_list.pop()
    return input_list


def generate_RSA_keys():
    # Create private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Create public key
    public_key = private_key.public_key()
    # Convert private key to printing format
    private_key_print = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")
    # Convert public key to printing format
    public_key_print = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    print(private_key_print)
    print(public_key_print)


if __name__ == '__main__':
    tree = MerkleTree()
    while True:
        user_input = input()
        command = user_input.split(" ", 1)
        if command[0] == '1':
            tree.add_leaf(command[1])
        elif command[0] == '2':
            tree.print_root()
        elif command[0] == '3':
            tree.create_proof_of_inclusion(command[1])
        elif command[0] == '4':
            tree.check_proof_of_inclusion(command[1])
        elif command[0] == '5':
            generate_RSA_keys()
        elif command[0] == '6':
            pass # todo implement
        elif command[0] == '7':
            pass # todo implement
        elif command[0] == '8':
            pass # todo implement
        elif command[0] == '9':
            pass # todo implement
        elif command[0] == '10':
            pass # todo implement
        elif command[0] == '11':
            pass # todo implement
        else:
            print("\n")

    # tree = MerkleTree()
    # list_from_info_input = get_input_from_user()
    # list_len = len(list_from_info_input)
    # for i in range(0, list_len):
    #     tree.activate_correct_function(list_from_info_input[i])
