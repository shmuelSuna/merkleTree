import sys,hashlib




class MerkleTreeNode:
    def __init__(self,number_leaf=-1,hased_value=0,parent=None,left=None,right=None,is_leaf=False):
        self.number_leaf = number_leaf
        self.hased_value = hased_value
        self.parent = parent
        self.left = left
        self.right = right
        self.is_leaf = is_leaf


class MerkleTree:
    def __init__(self,root=None):
        self.root = root
        self.leaf_counter = 0
        self.all_nodes = []
        self.leafs = []



    def activate_correct_function(self,list):
        choice = list[0]
        if int(choice) == 1:
            self.add_leaf(list[1:])
        elif int(choice) == 2:
            print(self.root.hased_value) #TODO: check if hex is needed?
        elif int(choice) == 3:
            k =[]
            #self.proof_of_inclusion(leaf_num)
        elif int(choice) == 4:
            self.check_proof_of_inclusion(list[1:])


    def add_leaf(self,list):
        data = list.encode('utf-8')
        h = hashlib.sha256(data) #TODO: check if h needs to be same h during the whole program

        #hash the data of new leaf
        hased_data = h.hexdigest()
        leaf = MerkleTreeNode(self.leaf_counter, hased_data,is_leaf=True)
        #updates
        self.all_nodes.append(leaf)
        self.leafs.append(leaf)

        if int(self.leaf_counter) == 0:
            #update tree root
            self.root = leaf
        elif int(self.leaf_counter) == 1:
            #concatenating hashes
            concatenated_hashes_str = str(self.root.hased_value) + str(hased_data)
            h2 = hashlib.sha256(concatenated_hashes_str.encode())
            concatenated_hashes = h2.hexdigest()
            new_root = MerkleTreeNode(-1,concatenated_hashes,None,left=self.root,right=leaf,is_leaf=False)
            leaf.parent = new_root
            self.root.parent = new_root
            #updates
            self.root = new_root
            self.all_nodes.append(new_root)

        #check if number of leafs is power of 2
        elif  (int(self.leaf_counter) & (int(self.leaf_counter)-1) == 0) and int(self.leaf_counter) != 0:
            #concatenating hashes
            concatenated_hashes_str = str(self.root.hased_value) + str(hased_data)
            h3 = hashlib.sha256(concatenated_hashes_str.encode())
            concatenated_hashes = h3.hexdigest()
            new_root = MerkleTreeNode(-1,concatenated_hashes,None,left=self.root,right=leaf,is_leaf=False)
            leaf.parent = new_root
            self.root.parent = new_root
            # updates
            self.root = new_root
            self.all_nodes.append(new_root)
        #check if number of leafs is even
        elif (int(self.leaf_counter) & 1) == 0:
            #find parent of most right leaf. Maybe use list to find last leaf?
            temp = self.root
            while not temp.right.is_leaf:
                temp = temp.right
            temps_parent = temp.parent
            #concatenating hashes
            concatenated_hashes_str = str(temp.hased_value) + str(hased_data)
            h4 = hashlib.sha256(concatenated_hashes_str.encode())
            concatenated_hashes = h4.hexdigest()


            new_interior_node = MerkleTreeNode(-1,concatenated_hashes,None,left=temp,right=leaf,parent=temps_parent,is_leaf=False)
            #updates
            temps_parent.right = new_interior_node
            temp.parent = new_interior_node
            leaf.parent = new_interior_node
            self.all_nodes.append(new_interior_node)
        #number of leafs is odd and not 1
        else:
            # find most right leaf
            temp = self.root
            while not temp.is_leaf:
                temp = temp.right
            temps_parent = temp.parent
            #concatenating hashes
            concatenated_hashes_str = str(temp.hased_value) + str(hased_data)
            h5 = hashlib.sha256(concatenated_hashes_str.encode())
            concatenated_hashes = h5.hexdigest()


            new_interior_node = MerkleTreeNode(-1,concatenated_hashes,None,left=temp,right=leaf,parent=temps_parent,is_leaf=False)
            # updates
            temps_parent.right = new_interior_node
            temp.parent = new_interior_node
            leaf.parent = new_interior_node
            self.all_nodes.append(new_interior_node)

        self.leaf_counter = self.leaf_counter + 1


    def proof_of_inclusion(self,leaf_num):
        #get neighbour node of leaf num
        for leaf in self.leafs:
            if leaf.number_leaf == leaf_num:
                pass


    def check_proof_of_inclusion(self,list):
        leaf_before_hash = list[0]
        roots_hash = list[1]
        list = list[2:]
        list_len = len(list)

        leaf_before_hash.encode('utf-8')
        h = hashlib.sha256(leaf_before_hash)  # TODO: check if h needs to be same h during the whole program

        # hash the data of leaf
        hashed_leaf_value = h.hexdigest()
        leaf_found = None
        #find the leaf
        for leaf in self.leafs:
            if leaf.hashed_value == hashed_leaf_value:
                leaf_found = leaf
                break

        if leaf_found is None:
            return False

        temp_node = leaf_found
        for i in range (0,list_len):
            parnet = temp_node.parent
            if parnet.left == temp_node: #TODO check this equation
                # concatenating hashes
                concatenated_hashes_str = str(temp_node.hased_value) + str(list[i])
            else :
                # concatenating hashes
                concatenated_hashes_str = str(list[i]) + str(temp_node.hased_value)

            h5 = hashlib.sha256(concatenated_hashes_str)
            concatenated_hashes = h5.hexdigest()
            if concatenated_hashes != parnet.hashed_value:
                return False
            else:
                temp_node = parnet

        if temp_node.hased_value == roots_hash:
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
    s =""
    for i in range(1,n):
        s+=sys.argv[i]
    input_list = s.split(sep='\\n')
    input_list.pop()
    return input_list

if __name__ == '__main__':
    # h = hashlib.sha256("b".encode())
    # print(h.hexdigest())
    # h2 = hashlib.sha256('c'.encode())
    # print(h2.hexdigest())

    tree = MerkleTree()
    list_from_info_input = get_input_from_user()
    list_len = len(list_from_info_input)
    for i in range(0,list_len):
        tree.activate_correct_function(list_from_info_input[i])
