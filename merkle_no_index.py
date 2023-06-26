###############################################################################
# Copyright 2019 StarkWare Industries Ltd.                                    #
#                                                                             #
# Licensed under the Apache License, Version 2.0 (the "License").             #
# You may not use this file except in compliance with the License.            #
# You may obtain a copy of the License at                                     #
#                                                                             #
# https://www.starkware.co/open-source-license/                               #
#                                                                             #
# Unless required by applicable law or agreed to in writing,                  #
# software distributed under the License is distributed on an "AS IS" BASIS,  #
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.    #
# See the License for the specific language governing permissions             #
# and limitations under the License.                                          #
###############################################################################


from hashlib import sha256
from math import log2, ceil
from io import BytesIO
from field import FieldElement


class MerkleTree(object):
    """
    A simple and naive implementation of an immutable Merkle tree.
    """

    def __init__(self, data):
        assert isinstance(data, list)

        if not data:
            raise RuntimeError("Can't create empty tree")
        # Mantengo self.hashes para poder mantener la interfaz que recibe ids
        self.hashes = [self.hash_data(x) for x in data]

        hashes = sorted(self.hashes)
        if len(hashes) == 1:
            self._root = hashes[0]
            self.destfile = None
            return

        self.destfile = destfile = BytesIO()
        count = len(hashes)

        destfile.write(count.to_bytes(32, "big"))

        while len(hashes) > 1:
            if len(hashes) % 2 == 1:  # Add 0 if odd
                hashes.append(b"\0" * 32)

            destfile.write(b"".join(hashes))

            new_hashes = [self.hash_pair(*hashes[i * 2:i * 2 + 2]) for i in range(len(hashes) // 2)]
            hashes = new_hashes
        destfile.write(hashes[0])
        self._root = hashes[0]

    @staticmethod
    def hash_data(x):
        leaf_data = str(x)
        return sha256(leaf_data.encode()).digest()

    @staticmethod
    def hash_pair(a, b):
        assert len(a) == 32
        assert len(b) == 32
        if a < b:
            return sha256(a + b).digest()
        else:
            return sha256(b + a).digest()

    @property
    def root(self):
        return self._root.hex()

    def get_authentication_path(self, leaf_id):
        data_hash = self.hashes[leaf_id]
        if len(self.hashes) == 1:
            return []

        proof = []
        merkle_file = self.destfile

        merkle_file.seek(0)
        leaf_count = int.from_bytes(merkle_file.read(32), "big")

        # Read leafs and find the node for this object
        leafs = merkle_file.read(leaf_count * 32)
        my_idx = -1
        while True:
            my_idx = leafs.find(data_hash, my_idx + 1)
            if my_idx < 0:
                raise RuntimeError(f"My hash key {data_hash.hex()} not found in the merkle tree")
            if my_idx % 32 == 0:
                my_idx = my_idx // 32
                break
            # else: si lo encontró en algo que no es múltiplo de 32 es casualidad

        # First proof is the sibling leaf
        other_idx = (my_idx + 1) if my_idx % 2 == 0 else (my_idx - 1)
        other_leaf = leafs[other_idx * 32:other_idx * 32 + 32]
        if other_leaf == b"":
            other_leaf = b"\0" * 32
        proof.append(other_leaf)

        # Start the process going up in the tree
        level_start = 32 + leaf_count * 32 + (32 if leaf_count % 2 == 1 else 0)
        level_count = ceil(leaf_count / 2)  # ceil makes odds equal to next even
        my_idx = my_idx // 2

        while level_count > 1:
            other_idx = (my_idx + 1) if my_idx % 2 == 0 else (my_idx - 1)
            merkle_file.seek(level_start + other_idx * 32, 0)
            proof.append(merkle_file.read(32))
            level_start += level_count * 32 + (32 if level_count % 2 == 1 else 0)
            level_count = ceil(level_count / 2)
            my_idx = my_idx // 2

        return [p.hex() for p in proof]


def verify_decommitment(leaf_data, decommitment, root):
    data_hash = MerkleTree.hash_data(leaf_data)

    computed_hash = data_hash
    for proof in [bytes.fromhex(x) for x in decommitment]:
        computed_hash = MerkleTree.hash_pair(computed_hash, proof)
    return computed_hash.hex() == root
