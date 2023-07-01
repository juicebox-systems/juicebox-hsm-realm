import string
import random


class Branch:
    def __init__(self, prefix, hash):
        self.prefix = prefix
        self.hash = hash

    def __repr__(self):
        return str(self.prefix) + ":" + self.hash


branches = [
    Branch([0, 0, 0, 0, 0, 0, 0, 0], "c054fba26029cf03"),
    Branch([0, 0, 0, 0, 1, 0, 0, 0], "2a9967cd63409150"),
    Branch([0, 0, 0, 0, 1, 0, 1, 0], "52fb4742172f2888"),
    Branch([0, 0, 0, 0, 1, 1, 1, 1], "3178f5b8405a7339"),
    Branch([0, 0, 1, 1, 1, 0, 1, 1], "15c12d359027d23f"),
    Branch([1, 1], "79964b40a0422fec"),
]


def build_tree(branches, start):
    if len(branches) == 1:
        return branches[0]
    bit = start
    while True:
        zeros = [b for b in branches if b.prefix[bit] == 0]
        ones = [b for b in branches if b.prefix[bit] == 1]
        if len(zeros) > 0 and len(ones) > 0:
            left = build_tree(zeros, bit + 1)
            right = build_tree(ones, bit + 1)
            return join_nodes(left, right, bit)
        bit += 1


def join_nodes(a, b, d):
    res = Branch(a.prefix[:d], "".join(random.choices(string.digits, k=16)))
    print("joining:\n{}\n{} resulting in\n{}\n".format(a, b, res))
    return res


build_tree(branches, 0)
