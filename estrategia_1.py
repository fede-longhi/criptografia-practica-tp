"""
ESTRATEGIA 1

p = 3 * 2 ** 30 + 1

El statement a probar es:
2**(8**20) mod p = RESULT = 1610563584 # Statement

a_0 = 2
a_n+1 = a_n**8 mod p
a_20 = 2**8**20 mod p = 1610563584

Longitud de la traza = 21

El orden del grupo |Fx| = 3 * 2 ** 30

El divisor más cercano a la longitud de la traza es: 3 * 2 ** 3 = 24

LDE = 21 * X > GRADO_RESTRICCIONES

Polinomial constraints

f(x) = 2 for x = g**0 -->
    p0(x) = f(x) - 2 / (x - g**0) = f(x) - 2 / (x - 1)

f(x) = RESULT for x = g**20 -->
    p1(x) = f(x) - RESULT / (x - g**20)

f(g*x) = f(x) ** 8 --> f(g*x) - f(x) ** 8 = 0 for x = g**i for 0 <= i <= 19 -->
    p2(x) = (f(g*x) - f(x) ** 8) / [(x - g**0)*(x - g**1)... (x - g**19)]

    Pero Mult(x - g**i) i=0..23 = (x ** 24 - 1) ==>

    [(x - g**0)*(x - g**1)... (x - g**20)] = (x ** 24 - 1) / prod[(x - g ** i) for i in [20, 21, 22, 23]]

    p2(x) = (f(g*x) - f(x) ** 8) / ((x ** 24 - 1) / prod[(x - g ** i) for i in [20, 21, 22, 23]])
"""

from channel import Channel
from field import FieldElement
from polynomial import interpolate_poly, X, prod
from merkle import MerkleTree
from utils import get_CP, FriCommit, decommit_fri

RESULT = FieldElement(2) ** (8 ** 20)


def generate_trace():
    a_0 = FieldElement(2)
    trace = [a_0]

    for i in range(20):
        trace.append(trace[-1] ** 8)

    return trace


def generate_subgroup(size):
    group_order = 3 * 2 ** 30
    assert (group_order / size) == (group_order // size), "El tamaño no es divisor del orden del grupo"
    g = FieldElement.generator() ** (group_order // size)
    return [g ** i for i in range(size)]


def make_eval_domain(size):
    group_order = 3 * 2 ** 30
    assert (group_order / size) == (group_order // size), "El tamaño no es divisor del orden del grupo"

    w = FieldElement.generator()
    h = FieldElement.generator() ** (group_order // size)
    H = [h ** i for i in range(size)]
    return [w * x for x in H]


def make_f_poly(A, G):
    """Devuelve in polinomio que interpola
    F(G[i]) = A[i] para i=0..len(A)
    """

    return interpolate_poly(G[:len(A)], A)


def make_constraint_polys(f, G):

    g = G[1]

    p0 = (f - FieldElement(2)) / (X - FieldElement(1))
    p1 = (f - RESULT) / (X - G[20])

    p2_numerator = f(g * X) - f ** 8

    p2_denom = prod([(X - g ** i) for i in range(20)])
    p2_denom_alternative = (X ** 24 - FieldElement(1)) / prod([(X - g ** i) for i in range(20, 24)])
    assert p2_denom == p2_denom_alternative

    p2 = p2_numerator / p2_denom_alternative
    return p0, p1, p2


def make_commitment_merkle(f, eval_domain):
    f_eval = [f(x) for x in eval_domain]
    # Commitments
    f_merkle = MerkleTree(f_eval)

    return f_eval, f_merkle


def make_CP_merkle(CP, eval_domain):
    CP_eval = [CP(x) for x in eval_domain]
    # Commitments
    CP_merkle = MerkleTree(CP_eval)

    return CP_eval, CP_merkle


def make_proof(channel=None):
    if channel is None:
        channel = Channel()

    A = generate_trace()
    G = generate_subgroup(24)
    f = make_f_poly(A, G)
    eval_domain = make_eval_domain(24 * 8)

    f_eval, f_merkle = make_commitment_merkle(f, eval_domain)

    channel.send(f_merkle.root)

    p0, p1, p2 = make_constraint_polys(f, G)

    CP = get_CP(channel, [p0, p1, p2])

    CP_eval, CP_merkle = make_CP_merkle(CP, eval_domain)

    channel.send(CP_merkle.root)

    # TODO: FRI
    fri_polys, fri_domains, fri_layers, fri_merkles = FriCommit(CP, eval_domain, CP_eval, CP_merkle, channel)
    
    return channel

make_proof()