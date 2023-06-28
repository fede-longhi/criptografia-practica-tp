"""
ESTRATEGIA 2

p = 3 * 2 ** 30 + 1

El statement a probar es:
2**(8**20) mod p = RESULT = 1610563584 # Statement

a_0 = 2
a_n+1 = a_n**2 mod p
a_60 = 2**(2**60) mod p = 1610563584

Longitud de la traza = 61

El orden del grupo |Fx| = 3 * 2 ** 30

El divisor más cercano a la longitud de la traza Y POTENCIA de 2 es: 2 ** 6 = 64

LDE = 21 * X > GRADO_RESTRICCIONES

Polinomial constraints

f(x) = 2 for x = g**0 -->
    p0(x) = f(x) - 2 / (x - g**0) = f(x) - 2 / (x - 1)

f(x) = RESULT for x = g**60 -->
    p1(x) = f(x) - RESULT / (x - g**60)

f(g*x) = f(x) ** 2 --> f(g*x) - f(x) ** 2 = 0 for x = g**i for 0 <= i <= 59 -->
    p2(x) = (f(g*x) - f(x) ** 2) / [(x - g**0)*(x - g**1)... (x - g**59)]

    Pero Mult(x - g**i) i=0..63 = (x ** 64 - 1) ==>

    [(x - g**0)*(x - g**1)... (x - g**59)] = (x ** 64 - 1) / prod[(x - g ** i) for i in [60, .., 63]]

    p2(x) = (f(g*x) - f(x) ** 2) / ((x ** 64 - 1) / prod[(x - g ** i) for i in [60, ..., 63]])
"""

from channel import Channel
from field import FieldElement
from polynomial import X, prod
from merkle_no_index import verify_decommitment
import utils

RESULT = FieldElement(2) ** (8 ** 20)

GROUP_SIZE = 64

TRACE_SIZE = 60

BLOWUP = 1

EVAL_SIZE = GROUP_SIZE * BLOWUP


def generate_trace():
    return utils.generate_trace([FieldElement(2)], lambda trace: trace[-1] ** 2, 60)


def make_constraint_polys(f, G, result=RESULT):

    g = G[1]

    p0 = (f - FieldElement(2)) / (X - FieldElement(1))
    p1 = (f - result) / (X - G[TRACE_SIZE])

    p2_numerator = f(g * X) - f ** 2

    # p2_denom_naif = prod([(X - g ** i) for i in range(20)])
    p2_denom = (X ** GROUP_SIZE - FieldElement(1)) / prod(
        [(X - g ** i) for i in range(TRACE_SIZE, GROUP_SIZE)]
    )
    # assert p2_denom == p2_denom_naif

    p2 = p2_numerator / p2_denom
    return p0, p1, p2


def calculate_cp(idx, fx, fgx, alphas, G, result):
    g = G[1]

    # Calculate x from idx (see make_eval_domain)
    w = FieldElement.generator()
    h = FieldElement.generator() ** (3 * 2 ** 30 // EVAL_SIZE)
    x = w * h ** idx

    p0 = (fx - FieldElement(2)) / (x - FieldElement(1))

    p1 = (fx - result) / (x - G[TRACE_SIZE])

    p2_numerator = fgx - fx ** 2
    p2_denom = (x ** GROUP_SIZE - FieldElement(1)) / prod(
        [(x - g ** i) for i in range(TRACE_SIZE, GROUP_SIZE)]
    )
    p2 = p2_numerator / p2_denom
    polys = [p0, p1, p2]
    return x, sum([alphas[i] * polys[i] for i in range(3)])


def make_proof(channel=None):
    if channel is None:
        channel = Channel()

    A = generate_trace()
    G = utils.generate_subgroup(GROUP_SIZE)
    f = utils.make_f_poly(A, G)
    eval_domain = utils.make_eval_domain(EVAL_SIZE)
    constraints = make_constraint_polys(f, G)

    return utils.make_proof(channel, f, constraints, G, eval_domain)


def add_query(*args):
    args = args + (BLOWUP, )
    return utils.add_query(*args)


def verifier(channel, result, number_of_queries):
    return utils.verifier(
        channel, result, number_of_queries,
        fri_size=6,
        n_constraints=3,
        GROUP_SIZE=GROUP_SIZE,
        EVAL_SIZE=EVAL_SIZE,
        BLOWUP=BLOWUP,
        calculate_cp=calculate_cp
    )
