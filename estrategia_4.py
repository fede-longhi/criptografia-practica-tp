"""
ESTRATEGIA 1

p = 3 * 2 ** 30 + 1

El statement a probar es:
2**(8**20) mod p = RESULT = 1610563584 # Statement

a_0 = 2
b_n = a_n**2
a_n+1 = b_n**4

b_9 = 2**8**20 mod p = 1610563584

Longitud de la traza = 10

El orden del grupo |Fx| = 3 * 2 ** 30

El divisor más cercano a la longitud de la traza Y POTENCIA de 2 es: 2 ** 4 = 16

LDE = 21 * X > GRADO_RESTRICCIONES

Polinomial constraints

a(gx) = b(x) ** 4
b(x) = a(x) ** 2

==>

a(gx) = b(x) ** 4 = (a(x)**2)**4 = a(x) ** 8
b(x) = a(x) ** 2 ==> b(gx) = a(gx) ** 2 = (b(x) ** 4) ** 2 = b(x) ** 8


f_a(x) = 2 for x = g**0 -->
    p0(x) = f(x) - 2 / (x - g**0) = f(x) - 2 / (x - 1)

f_a(x) = RESULT_A for x = g**9 -->
    p1(x) = f(x) - RESULT_A / (x - g**9)

f_a(g*x) = f_a(x) ** 8 --> f_a(g*x) - f_a(x) ** 8 = 0 for x = g**i for 0 <= i <= 8 -->
    p2(x) = (f_a(g*x) - f_a(x) ** 8) / [(x - g**0)*(x - g**1)... (x - g**8)]

f_b(x) = 4 for x = g**0 -->
    p0(x) = f_b(x) - 4 / (x - g**0) = f_b(x) - 4 / (x - 1)

f_b(x) = RESULT for x = g**9 -->
    p1(x) = f_b(x) - RESULT / (x - g**9)

f_b(g*x) = f_b(x) ** 8 --> f_b(g*x) - f_b(x) ** 8 = 0 for x = g**i for 0 <= i <= 8 -->
    p2(x) = (f_b(g*x) - f_b(x) ** 8) / [(x - g**0)*(x - g**1)... (x - g**8)]
"""

from channel import Channel
from field import FieldElement
from polynomial import X, prod
from merkle_no_index import verify_decommitment
import utils

RESULT = FieldElement(2) ** (8 ** 20)
RESULT_A = FieldElement(1610563585)  # lo defino acá por simplicidad, pero sale del cálculo de la traza

assert RESULT_A ** 2 == RESULT

GROUP_SIZE = 16

TRACE_SIZE = 9

BLOWUP = 4  # Porque 16 * 4 > 63 (grado de CP)

EVAL_SIZE = GROUP_SIZE * BLOWUP


def generate_trace():
    a_0 = FieldElement(2)
    b_0 = a_0 ** 2
    trace_a, trace_b = [a_0], [b_0]

    for i in range(9):
        a_n = trace_b[-1] ** 4
        b_n = a_n ** 2
        trace_a.append(a_n)
        trace_b.append(b_n)
    return trace_a, trace_b


def make_constraint_polys_a(f, G, result=RESULT_A):

    g = G[1]

    p0 = (f - FieldElement(2)) / (X - FieldElement(1))
    p1 = (f - result) / (X - G[TRACE_SIZE])

    p2_numerator = f(g * X) - f ** 8

    # p2_denom_naif = prod([(X - g ** i) for i in range(20)])
    p2_denom = (X ** GROUP_SIZE - FieldElement(1)) / prod(
        [(X - g ** i) for i in range(TRACE_SIZE, GROUP_SIZE)]
    )
    # assert p2_denom == p2_denom_naif

    p2 = p2_numerator / p2_denom
    return p0, p1, p2


def make_constraint_polys_b(f, G, result=RESULT):

    g = G[1]

    p0 = (f - FieldElement(4)) / (X - FieldElement(1))
    p1 = (f - result) / (X - G[TRACE_SIZE])

    p2_numerator = f(g * X) - f ** 8

    # p2_denom_naif = prod([(X - g ** i) for i in range(20)])
    p2_denom = (X ** GROUP_SIZE - FieldElement(1)) / prod(
        [(X - g ** i) for i in range(TRACE_SIZE, GROUP_SIZE)]
    )
    # assert p2_denom == p2_denom_naif

    p2 = p2_numerator / p2_denom
    return p0, p1, p2


def calculate_cp_a(idx, fx, fgx, alphas, G, result):
    g = G[1]

    # Calculate x from idx (see make_eval_domain)
    w = FieldElement.generator()
    h = FieldElement.generator() ** (3 * 2 ** 30 // EVAL_SIZE)
    x = w * h ** idx

    p0 = (fx - FieldElement(2)) / (x - FieldElement(1))

    p1 = (fx - result) / (x - G[TRACE_SIZE])

    p2_numerator = fgx - fx ** 8
    p2_denom = (x ** GROUP_SIZE - FieldElement(1)) / prod(
        [(x - g ** i) for i in range(TRACE_SIZE, GROUP_SIZE)]
    )
    p2 = p2_numerator / p2_denom
    polys = [p0, p1, p2]
    return x, sum([alphas[i] * polys[i] for i in range(3)])


def calculate_cp_b(idx, fx, fgx, alphas, G, result):
    g = G[1]

    # Calculate x from idx (see make_eval_domain)
    w = FieldElement.generator()
    h = FieldElement.generator() ** (3 * 2 ** 30 // EVAL_SIZE)
    x = w * h ** idx

    p0 = (fx - FieldElement(4)) / (x - FieldElement(1))

    p1 = (fx - result) / (x - G[TRACE_SIZE])

    p2_numerator = fgx - fx ** 8
    p2_denom = (x ** GROUP_SIZE - FieldElement(1)) / prod(
        [(x - g ** i) for i in range(TRACE_SIZE, GROUP_SIZE)]
    )
    p2 = p2_numerator / p2_denom
    polys = [p0, p1, p2]
    return x, sum([alphas[i] * polys[i] for i in range(3)])


def make_proof_a(trace, channel=None):
    if channel is None:
        channel = Channel()

    A = trace
    G = utils.generate_subgroup(GROUP_SIZE)
    f = utils.make_f_poly(A, G)
    eval_domain = utils.make_eval_domain(EVAL_SIZE)
    constraints = make_constraint_polys_a(f, G)
    return utils.make_proof(channel, f, constraints, G, eval_domain)


def make_proof_b(trace, channel=None):
    if channel is None:
        channel = Channel()

    A = trace
    G = utils.generate_subgroup(GROUP_SIZE)
    f = utils.make_f_poly(A, G)
    eval_domain = utils.make_eval_domain(EVAL_SIZE)
    constraints = make_constraint_polys_b(f, G)
    return utils.make_proof(channel, f, constraints, G, eval_domain)


def add_query(*args):
    args = args + (BLOWUP, )
    return utils.add_query(*args)


def verifier_a(channel, result, number_of_queries):
    return utils.verifier(
        channel, result, number_of_queries,
        fri_size=6,
        n_constraints=3,
        GROUP_SIZE=GROUP_SIZE,
        EVAL_SIZE=EVAL_SIZE,
        BLOWUP=BLOWUP,
        calculate_cp=calculate_cp_a
    )


def verifier_b(channel, result, number_of_queries):
    return utils.verifier(
        channel, result, number_of_queries,
        fri_size=6,
        n_constraints=3,
        GROUP_SIZE=GROUP_SIZE,
        EVAL_SIZE=EVAL_SIZE,
        BLOWUP=BLOWUP,
        calculate_cp=calculate_cp_b
    )
