"""
ESTRATEGIA 3

p = 3 * 2 ** 30 + 1

El statement a probar es:
2**(8**20) mod p = RESULT = 1610563584 # Statement

a_0 = 2
a_2n+1 = a_2n**2 mod p
a_2n = a_2n-1**4 mod p
a_19 = 2**(2**60) mod p = 1610563584

Longitud de la traza = 20

El orden del grupo |Fx| = 3 * 2 ** 30

El divisor más cercano a la longitud de la traza Y POTENCIA de 2 es: 2 ** 5 = 32

LDE = 21 * X > GRADO_RESTRICCIONES

Polinomial constraints

f(x) = 2 for x = g**0 -->
    p0(x) = f(x) - 2 / (x - g**0) = f(x) - 2 / (x - 1)

f(x) = RESULT for x = g**20 -->
    p1(x) = f(x) - RESULT / (x - g**20)

f(gx) = f(x)**4 para los pasos pares (x = [g**1, g**3, g**5, ... g**17])
    p2(x) = f(gx) - f(x)**4 / [(x - g**1) * (x - g**3) ...]

f(gx) = f(x)**2 para los pasos impares (x = [g**0, g**2, g**4, ...g**18])
    p2(x) = f(gx) - f(x)**2 / [(x - g**0) * (x - g**2) ... ]

"""

from channel import Channel
from field import FieldElement
from polynomial import X, prod
from merkle_no_index import verify_decommitment
import utils

RESULT = FieldElement(2) ** (8 ** 20)

GROUP_SIZE = 32

TRACE_SIZE = 19  # Este es el índice del último elemento de la traza que da el resultado, el tamaño es +1

BLOWUP = 4  # El degree del CP es 68, 4 * 32 = 128 esta es la potencia de 2 que lo supera

EVAL_SIZE = GROUP_SIZE * BLOWUP


def generate_trace():
    # return utils.generate_trace([FieldElement(2)], lambda trace: trace[-1] ** 2, 60)
    a0 = FieldElement(2)
    a1 = a0**2
    trace = [a0, a1]  # Ya computo a1 para mejor eficiencia
    for n in range(9):
        A = trace[-1]**4
        B = A**2
        trace.append(A)
        trace.append(B)
    return trace


def make_constraint_polys(f, G, result=RESULT):
    """
    Polinomial constraints

    f(x) = 2 for x = g**0 -->
        p0(x) = f(x) - 2 / (x - g**0) = f(x) - 2 / (x - 1)

    f(x) = RESULT for x = g**20 -->
        p1(x) = f(x) - RESULT / (x - g**20)

    f(gx) = f(x)**4 para los pasos pares (x = [g**1, g**3, g**5, ... g**17])
        p2(x) = f(gx) - f(x)**4 / [(x - g**1) * (x - g**3) ...]

    f(gx) = f(x)**2 para los pasos impares (x = [g**0, g**2, g**4, ...g**18])
        p2(x) = f(gx) - f(x)**2 / [(x - g**0) * (x - g**2) ... ]

    """

    g = G[1]

    p0 = (f - FieldElement(2)) / (X - FieldElement(1))
    p1 = (f - result) / (X - G[TRACE_SIZE])

    p2_numerator = f(g * X) - f(X) ** 4
    p2_denom = prod([(X - g ** (2 * i + 1)) for i in range(8)])

    p2 = p2_numerator / p2_denom

    p3_numerator = f(g * X) - f(X) ** 2

    p3_denom = prod([(X - g ** (2 * i)) for i in range(9)])

    p3 = p3_numerator / p3_denom

    return [p0, p1, p2, p3]


def calculate_cp(idx, fx, fgx, alphas, G, result):
    g = G[1]

    # Calculate x from idx (see make_eval_domain)
    w = FieldElement.generator()
    h = FieldElement.generator() ** (3 * 2 ** 30 // EVAL_SIZE)
    x = w * h ** idx

    p0 = (fx - FieldElement(2)) / (x - FieldElement(1))

    p1 = (fx - result) / (x - G[TRACE_SIZE])

    p2_numerator = fgx - fx ** 4
    p2_denom = prod([(x - g ** (2 * i + 1)) for i in range(8)])
    p2 = p2_numerator / p2_denom

    p3_numerator = fgx - fx ** 2
    p3_denom = prod([(x - g ** (2 * i)) for i in range(9)])
    p3 = p3_numerator / p3_denom

    polys = [p0, p1, p2, p3]
    return x, sum([alphas[i] * polys[i] for i in range(len(alphas))])


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
        fri_size=7,
        n_constraints=4,
        GROUP_SIZE=GROUP_SIZE,
        EVAL_SIZE=EVAL_SIZE,
        BLOWUP=BLOWUP,
        calculate_cp=calculate_cp
    )
