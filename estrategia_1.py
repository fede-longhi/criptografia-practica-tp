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

El divisor más cercano a la longitud de la traza Y POTENCIA de 2 es: 2 ** 5 = 32

LDE = 21 * X > GRADO_RESTRICCIONES

Polinomial constraints

f(x) = 2 for x = g**0 -->
    p0(x) = f(x) - 2 / (x - g**0) = f(x) - 2 / (x - 1)

f(x) = RESULT for x = g**20 -->
    p1(x) = f(x) - RESULT / (x - g**20)

f(g*x) = f(x) ** 8 --> f(g*x) - f(x) ** 8 = 0 for x = g**i for 0 <= i <= 19 -->
    p2(x) = (f(g*x) - f(x) ** 8) / [(x - g**0)*(x - g**1)... (x - g**19)]

    Pero Mult(x - g**i) i=0..31 = (x ** 32 - 1) ==>

    [(x - g**0)*(x - g**1)... (x - g**19)] = (x ** 32 - 1) / prod[(x - g ** i) for i in [20, .., 31]]

    p2(x) = (f(g*x) - f(x) ** 8) / ((x ** 32 - 1) / prod[(x - g ** i) for i in [20, ..., 31]])
"""

from channel import Channel
from field import FieldElement
from polynomial import X, prod
from merkle_no_index import verify_decommitment
import utils

RESULT = FieldElement(2) ** (8 ** 20)

GROUP_SIZE = 32

TRACE_SIZE = 20

BLOWUP = 8

EVAL_SIZE = GROUP_SIZE * BLOWUP


def generate_trace():
    return utils.generate_trace([FieldElement(2)], lambda trace: trace[-1] ** 8, 20)


def make_constraint_polys(f, G, result=RESULT):

    g = G[1]

    p0 = (f - FieldElement(2)) / (X - FieldElement(1))
    p1 = (f - result) / (X - G[20])

    p2_numerator = f(g * X) - f ** 8

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

    p2_numerator = fgx - fx ** 8
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
    # eval_domain[idx] * G[1] = eval_domain[idx + BLOWUP]

    f_eval, f_merkle = utils.make_commitment_merkle(f, eval_domain)

    channel.send(f_merkle.root)

    constraints = make_constraint_polys(f, G)

    alphas = [channel.receive_random_field_element() for i in range(3)]
    CP = sum([constraints[i] * alphas[i] for i in range(3)])

    CP_eval, CP_merkle = utils.eval_and_commit(CP, eval_domain)

    channel.send(CP_merkle.root)

    # CP = FRI-0
    fri_polys, fri_domains, fri_layers, fri_merkles = [CP], [eval_domain], [CP_eval], [CP_merkle]

    fri_poly, fri_eval_domain = CP, eval_domain
    while True:
        beta = channel.receive_random_field_element()
        fri_eval_domain, fri_poly = utils.make_fri_step(fri_poly, fri_eval_domain, beta)
        fri_layer, fri_merkle = utils.eval_and_commit(fri_poly, fri_eval_domain)
        fri_polys.append(fri_poly)
        fri_domains.append(fri_eval_domain)
        fri_layers.append(fri_layer)
        fri_merkles.append(fri_merkle)
        channel.send(fri_merkle.root)
        if fri_poly.degree() < 1:
            channel.send(str(fri_poly.poly[0]))
            break

    return channel, f_eval, f_merkle, fri_polys, fri_domains, fri_layers, fri_merkles


def add_query(channel, f_eval, f_merkle, fri_polys, fri_domains, fri_layers, fri_merkles):
    # En mi CP tengo f(x) y f(g*x), entonces x puede ser g**i i=0..len(f_eval - 8)
    idx = channel.receive_random_int(0, len(f_eval) - BLOWUP)
    channel.send(str(f_eval[idx]))  # f(x)
    channel.send(",".join(f_merkle.get_authentication_path(idx)))  # auth path for f(x)
    channel.send(str(f_eval[idx + BLOWUP]))  # f(g*x)
    channel.send(",".join(f_merkle.get_authentication_path(idx + BLOWUP)))  # auth path for f(g*x)
    # print(
    #    f"idx = {idx} / X = {fri_domains[0][idx]} / f(x) = {f_eval[idx]} / "
    #    f"f(gx) = {f_eval[idx + BLOWUP]}"
    #    f" / CP(x) = {fri_polys[0](fri_domains[0][idx])} / CP(x) = {fri_layers[0][idx]}"
    # )

    for layer, merkle in zip(fri_layers[:-1], fri_merkles[:-1]):
        length = len(layer)
        idx = idx % length
        sib_idx = (idx + length // 2) % length
        channel.send(str(layer[idx]))
        channel.send(",".join(merkle.get_authentication_path(idx)))
        channel.send(str(layer[sib_idx]))
        channel.send(",".join(merkle.get_authentication_path(sib_idx)))
        # print(f"{length} - cp(x) {layer[idx]} - cp(-x) {layer[sib_idx]}")
    channel.send(str(fri_layers[-1][0]))


def verifier(channel, result, number_of_queries):
    proofs = [p[len("send:"):] for p in channel.proof if p.startswith("send:")]

    G = utils.generate_subgroup(GROUP_SIZE)

    replay_channel = Channel()
    f_merkle_root = proofs[0]
    replay_channel.send(f_merkle_root)
    alphas = [replay_channel.receive_random_field_element() for i in range(3)]

    cp_merkle_root = proofs[1]
    replay_channel.send(cp_merkle_root)

    fri_size = 8
    betas = []
    fri_roots = proofs[2:2 + fri_size]
    for i in range(fri_size):
        betas.append(replay_channel.receive_random_field_element())
        replay_channel.send(proofs[2 + i])
    fri_constant = FieldElement(int(proofs[2 + fri_size]))
    replay_channel.send(str(fri_constant))

    queries_proofs = proofs[2 + fri_size + 1:]
    proofs_per_query = (
        2 +  # fx + auth_path
        2 +  # fgx + auth_path
        4 * fri_size +  # CPi(x) + auth_path + CPi(-x) + auth_path
        1    # fri_constant
    )

    for query in range(number_of_queries):
        query_proofs = queries_proofs[query * proofs_per_query:(query + 1) * proofs_per_query]
        idx = replay_channel.receive_random_int(0, EVAL_SIZE - BLOWUP)
        fx = FieldElement(int(query_proofs[0]))
        fx_auth_path = query_proofs[1].split(",")
        fgx = FieldElement(int(query_proofs[2]))
        fgx_auth_path = query_proofs[3].split(",")

        # Check fx and fgx belongs to f_merkle_root
        verify_decommitment(fx, fx_auth_path, f_merkle_root)
        verify_decommitment(fgx, fgx_auth_path, f_merkle_root)

        x, cp_0 = calculate_cp(idx, fx, fgx, alphas, G, result)

        # print(
        #     f"idx = {idx} / f(x) = {fx} / f(gx) = {fgx} / "
        #     f"x = {x} / CP(x) = {cp_0}"
        # )

        # Check calculated CP_0 matches received CP_0
        assert cp_0 == FieldElement(int(query_proofs[4]))
        cp_0_auth_path = query_proofs[5].split(",")
        verify_decommitment(cp_0, cp_0_auth_path, cp_merkle_root)

        cp_0_sib = FieldElement(int(query_proofs[6]))
        cp_0_sib_auth_path = query_proofs[7].split(",")
        verify_decommitment(cp_0_sib, cp_0_sib_auth_path, cp_merkle_root)

        for fri_id in range(fri_size - 1):
            g_x2 = (cp_0 + cp_0_sib) / FieldElement(2)
            h_x2 = (cp_0 - cp_0_sib) / (x * FieldElement(2))
            cp_0 = g_x2 + betas[fri_id] * h_x2
            x = x ** 2

            # print(f"fri_id: {fri_id} / cp_0: {cp_0} / x: {x}")

            # Check the new cp_0
            assert cp_0 == FieldElement(int(query_proofs[8 + fri_id * 4]))
            cp_0_auth_path = query_proofs[8 + fri_id * 4 + 1].split(",")
            verify_decommitment(cp_0, cp_0_auth_path, fri_roots[fri_id])

            # Check the new cp_0_sib
            cp_0_sib = FieldElement(int(query_proofs[8 + fri_id * 4 + 2]))
            cp_0_sib_auth_path = query_proofs[8 + fri_id * 4 + 3].split(",")
            verify_decommitment(cp_0_sib, cp_0_sib_auth_path, fri_roots[fri_id])

        # TODO: verify fri_constant

        # Write to channel to update random
        [replay_channel.send(qp) for qp in query_proofs]
