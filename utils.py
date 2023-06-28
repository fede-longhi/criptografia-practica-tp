from field import FieldElement
from channel import Channel
from polynomial import Polynomial, prod, X
from merkle_no_index import MerkleTree, verify_decommitment
from polynomial import interpolate_poly


def generate_trace(start_trace, step_operation, steps):
    """Función genérica para generar la traza

    @param start a_0
    @param step_operation función que toma trace como parámetro y devuelve el siguiente elemento
    @param steps Cantidad de pasos
    """
    trace = list(start_trace)

    for i in range(steps):
        trace.append(step_operation(trace))

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


def make_commitment_merkle(f, eval_domain):
    f_eval = [f(x) for x in eval_domain]
    # Commitments
    f_merkle = MerkleTree(f_eval)

    return f_eval, f_merkle


def eval_and_commit(poly, eval_domain):
    eval_results = [poly(x) for x in eval_domain]
    # Commitments
    merkle = MerkleTree(eval_results)

    return eval_results, merkle


def make_fri_step(poly, eval_domain, beta):
    domain_size = len(eval_domain)
    next_domain = [x ** 2 for x in eval_domain[:(domain_size + 1) // 2]]
    # Check 2nd half is equal to 1st half
    # next_domain_alt = [x ** 2 for x in eval_domain[len(eval_domain) // 2:]]
    # assert next_domain == next_domain_alt

    odd_coeficients = poly.poly[1::2]
    even_coeficients = poly.poly[::2]
    odd = beta * Polynomial(odd_coeficients)
    even = Polynomial(even_coeficients)
    next_poly = odd + even
    return next_domain, next_poly


def make_proof(channel, f, constraints, G, eval_domain):
    f_eval, f_merkle = make_commitment_merkle(f, eval_domain)

    channel.send(f_merkle.root)

    alphas = [channel.receive_random_field_element() for i in range(len(constraints))]
    CP = sum([constraints[i] * alphas[i] for i in range(len(constraints))])

    CP_eval, CP_merkle = eval_and_commit(CP, eval_domain)

    channel.send(CP_merkle.root)

    # CP = FRI-0
    fri_polys, fri_domains, fri_layers, fri_merkles = [CP], [eval_domain], [CP_eval], [CP_merkle]

    fri_poly, fri_eval_domain = CP, eval_domain
    while True:
        beta = channel.receive_random_field_element()
        fri_eval_domain, fri_poly = make_fri_step(fri_poly, fri_eval_domain, beta)
        fri_layer, fri_merkle = eval_and_commit(fri_poly, fri_eval_domain)
        fri_polys.append(fri_poly)
        fri_domains.append(fri_eval_domain)
        fri_layers.append(fri_layer)
        fri_merkles.append(fri_merkle)
        channel.send(fri_merkle.root)
        if fri_poly.degree() < 1:
            channel.send(str(fri_poly.poly[0]))
            break

    return channel, f_eval, f_merkle, fri_polys, fri_domains, fri_layers, fri_merkles


def add_query(channel, f_eval, f_merkle, fri_polys, fri_domains, fri_layers, fri_merkles, BLOWUP):
    # En mi CP tengo f(x) y f(g*x), entonces x puede ser g**i i=0..len(f_eval - 8)
    idx = channel.receive_random_int(0, len(f_eval) - BLOWUP - 1)

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


def verifier(channel, result, number_of_queries,
             fri_size, n_constraints, GROUP_SIZE, EVAL_SIZE, BLOWUP, calculate_cp):
    proofs = [p[len("send:"):] for p in channel.proof if p.startswith("send:")]

    G = generate_subgroup(GROUP_SIZE)

    replay_channel = Channel()
    f_merkle_root = proofs[0]
    replay_channel.send(f_merkle_root)
    alphas = [replay_channel.receive_random_field_element() for i in range(n_constraints)]

    cp_merkle_root = proofs[1]
    replay_channel.send(cp_merkle_root)

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
        idx = replay_channel.receive_random_int(0, EVAL_SIZE - BLOWUP - 1)
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
