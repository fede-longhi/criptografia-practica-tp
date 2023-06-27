import math
import estrategia_2 as E2
import utils as UT
from field import FieldElement


def test_generate_trace():
    trace = E2.generate_trace()
    assert len(trace) == 61
    assert trace[0] == 2
    assert trace[-1] == E2.RESULT


def test_generate_subgroup():
    subgroup = UT.generate_subgroup(E2.GROUP_SIZE)
    assert len(subgroup) == E2.GROUP_SIZE
    # Verifico que el subgrupo tenga tamaño E2.GROUP_SIZE, si multiplico el último
    # g**23 * g, me tiene que dar 1
    assert subgroup[1] * subgroup[-1] == FieldElement.one()


def test_make_f_poly():
    trace = E2.generate_trace()
    subgroup = UT.generate_subgroup(E2.GROUP_SIZE)

    f = UT.make_f_poly(trace, subgroup)
    assert f.degree() == E2.TRACE_SIZE
    assert f(subgroup[E2.TRACE_SIZE]) == E2.RESULT
    assert f(1) == 2

    for i in range(2, E2.TRACE_SIZE):
        assert f(subgroup[i]) == trace[i]


def test_make_constraint_polys():
    trace = E2.generate_trace()
    G = UT.generate_subgroup(E2.GROUP_SIZE)

    f = UT.make_f_poly(trace, G)

    p0, p1, p2 = E2.make_constraint_polys(f, G)

    assert p0.degree() == 59
    assert p1.degree() == 59
    assert p2.degree() == 60


def test_calculate_cp():
    trace = E2.generate_trace()
    G = UT.generate_subgroup(E2.GROUP_SIZE)
    g = G[1]

    f = UT.make_f_poly(trace, G)

    constraints = E2.make_constraint_polys(f, G)
    eval_domain = UT.make_eval_domain(E2.EVAL_SIZE)

    alphas = [FieldElement.random_element() for x in range(3)]
    CP = sum([constraints[i] * alphas[i] for i in range(3)])

    for idx in range(len(eval_domain)):
        x = eval_domain[idx]
        cp_x = CP(x)
        x_calculated, cp_x_calculated = E2.calculate_cp(idx, f(x), f(g * x), alphas, G, E2.RESULT)
        assert x_calculated == x
        assert cp_x_calculated == cp_x


def test_make_eval_domain():
    size = E2.GROUP_SIZE * 8
    assert size > 140, "El tamaño es menor que el grado de los constraints"
    eval_domain = UT.make_eval_domain(size)
    assert len(eval_domain) == size

    G = UT.generate_subgroup(E2.GROUP_SIZE)
    g = G[1]

    # Relación usada después en la parte de los queries
    for i in range(len(eval_domain) - 8):
        assert eval_domain[i] * g == eval_domain[i + 8]


def test_make_commitment_merkle():
    trace = E2.generate_trace()
    G = UT.generate_subgroup(E2.GROUP_SIZE)

    f = UT.make_f_poly(trace, G)

    eval_domain = UT.make_eval_domain(E2.EVAL_SIZE)

    f_eval, commit_merkle = UT.make_commitment_merkle(f, eval_domain)
    if E2.BLOWUP == 1:
        assert commit_merkle.root == "53045f6684e4bd7b24f7fdd3c6a52fc22a97d72b2438b54e374eab7d3478f851"
    elif E2.BLOWUP == 8:
        assert commit_merkle.root == "4e3cc77d94d2d3e5746101f82c8d147c3007c6a74225daa603c001c4f9a81374"


def test_make_fri_step():
    trace = E2.generate_trace()
    G = UT.generate_subgroup(E2.GROUP_SIZE)

    f = UT.make_f_poly(trace, G)

    eval_domain = UT.make_eval_domain(E2.GROUP_SIZE * 8)
    p0, p1, p2 = E2.make_constraint_polys(f, G)

    CP = 2 * p0 + 3 * p1 + 4 * p2

    next_eval_domain, next_poly = UT.make_fri_step(CP, eval_domain, 5)
    assert len(next_eval_domain) == len(eval_domain) // 2
    assert next_poly.degree() == CP.degree() // 2


def test_make_proof():
    channel, f_eval, f_merkle, fri_polys, fri_domains, fri_layers, fri_merkles = E2.make_proof()

    CP = fri_polys[0]

    fri_size = math.ceil(math.log2(CP.degree()))
    assert fri_size == len(fri_polys[1:])
    assert fri_size == 6

    # Merkle root commits on f
    if E2.BLOWUP == 8:
        assert channel.proof[0] == "send:4e3cc77d94d2d3e5746101f82c8d147c3007c6a74225daa603c001c4f9a81374"
    elif E2.BLOWUP == 1:
        assert channel.proof[0] == "send:53045f6684e4bd7b24f7fdd3c6a52fc22a97d72b2438b54e374eab7d3478f851"

    assert len(channel.proof) == (
        1 +  # commits on F
        3 +  # alfas for CP
        1 +  # commits on CP
        2 * fri_size +  # Beta + commit on FRI-X
        1  # Término constante del último FRI
    )


def test_add_query():
    channel, f_eval, f_merkle, fri_polys, fri_domains, fri_layers, fri_merkles = E2.make_proof()

    proof_length = len(channel.proof)

    E2.add_query(channel, f_eval, f_merkle, fri_polys, fri_domains, fri_layers, fri_merkles)

    assert len(channel.proof) == (
        proof_length +
        1 +  # random idx
        2 +  # f(x) + auth_path
        2 +  # f(g*x) + auth_path
        4 * len(fri_layers[:-1]) +  # FRI-x(x) + FRI-x(-x) + auth_paths
        1
    )


def test_verifier():
    channel, f_eval, f_merkle, fri_polys, fri_domains, fri_layers, fri_merkles = E2.make_proof()

    number_of_queries = 1

    for i in range(number_of_queries):
        E2.add_query(channel, f_eval, f_merkle, fri_polys, fri_domains, fri_layers, fri_merkles)

    E2.verifier(channel, E2.RESULT, number_of_queries)
