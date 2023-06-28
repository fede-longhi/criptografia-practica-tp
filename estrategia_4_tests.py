import math
import estrategia_4 as E4
import utils as UT
from field import FieldElement


def test_generate_trace():
    trace_a, trace_b = E4.generate_trace()
    assert len(trace_a) == 10
    assert len(trace_b) == 10
    assert trace_b[-1] == E4.RESULT
    assert trace_b[E4.TRACE_SIZE] == E4.RESULT
    assert trace_a[-1] == E4.RESULT_A
    assert trace_a[E4.TRACE_SIZE] == E4.RESULT_A


def test_generate_subgroup():
    subgroup = UT.generate_subgroup(E4.GROUP_SIZE)
    assert len(subgroup) == E4.GROUP_SIZE
    # Verifico que el subgrupo tenga tamaño E4.GROUP_SIZE, si multiplico el último
    # g**23 * g, me tiene que dar 1
    assert subgroup[1] * subgroup[-1] == FieldElement.one()


def test_make_f_poly():
    trace_a, trace_b = E4.generate_trace()
    subgroup = UT.generate_subgroup(E4.GROUP_SIZE)

    f_a = UT.make_f_poly(trace_a, subgroup)
    f_b = UT.make_f_poly(trace_b, subgroup)

    # Check f interpolates
    g = subgroup[1]
    for i in range(E4.TRACE_SIZE):
        assert f_a(g ** i) == trace_a[i]
        assert f_b(g ** i) == trace_b[i]

    assert f_a.degree() == E4.TRACE_SIZE
    assert f_b.degree() == E4.TRACE_SIZE
    assert f_b(subgroup[E4.TRACE_SIZE]) == E4.RESULT
    assert f_a(1) == 2

    for i in range(2, E4.TRACE_SIZE):
        assert f_a(subgroup[i]) == trace_a[i]
        assert f_b(subgroup[i]) == trace_b[i]


def test_make_constraint_polys():
    trace_a, trace_b = E4.generate_trace()
    G = UT.generate_subgroup(E4.GROUP_SIZE)

    f_a = UT.make_f_poly(trace_a, G)
    f_b = UT.make_f_poly(trace_b, G)

    polys_a = E4.make_constraint_polys_a(f_a, G, E4.RESULT_A)
    polys_b = E4.make_constraint_polys_b(f_b, G)

    assert polys_a[0].degree() == 8
    assert polys_a[1].degree() == 8
    assert polys_a[2].degree() == 63
    CP_a = sum([polys_a[i] * (i + 1) for i in range(3)])
    assert CP_a.degree() == 63

    assert polys_b[0].degree() == 8
    assert polys_b[1].degree() == 8
    assert polys_b[2].degree() == 63
    CP_b = sum([polys_b[i] * (i + 1) for i in range(3)])
    assert CP_b.degree() == 63


def test_calculate_cp():
    trace_a, trace_b = E4.generate_trace()
    G = UT.generate_subgroup(E4.GROUP_SIZE)
    g = G[1]

    f_a = UT.make_f_poly(trace_a, G)
    f_b = UT.make_f_poly(trace_b, G)

    constraints_a = E4.make_constraint_polys_a(f_a, G, E4.RESULT_A)
    constraints_b = E4.make_constraint_polys_b(f_b, G)

    eval_domain = UT.make_eval_domain(E4.EVAL_SIZE)

    alphas_a = [FieldElement.random_element() for x in range(len(constraints_a))]
    alphas_b = [FieldElement.random_element() for x in range(len(constraints_b))]
    CP_a = sum([constraints_a[i] * alphas_a[i] for i in range(len(constraints_a))])
    CP_b = sum([constraints_b[i] * alphas_b[i] for i in range(len(constraints_b))])

    for idx in range(len(eval_domain)):
        x = eval_domain[idx]
        x_calculated, cp_a_calculated = E4.calculate_cp_a(
            idx, f_a(x), f_a(g * x), alphas_a, G, E4.RESULT_A
        )
        cp_a_x = CP_a(x)

        x_calculated, cp_b_calculated = E4.calculate_cp_b(
            idx, f_b(x), f_b(g * x), alphas_b, G, E4.RESULT
        )
        cp_b_x = CP_b(x)
        assert x_calculated == x
        assert cp_a_calculated == cp_a_x
        assert cp_b_calculated == cp_b_x


def test_make_eval_domain():
    size = E4.GROUP_SIZE * 8
    assert size > 63, "El tamaño es menor que el grado de los constraints"
    eval_domain = UT.make_eval_domain(size)
    assert len(eval_domain) == size

    G = UT.generate_subgroup(E4.GROUP_SIZE)
    g = G[1]

    # Relación usada después en la parte de los queries
    for i in range(len(eval_domain) - 8):
        assert eval_domain[i] * g == eval_domain[i + 8]


def test_make_commitment_merkle():
    trace_a, trace_b = E4.generate_trace()
    G = UT.generate_subgroup(E4.GROUP_SIZE)

    f_a = UT.make_f_poly(trace_a, G)
    f_b = UT.make_f_poly(trace_b, G)

    eval_domain = UT.make_eval_domain(E4.EVAL_SIZE)

    f_eval_a, commit_merkle_a = UT.make_commitment_merkle(f_a, eval_domain)
    if E4.BLOWUP == 4:
        assert commit_merkle_a.root == "cfac3783e0c3c141d63dd5f5f5a5d158670634f6a0dfee9be4fe29bd67857794"

    f_eval_b, commit_merkle_b = UT.make_commitment_merkle(f_b, eval_domain)
    if E4.BLOWUP == 4:
        assert commit_merkle_b.root == "adc7cef1201ee5a0371636dfd2a2a1fd65a7602c49ddafaf5a757f868d98de36"


def test_make_fri_step():
    trace_a, trace_b = E4.generate_trace()
    G = UT.generate_subgroup(E4.GROUP_SIZE)

    f_a = UT.make_f_poly(trace_a, G)
    f_b = UT.make_f_poly(trace_b, G)

    eval_domain = UT.make_eval_domain(E4.GROUP_SIZE * E4.BLOWUP)
    polys_a = E4.make_constraint_polys_a(f_a, G, E4.RESULT_A)
    polys_b = E4.make_constraint_polys_b(f_b, G)

    CP_a = sum([polys_a[i] * (i + 1) for i in range(3)])
    CP_b = sum([polys_b[i] * (i + 1) for i in range(3)])

    next_eval_domain, next_poly_a = UT.make_fri_step(CP_a, eval_domain, 5)
    assert len(next_eval_domain) == len(eval_domain) // 2
    assert next_poly_a.degree() == CP_a.degree() // 2

    next_eval_domain, next_poly_b = UT.make_fri_step(CP_b, eval_domain, 5)
    assert len(next_eval_domain) == len(eval_domain) // 2
    assert next_poly_b.degree() == CP_b.degree() // 2


def test_make_proof():
    trace_a, trace_b = E4.generate_trace()

    # Check proof A
    channel, f_eval, f_merkle, fri_polys, fri_domains, fri_layers, fri_merkles = E4.make_proof_a(trace_a)

    CP = fri_polys[0]

    fri_size = math.ceil(math.log2(CP.degree()))
    assert fri_size == len(fri_polys[1:])
    assert fri_size == 6
    assert fri_size == math.ceil(math.log2(63))  # 63 es el grado de CP

    # Merkle root commits on f
    if E4.BLOWUP == 4:
        assert channel.proof[0] == "send:cfac3783e0c3c141d63dd5f5f5a5d158670634f6a0dfee9be4fe29bd67857794"

    assert len(channel.proof) == (
        1 +  # commits on F
        3 +  # alfas for CP
        1 +  # commits on CP
        2 * fri_size +  # Beta + commit on FRI-X
        1  # Término constante del último FRI
    )

    # Check proof B
    channel, f_eval, f_merkle, fri_polys, fri_domains, fri_layers, fri_merkles = E4.make_proof_b(trace_b)

    CP = fri_polys[0]

    fri_size = math.ceil(math.log2(CP.degree()))
    assert fri_size == len(fri_polys[1:])
    assert fri_size == 6
    assert fri_size == math.ceil(math.log2(63))  # 63 es el grado de CP

    # Merkle root commits on f
    if E4.BLOWUP == 4:
        assert channel.proof[0] == "send:adc7cef1201ee5a0371636dfd2a2a1fd65a7602c49ddafaf5a757f868d98de36"

    assert len(channel.proof) == (
        1 +  # commits on F
        3 +  # alfas for CP
        1 +  # commits on CP
        2 * fri_size +  # Beta + commit on FRI-X
        1  # Término constante del último FRI
    )


def test_add_query():
    trace_a, trace_b = E4.generate_trace()

    # Check for A
    channel, f_eval, f_merkle, fri_polys, fri_domains, fri_layers, fri_merkles = E4.make_proof_a(trace_a)

    proof_length = len(channel.proof)

    E4.add_query(channel, f_eval, f_merkle, fri_polys, fri_domains, fri_layers, fri_merkles)

    assert len(channel.proof) == (
        proof_length +
        1 +  # random idx
        2 +  # f(x) + auth_path
        2 +  # f(g*x) + auth_path
        4 * len(fri_layers[:-1]) +  # FRI-x(x) + FRI-x(-x) + auth_paths
        1
    )

    # Check for B
    channel, f_eval, f_merkle, fri_polys, fri_domains, fri_layers, fri_merkles = E4.make_proof_b(trace_b)

    proof_length = len(channel.proof)

    E4.add_query(channel, f_eval, f_merkle, fri_polys, fri_domains, fri_layers, fri_merkles)

    assert len(channel.proof) == (
        proof_length +
        1 +  # random idx
        2 +  # f(x) + auth_path
        2 +  # f(g*x) + auth_path
        4 * len(fri_layers[:-1]) +  # FRI-x(x) + FRI-x(-x) + auth_paths
        1
    )


def test_verifier():
    trace_a, trace_b = E4.generate_trace()

    # Check for A
    channel, f_eval, f_merkle, fri_polys, fri_domains, fri_layers, fri_merkles = E4.make_proof_a(trace_a)

    number_of_queries = 10

    for i in range(number_of_queries):
        E4.add_query(channel, f_eval, f_merkle, fri_polys, fri_domains, fri_layers, fri_merkles)

    E4.verifier_a(channel, E4.RESULT_A, number_of_queries)

    # Check for B
    channel, f_eval, f_merkle, fri_polys, fri_domains, fri_layers, fri_merkles = E4.make_proof_b(trace_b)

    number_of_queries = 10

    for i in range(number_of_queries):
        E4.add_query(channel, f_eval, f_merkle, fri_polys, fri_domains, fri_layers, fri_merkles)

    E4.verifier_b(channel, E4.RESULT, number_of_queries)
