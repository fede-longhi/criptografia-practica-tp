import math
import estrategia_1 as E1
import utils as UT
from field import FieldElement


def test_generate_trace():
    trace = E1.generate_trace()
    assert len(trace) == 21
    assert trace[0] == 2
    assert trace[-1] == E1.RESULT


def test_generate_subgroup():
    subgroup = UT.generate_subgroup(E1.GROUP_SIZE)
    assert len(subgroup) == E1.GROUP_SIZE
    # Verifico que el subgrupo tenga tamaño E1.GROUP_SIZE, si multiplico el último
    # g**23 * g, me tiene que dar 1
    assert subgroup[1] * subgroup[-1] == FieldElement.one()


def test_make_f_poly():
    trace = E1.generate_trace()
    subgroup = UT.generate_subgroup(E1.GROUP_SIZE)

    f = UT.make_f_poly(trace, subgroup)
    assert f.degree() == 20
    assert f(subgroup[20]) == E1.RESULT
    assert f(1) == 2

    for i in range(2, 20):
        assert f(subgroup[i]) == trace[i]


def test_make_constraint_polys():
    trace = E1.generate_trace()
    G = UT.generate_subgroup(E1.GROUP_SIZE)

    f = UT.make_f_poly(trace, G)

    p0, p1, p2 = E1.make_constraint_polys(f, G)

    assert p0.degree() == 19
    assert p1.degree() == 19
    assert p2.degree() == 140


def test_calculate_cp():
    trace = E1.generate_trace()
    G = UT.generate_subgroup(E1.GROUP_SIZE)
    g = G[1]

    f = UT.make_f_poly(trace, G)

    constraints = E1.make_constraint_polys(f, G)
    eval_domain = UT.make_eval_domain(E1.GROUP_SIZE * 8)

    alphas = [FieldElement.random_element() for x in range(3)]
    CP = sum([constraints[i] * alphas[i] for i in range(3)])

    for idx in range(len(eval_domain)):
        x = eval_domain[idx]
        cp_x = CP(x)
        x_calculated, cp_x_calculated = E1.calculate_cp(idx, f(x), f(g * x), alphas, G, E1.RESULT)
        assert x_calculated == x
        assert cp_x_calculated == cp_x


def test_make_eval_domain():
    size = E1.GROUP_SIZE * 8
    assert size > 140, "El tamaño es menor que el grado de los constraints"
    eval_domain = UT.make_eval_domain(size)
    assert len(eval_domain) == size

    G = UT.generate_subgroup(E1.GROUP_SIZE)
    g = G[1]

    # Relación usada después en la parte de los queries
    for i in range(len(eval_domain) - 8):
        assert eval_domain[i] * g == eval_domain[i + 8]


def test_make_commitment_merkle():
    trace = E1.generate_trace()
    G = UT.generate_subgroup(24)

    f = UT.make_f_poly(trace, G)

    eval_domain = UT.make_eval_domain(24 * 8)

    f_eval, commit_merkle = UT.make_commitment_merkle(f, eval_domain)
    assert commit_merkle.root == "742708abb3da2bc4805d1ac9070ace0409b7b7c823c3cc699be08c206e36710d"


def test_make_fri_step():
    trace = E1.generate_trace()
    G = UT.generate_subgroup(E1.GROUP_SIZE)

    f = UT.make_f_poly(trace, G)

    eval_domain = UT.make_eval_domain(E1.GROUP_SIZE * 8)
    p0, p1, p2 = E1.make_constraint_polys(f, G)

    CP = 2 * p0 + 3 * p1 + 4 * p2

    next_eval_domain, next_poly = UT.make_fri_step(CP, eval_domain, 5)
    assert len(next_eval_domain) == len(eval_domain) // 2
    assert next_poly.degree() == CP.degree() // 2


def test_make_proof():
    channel, f_eval, f_merkle, fri_polys, fri_domains, fri_layers, fri_merkles = E1.make_proof()

    CP = fri_polys[0]

    fri_size = math.ceil(math.log2(CP.degree()))
    assert fri_size == len(fri_polys[1:])

    assert channel.proof == [
        "send:b1bb1637c1b5b32b097685229f6d8e028af87c22e2f7883abab0ceb60feff922",  # Merkle root commits on f
        "receive_random_field_element:1023867590",  # alfa_1 for CP
        "receive_random_field_element:1266220913",  # alfa_2 for CP
        "receive_random_field_element:3038548208",  # alfa_3 for CP
        "send:6d7cc13db7c472b1e622e08271dd48bca6c16724f5bc00d85a42ddf6859d9251",  # Merkle root commits on CP
        "receive_random_field_element:3186713001",  # Beta for FRI-1
        "send:744971ab39d8444dbf783d4f28b14bf65d82660c14b847291da1994aca6b0cf1",  # Merkle commit FRI-1
        "receive_random_field_element:1461638272",   # Beta for FRI-2
        "send:c9d9f6ef680fefb8e4264afe504e71849ec8079ae673efa01f914fab1f616fc6",  # Merkle commit FRI-2
        "receive_random_field_element:2689121257",  # Beta for FRI-3
        "send:981e8ee4a3a777c0ea50a4b6e01f56a45c46de5a67471be3479b88bd9e4ccaf6",  # Merkle commit FRI-3
        "receive_random_field_element:1966890461",  # Beta for FRI-4
        "send:46e9057e5612bd67245dab4db1c592fa850f90aeaf5a63d932e7e97fd22dfd8c",  # Merkle commit FRI-4
        "receive_random_field_element:1163474898",  # Beta for FRI-5
        "send:2df2409d247ebeea767120f7a36e5d49091de080c2ffa23df66363581bf883b0",  # Merkle commit FRI-5
        "receive_random_field_element:906664276",  # Beta for FRI-6
        "send:e57204e56171ad7875e3cae2dd1de6a4eecefa65f63a31e692b96c29556fe5cb",  # Merkle commit FRI-6
        "receive_random_field_element:2258353312",  # Beta for FRI-7
        "send:379e69436dbdbbeb58f0e10a132cb112e0a72ace67b31dffb46479530ceb099e",  # Merkle commit FRI-7
        "receive_random_field_element:1426558679",  # Beta for FRI-8
        "send:9b51e36e675418f9497302f7347f1d56fcbe0583ee6d1169450cb206e03c049b",  # Merkle commit FRI-8
        "send:-391489325"  # Término constante del último FRI-9
    ]

    assert len(channel.proof) == (
        1 +  # commits on F
        3 +  # alfas for CP
        1 +  # commits on CP
        2 * fri_size +  # Beta + commit on FRI-X
        1  # Término constante del último FRI
    )


def test_add_query():
    channel, f_eval, f_merkle, fri_polys, fri_domains, fri_layers, fri_merkles = E1.make_proof()

    proof_length = len(channel.proof)

    E1.add_query(channel, f_eval, f_merkle, fri_polys, fri_domains, fri_layers, fri_merkles)

    assert len(channel.proof) == (
        proof_length +
        1 +  # random idx
        2 +  # f(x) + auth_path
        2 +  # f(g*x) + auth_path
        4 * len(fri_layers[:-1]) +  # FRI-x(x) + FRI-x(-x) + auth_paths
        1
    )


def test_verifier():
    channel, f_eval, f_merkle, fri_polys, fri_domains, fri_layers, fri_merkles = E1.make_proof()

    number_of_queries = 10

    for i in range(number_of_queries):
        E1.add_query(channel, f_eval, f_merkle, fri_polys, fri_domains, fri_layers, fri_merkles)

    E1.verifier(channel, E1.RESULT, number_of_queries)
