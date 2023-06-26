import math
import estrategia_1 as E1
from field import FieldElement


def test_generate_trace():
    trace = E1.generate_trace()
    assert len(trace) == 21
    assert trace[0] == 2
    assert trace[-1] == E1.RESULT


def test_generate_subgroup():
    subgroup = E1.generate_subgroup(24)
    assert len(subgroup) == 24
    # Verifico que el subgrupo tenga tamaño 24, si multiplico el último
    # g**23 * g, me tiene que dar 1
    assert subgroup[1] * subgroup[-1] == FieldElement.one()


def test_make_f_poly():
    trace = E1.generate_trace()
    subgroup = E1.generate_subgroup(24)

    f = E1.make_f_poly(trace, subgroup)
    assert f.degree() == 20
    assert f(subgroup[20]) == E1.RESULT
    assert f(1) == 2

    for i in range(2, 20):
        assert f(subgroup[i]) == trace[i]


def test_make_constraint_polys():
    trace = E1.generate_trace()
    G = E1.generate_subgroup(24)

    f = E1.make_f_poly(trace, G)

    p0, p1, p2 = E1.make_constraint_polys(f, G)

    assert p0.degree() == 19
    assert p1.degree() == 19
    assert p2.degree() == 140


def test_make_eval_domain():
    size = 24 * 8
    assert size > 140, "El tamaño es menor que el grado de los constraints"
    eval_domain = E1.make_eval_domain(size)
    assert len(eval_domain) == size

    G = E1.generate_subgroup(24)
    g = G[1]

    # Relación usada después en la parte de los queries
    for i in range(len(eval_domain) - 8):
        assert eval_domain[i] * g == eval_domain[i + 8]


def test_make_commitment_merkle():
    trace = E1.generate_trace()
    G = E1.generate_subgroup(24)

    f = E1.make_f_poly(trace, G)

    eval_domain = E1.make_eval_domain(24 * 8)

    f_eval, commit_merkle = E1.make_commitment_merkle(f, eval_domain)
    assert commit_merkle.root == "742708abb3da2bc4805d1ac9070ace0409b7b7c823c3cc699be08c206e36710d"


def test_make_fri_step():
    trace = E1.generate_trace()
    G = E1.generate_subgroup(24)

    f = E1.make_f_poly(trace, G)

    eval_domain = E1.make_eval_domain(24 * 8)
    p0, p1, p2 = E1.make_constraint_polys(f, G)

    CP = 2 * p0 + 3 * p1 + 4 * p2

    next_eval_domain, next_poly = E1.make_fri_step(CP, eval_domain, 5)
    assert len(next_eval_domain) == len(eval_domain) // 2
    assert next_poly.degree() == CP.degree() // 2


def test_make_proof():
    channel, f_eval, f_merkle, fri_polys, fri_domains, fri_layers, fri_merkles = E1.make_proof()

    CP = fri_polys[0]

    fri_size = math.ceil(math.log2(CP.degree()))
    assert fri_size == len(fri_polys[1:])

    assert channel.proof == [
        "send:742708abb3da2bc4805d1ac9070ace0409b7b7c823c3cc699be08c206e36710d",  # Merkle root commits on f
        "receive_random_field_element:1986540441",  # alfa_1 for CP
        "receive_random_field_element:1090716028",  # alfa_2 for CP
        "receive_random_field_element:967128977",  # alfa_3 for CP
        "send:b2eb358a60e779f0652b767e66c41dcf1928edbc689d58e95867e830eabf8e20",  # Merkle root commits on CP
        "receive_random_field_element:760601736",  # Beta for FRI-1
        "send:fc24ef5f12a699797014c8436548fab9d7ef91ecc5405914e5bef8fbf11a46ed",  # Merkle commit FRI-1
        "receive_random_field_element:638900333",   # Beta for FRI-2
        "send:3594d91dfb3d8ef899367b9034223bbb78a46ccc6a4ec0e8fbc27cf73dd65bb7",  # Merkle commit FRI-2
        "receive_random_field_element:1891542084",  # Beta for FRI-3
        "send:c5f3fdf3e8df5e659f60873f588a8afbae09a9b3233aab00f81a16293025fe9c",  # Merkle commit FRI-3
        "receive_random_field_element:1331305393",  # Beta for FRI-4
        "send:bebd6d335421d3aad53accff33b9f43ffbd7bddf81c876d94877a5d58c438982",  # Merkle commit FRI-4
        "receive_random_field_element:460803178",  # Beta for FRI-5
        "send:e8e9c42e78cc497d4c5892b8039a0982e0256ffeeeb91a79b12c48da83e2f384",  # Merkle commit FRI-5
        "receive_random_field_element:2446862658",  # Beta for FRI-6
        "send:878ee6b39c91ecb3d68c703b8ebb1c4b36d5703c7010f4c844492d564963e6c4",  # Merkle commit FRI-6
        "receive_random_field_element:2965857702",  # Beta for FRI-7
        "send:703f81ab5e0c92e4f846d56de16273faf860b00a002d51080267e58e196d783c",  # Merkle commit FRI-7
        "receive_random_field_element:1335015104",  # Beta for FRI-8
        "send:c10bba9d9e91c7157189bd5d97e9019453e007ce2a8260ed5fa388efa7ce0d7c",  # Merkle commit FRI-8
        "send:-1096657780"  # Término constante del último FRI-9
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

    # Add 2 queries
    E1.add_query(channel, f_eval, f_merkle, fri_polys, fri_domains, fri_layers, fri_merkles)
    E1.add_query(channel, f_eval, f_merkle, fri_polys, fri_domains, fri_layers, fri_merkles)

    E1.verifier(channel, E1.RESULT, 2)
