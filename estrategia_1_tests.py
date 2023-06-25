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


def test_make_commitment_merkle():
    trace = E1.generate_trace()
    G = E1.generate_subgroup(24)

    f = E1.make_f_poly(trace, G)

    eval_domain = E1.make_eval_domain(24 * 8)

    f_eval, commit_merkle = E1.make_commitment_merkle(f, eval_domain)
    assert commit_merkle.root == "e9cd344d2ff041c753023095fc02b7b4ef4abf4822d5b9e69880532dca9a13ce"

    assert len(commit_merkle.data) >= len(f_eval)  # Tiene más data porque completa con ceros
    # Chequea que todos f_eval estén en el MerkleTree
    for x in f_eval:
        assert x.val in commit_merkle.data


def test_make_proof():
    channel = E1.make_proof()

    assert channel.proof == [
        "send:e9cd344d2ff041c753023095fc02b7b4ef4abf4822d5b9e69880532dca9a13ce",  # Merkle root commits on f
        "receive_random_field_element:144202928",  # alfa_1 for CP
        "receive_random_field_element:983523113",  # alfa_2 for CP
        "receive_random_field_element:3197700428", # alfa_3 for CP
        "send:2a1ba165d1d71ba2eb936d3be59aa3603ae8b73ae35d77804d6f0708c1b39bf9"  # Merkle root commits on CP
    ]
