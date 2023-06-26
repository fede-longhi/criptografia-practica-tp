from field import FieldElement
from channel import Channel
from polynomial import Polynomial, prod, X
from merkle import MerkleTree


def generate_trace_e1(size):
    trace = [FieldElement(2)]
    while len(trace) < size:
        trace.append(trace[-1]**8)
    return trace


def generate_group(g, group_size):
    G = [g ** i for i in range(group_size)]
    return G


def generate_group_and_generator(group_order, sub_group_size):
    assert (group_order / sub_group_size) == (group_order // sub_group_size), \
        "El tamaño no es divisor del orden del grupo"
    g = FieldElement.generator()**(group_order//sub_group_size)  # 3*2**30 / 2**27 = 3*2**3 (trace_size)
    G = generate_group(g, sub_group_size)
    return g, G


def generate_larger_domain_evaluation(size, group_order, f):
    w = FieldElement.generator()
    h = w ** ((group_order)//(size))
    H = [h**i for i in range(size)]
    eval_domain = [w*x for x in H]

    f_eval = [f(d) for d in eval_domain]
    return f_eval, eval_domain


def make_constraint_polys_e1(f, g, G, RESULT, group_size, trace_size):
    # First constraint
    numer0 = f - FieldElement(2)
    denom0 = X - FieldElement(1)  # X - g^0

    p0 = numer0/denom0

    # Second constraint -> hay segunda constraint?
    numer1 = f - RESULT
    denom1 = X - G[20]
    p1 = numer1 / denom1

    # Third constraint -> si no hay segunda esta deberia ser segunda
    numer2 = f(g*X) - f(X)**8
    denom2 = ((X**group_size) - FieldElement(1)) / prod([X - g**i for i in range(trace_size-1, group_size)]) # esto hay que chequear

    p2 = numer2/denom2
    return [p0, p1, p2]


def get_CP(channel, polynomials):
    CP = 0
    for pol in polynomials:
        CP += Channel.receive_random_field_element(channel) * pol
    return CP


def get_CP_eval(CP, eval_domain):
    return [CP(x) for x in eval_domain]


def next_fri_domain(fri_domain):
    return [x**2 for x in fri_domain[:len(fri_domain) // 2]]


def next_fri_polynomial(poly, beta):
    odd_coeficients = poly.poly[1::2]
    even_coeficients = poly.poly[::2]
    odd = beta * Polynomial(odd_coeficients)
    even = Polynomial(even_coeficients)
    return odd + even


def next_fri_layer(poly, domain, beta):
    next_poly = next_fri_polynomial(poly, beta)
    next_domain = next_fri_domain(domain)
    next_layer = [next_poly(x) for x in next_domain]
    return next_poly, next_domain, next_layer


def FriCommit(cp, domain, cp_eval, cp_merkle, channel):
    fri_polys = [cp]
    fri_domains = [domain]
    fri_layers = [cp_eval]
    fri_merkles = [cp_merkle]
    while fri_polys[-1].degree() > 0 and len(fri_layers[-1]) > 1:  # agrego condicion len(fri_layers[-1])>1
        beta = channel.receive_random_field_element()
        next_poly, next_domain, next_layer = next_fri_layer(fri_polys[-1], fri_domains[-1], beta)
        fri_polys.append(next_poly)
        fri_domains.append(next_domain)
        fri_layers.append(next_layer)
        fri_merkles.append(MerkleTree(next_layer))
        channel.send(fri_merkles[-1].root)
    channel.send(str(fri_polys[-1].poly[0]))
    return fri_polys, fri_domains, fri_layers, fri_merkles


# add fri_layers, fri_merkles
def decommit_on_fri_layers(idx, channel, fri_layers, fri_merkles):
    for layer, merkle in zip(fri_layers[:-1], fri_merkles[:-1]):
        length = len(layer)
        idx = idx % length
        sib_idx = (idx + length//2) % length
        channel.send(str(layer[idx]))
        channel.send(str(merkle.get_authentication_path(idx)))
        channel.send(str(layer[sib_idx]))
        channel.send(str(merkle.get_authentication_path(sib_idx)))
    # Send the element in the last FRI layer.
    channel.send(str(fri_layers[-1][0]))


def decommit_on_query(idx, channel, f_eval, f_merkle, fri_layers, fri_merkles):
    # Send elements and authentication pathes for f(x), f(gx) and f(g^2x) over the channel.
    # chequear si esto es siempre asi o depende de las restricciones
    channel.send(str(f_eval[idx]))
    channel.send(str(f_merkle.get_authentication_path(idx)))
    channel.send(str(f_eval[idx + 8]))
    channel.send(str(f_merkle.get_authentication_path(idx + 8)))
    channel.send(str(f_eval[idx + 16]))
    channel.send(str(f_merkle.get_authentication_path(idx + 16)))
    decommit_on_fri_layers(idx, channel, fri_layers, fri_merkles)


# Agrego length, esto es large_domain_size - 1
# El 16 depende de la funcion anterior, ver si esto es siempre asi.
def decommit_fri(channel, f_eval, f_merkle, fri_layers, fri_merkles, length):
    for query in range(3):
        idx = channel.receive_random_int(0, length-16)
        decommit_on_query(idx, channel, f_eval, f_merkle, fri_layers, fri_merkles)
