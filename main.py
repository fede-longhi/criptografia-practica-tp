import time
from field import FieldElement
from polynomial import interpolate_poly, X, prod
from channel import Channel
from merkle import MerkleTree
from utils import *

# Constantes Generales
group_order = 3 * 2 ** 30
assert group_order == FieldElement.k_modulus - 1

RESULT = FieldElement(2)**(8**20)

# Estrategia 1

start = time.time()
start_all = start
print("Generating the trace...")

# Traza
group_size = 24 # 3*2**3 = 24
trace_size = 21
larger_domain_multiplier = 8


trace = generate_trace_e1(trace_size)
assert trace[-1] == RESULT, 'el ultimo elemento no corresponde con el resultado'

# Generando grupo de tamaño group_size
g, G = generate_group_and_generator(group_order, group_size)

# Interpolando
f = interpolate_poly(G[:trace_size], trace)

# Evaluating on a larger domain
f_eval, eval_domain = generate_larger_domain_evaluation(group_size*larger_domain_multiplier, group_order, f)

# Commitments
f_merkle = MerkleTree(f_eval)

channel = Channel()
channel.send(f_merkle.root)

print(f'{time.time() - start}s')
start = time.time()
print("Generating the composition polynomial and the FRI layers...")

polynomials = make_constraint_polys_e1(f, g, G, RESULT, group_size, trace_size)

# Commit on the composition polynomial

# channel = Channel() # ver si hay que crearlo de nuevo
CP = get_CP(channel, polynomials)
CP_eval = get_CP_eval(CP, eval_domain)
CP_merkle = MerkleTree(CP_eval)
channel.send(CP_merkle.root)

# Part 3
fri_polys, fri_domains, fri_layers, fri_merkles = FriCommit(CP, eval_domain, CP_eval, CP_merkle, channel)

print(f'{time.time() - start}s')
start = time.time()

print("Generating queries and decommitments...")

length = group_size*larger_domain_multiplier - 1
decommit_fri(channel, f_eval, f_merkle, fri_layers, fri_merkles, length)

print (channel.state)

print(f'{time.time() - start}s')
start = time.time()
print(f'Overall time: {time.time() - start_all}s')
print(f'Uncompressed proof length in characters: {len(str(channel.proof))}')