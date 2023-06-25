import time
from field import FieldElement
from polynomial import interpolate_poly, X, prod
from channel import Channel
from merkle import MerkleTree
from utils import get_CP, get_CP_eval, FriCommit, decommit_fri, generate_group

# Constants
# trace size
# larger domain size (porque lo multiplicamos por 8...)
# constraints -> ver lo de blowup factor

start = time.time()
start_all = start
print("Generating the trace...")

# Traza
group_size = 24 # 3*2**3 = 24
group_order = 3 * 2 ** 30

trace_size = 21

RESULT = FieldElement(2)**(8**20)

a = [FieldElement(2)]
while len(a) < trace_size:
    a.append(a[-1]**8)

assert a[-1] == RESULT, 'el ultimo elemento no corresponde con el resultado'

# Generando grupo de tamaño group_size

g = FieldElement.generator()**(group_order//group_size) # 3*2**30 / 2**27 = 3*2**3 (trace_size)
G = generate_group(group_order, group_size)
# g = FieldElement.generator()**(group_order//group_size) # 3*2**30 / 2**27 = 3*2**3 (trace_size)
# G = [g ** i for i in range(group_size)]
# assert len(G) == len(a)

# Interpolando
f = interpolate_poly(G[:trace_size], a)
print('f(1): ', f(1)) # chequeando primera constraint 


# Evaluating on a larger domain
larger_domain_size = group_size*8 # 192
w = FieldElement.generator()
h = w ** ((3*2**30)//(larger_domain_size))
H = [h**i for i in range(larger_domain_size)]
eval_domain = [w*x for x in H]

f_eval = [f(d) for d in eval_domain]

# Commitments
f_merkle = MerkleTree(f_eval)

channel = Channel()
channel.send(f_merkle.root)

print(f'{time.time() - start}s')
start = time.time()
print("Generating the composition polynomial and the FRI layers...")

# First constraint
numer0 = f - FieldElement(2)
denom0 = X - FieldElement(1) # X - g^0

p0 = numer0/denom0

# Second constraint -> hay segunda constraint?
numer1 = f - RESULT
denom1 = X - G[20]
p1 = numer1 / denom1

# Third constraint -> si no hay segunda esta deberia ser segunda
numer2 = f(g*X) - f(X)**8
denom2 = ((X**group_size) - FieldElement(1)) / prod([X - g**i for i in range(trace_size-1, group_size)]) # esto hay que chequear

p2 = numer2/denom2

print('deg p0: ', p0.degree())
print('deg p1: ', p1.degree())
print('deg p2: ', p2.degree())

polynomials = [p0, p1, p2]

# Commit on the composition polynomial

# channel = Channel() # ver si hay que crearlo de nuevo
CP = get_CP(channel, polynomials)
CP_eval = get_CP_eval(CP, eval_domain)
CP_merkle = MerkleTree(CP_eval)
channel.send(CP_merkle.root)

# Part 3
fri_polys, fri_domains, fri_layers, fri_merkles = FriCommit(CP, eval_domain, CP_eval, CP_merkle, channel)
print(channel.proof)


print(f'{time.time() - start}s')
start = time.time()

print("Generating queries and decommitments...")

length = larger_domain_size - 1
decommit_fri(channel, f_eval, f_merkle, fri_layers, fri_merkles, length)

print(f'{time.time() - start}s')
start = time.time()
print(channel.proof)
print(f'Overall time: {time.time() - start_all}s')
print(f'Uncompressed proof length in characters: {len(str(channel.proof))}')