from field import FieldElement
from polynomial import interpolate_poly, X, prod
from channel import Channel
from merkle import MerkleTree
from utils import CP_eval

# Constants
# trace size
# larger domain size (porque lo multiplicamos por 8...)
# constraints -> ver lo de blowup factor

# Traza
trace_size = 3*2**3 # 24
a = [FieldElement(2)]  # a0 = 2
while len(a) < trace_size-1:
    a.append(a[-1]**8)

# Generando grupo de tamaño trace_size
g = FieldElement.generator()**(2**27) # 3*2**30 / 2**27 = 3*2**3 (trace_size)
G = [g ** i for i in range(trace_size)]

print(g.is_order(trace_size)) # chequeo el orden del generador

# Interpolando
f = interpolate_poly(G[:-1], a)
print(f(1)) # chequeando primera constraint 


# Evaluating on a larger domain
larger_domain_size = trace_size*8 # 192
w = FieldElement.generator()
h = w ** ((3*2**30)//(larger_domain_size))
H = [h**i for i in range(larger_domain_size)]
eval_domain = [w*x for x in H]

f_eval = [f(d) for d in eval_domain]

# Commitments
f_merkle = MerkleTree(f_eval)
print(f_merkle.root)

channel = Channel()
channel.send(f_merkle.root)

print(channel.proof) # proof so far

# First constraint
numer0 = f - 2
denom0 = X - 1 # X - g^0

p0 = numer0/denom0

# Second constraint -> hay segunda constraint?

# Third constraint -> si no hay segunda esta deberia ser segunda
numer2 = f(g*X) - f(X)**8
denom2 = ((X**trace_size) - 1) / prod([X - g**i for i in range(20, trace_size)]) # esto hay que chequear

p2 = numer2/denom2

print('deg p0: ', p0.degree())
print('deg p2: ', p2.degree()) # este esta mal tiene que dar < 24 (trace size)

polynomials = [p0, p2]

# Commit on the composition polynomial

channel = Channel() # ver si hay que crearlo de nuevo
CP_merkle = MerkleTree(CP_eval(channel, polynomials, eval_domain))
channel.send(CP_merkle.root)