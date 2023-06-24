from field import FieldElement

trace_size = 3*2**3
a = [FieldElement(2)]  # a0 = 2
while len(a) < trace_size:
    a.append(a[-1]**8)

g = FieldElement.generator()**(2**27) # 3*2**30 / 2**27 = 3*2**3 (trace_size)
G = [g ** i for i in range(trace_size)]

print(g.is_order(trace_size)) # chequeo el orden del generador

