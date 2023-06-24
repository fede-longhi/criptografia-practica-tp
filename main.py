from field import FieldElement

print(FieldElement(3221225472))

a = [FieldElement(2)]
while len(a)<20:
    a.append(a[-1]**8)

g = FieldElement.generator()**(3*20)
G = [g ** i for i in range(21)]
print(G)
assert(g.is_order())