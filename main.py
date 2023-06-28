import timeit

import estrategia_1 as E1
import estrategia_2 as E2
import estrategia_3 as E3
import estrategia_4 as E4

TIMEIT_COUNT = 10
QUERIES = 10


def calculate_proof_len(channel):
    proofs = [p[len("send:"):] for p in channel.proof if p.startswith("send:")]
    return len(",".join(proofs))


def print_E_performance(name, number, E):
    # Estrategia 1
    print(name)

    print(f"Tamaño de la traza: {E.TRACE_SIZE + 1}")
    print(f"Tamaño del grupo: {E.GROUP_SIZE}")
    print(f"Tamaño del dominio de evaluación: {E.EVAL_SIZE}")

    proof = E.make_proof()
    channel = proof[0]
    print(f"Tamaño de la prueba: {calculate_proof_len(channel)}")

    for i in range(QUERIES):
        E.add_query(*proof)

    print(f"Tamaño de la prueba incluyendo {QUERIES} queries: {calculate_proof_len(channel)}")

    exec_time = timeit.timeit(
        f"import estrategia_{number} as E{number}; E{number}.make_proof()",
        number=TIMEIT_COUNT
    )
    print(f"Tiempo promedio de ejecución: {exec_time / TIMEIT_COUNT}")


def print_E4_performance():
    # Estrategia 4
    print("Estrategia 4")

    print(f"Tamaño de la traza: {E4.TRACE_SIZE + 1} (doble traza)")
    print(f"Tamaño del grupo: {E4.GROUP_SIZE}")
    print(f"Tamaño del dominio de evaluación: {E4.EVAL_SIZE}")

    trace_a, trace_b = E4.generate_trace()
    proof_a = E4.make_proof_a(trace_a)
    channel_a = proof_a[0]
    print(f"Tamaño de la prueba A: {calculate_proof_len(channel_a)}")

    proof_b = E4.make_proof_b(trace_b)
    channel_b = proof_b[0]
    print(f"Tamaño de la prueba B: {calculate_proof_len(channel_b)}")
    total = calculate_proof_len(channel_a) + calculate_proof_len(channel_b)
    print(f"Tamaño de la prueba total: {total}")

    for i in range(QUERIES):
        E4.add_query(*proof_a)

        E4.add_query(*proof_b)

    total = calculate_proof_len(channel_a) + calculate_proof_len(channel_b)
    print(f"Tamaño de la prueba total incluyendo {QUERIES} queries: {total}")

    exec_time = timeit.timeit(
        "import estrategia_4 as E4; trace_a, trace_b = E4.generate_trace();"
        "E4.make_proof_a(trace_a); E4.make_proof_b(trace_b)",
        number=TIMEIT_COUNT
    )
    print(f"Tiempo promedio de ejecución: {exec_time / TIMEIT_COUNT}")


print_E_performance("Estrategia 1", 1, E1)
print_E_performance("Estrategia 2", 2, E2)
print_E_performance("Estrategia 3", 3, E3)
print_E4_performance()
