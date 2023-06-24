from channel import Channel

def get_CP(channel, polynomials):
    CP = 0
    for pol in polynomials:
        CP += Channel.receive_random_field_element(channel) * pol
    return CP

def CP_eval(channel, polynomials, eval_domain):
    CP = get_CP(channel, polynomials)
    return [CP(x) for x in eval_domain]