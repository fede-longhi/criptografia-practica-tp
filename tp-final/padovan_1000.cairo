func main() {
    let result: felt = pado(1000);

    assert result = 95947899754891883718198635265406591795729388343961013326205746660648433358757497113284765865744376976832226705511219598880;
    ret;
}

func pado(n) -> (res: felt) {
    return pado_rec(1, 1, 1, n - 1);
}

func pado_rec(first_element, second_element, third_element, n) -> (res: felt) {
    jmp pado_body if n != 0;
    tempvar result = second_element;
    return (second_element,);

    pado_body:
    tempvar y = first_element + second_element;
    return pado_rec(second_element, third_element, y, n - 1);
}

