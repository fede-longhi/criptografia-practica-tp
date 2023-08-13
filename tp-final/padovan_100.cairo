func main() {
    let result: felt = pado(100);

    assert result = 1177482265857;
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

