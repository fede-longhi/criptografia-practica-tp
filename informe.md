# Trabajo Práctico: Pruebas de Validez

Para realizar el trabajo practico hemos desarrollado 4 estrategias descriptas en el enunciado del mismo. El trabajo fue realizado en python siguiendo los lineamientos de los tutoriales de stark-101.

## Autores

- Guillermo Mario Narvaja - Padrón 76.710
- Federico Rodríguez Longhi 93.336

## Instrucciones de ejecución
* `python main.py` : corre las diferentes estrategias e imprime los resultados.
* `pytest estrategia_n_tests.py` : corre los tests correspondientes. (Hay que tener instalado pytest)

## Desarrollo
A continuación detallamos los resultados de las distintas estrategias. Las mismas se encuentran implementadas en los correspondientes archivos con el nombre estrategia_n.py, siendo n el numero de la estrategia. En cada archivo se puede ver la documentación al principio del mismo donde detalla el desarrollo de la estrategia con los diferentes parametros y constraints correspondientes.

Además cada una tiene un archivo de pruebas donde se verifica paso a paso la correcta implementación de cada método.

---

### Estrategia 1
$a_0 = 2$\
$a_{n+1} = a_n^8$

#### Resultados
* Tamaño de la traza: 21
* Tamaño del grupo: 32
* Tamaño del dominio de evaluación: 256
* Tamaño de la prueba: 660
* Tamaño de la prueba incluyendo 10 queries: 59895
* Tiempo promedio de ejecución: 0.05004346999921836

---

### Estrategia 2
$a_0 = 2$\
$a_{n+1} = a_n^2$

#### Resultados
* Tamaño de la traza: 61
* Tamaño del grupo: 64
* Tamaño del dominio de evaluación: 64
* Tamaño de la prueba: 529
* Tamaño de la prueba incluyendo 10 queries: 37232
* Tiempo promedio de ejecución: 0.06114284000359475

---

### Estrategia 3
$a_0 = 2$\
$a_{2n+1} = (a_{2n})^2$\
$a_{2n} = (a_{2n-1})^4$

#### Resultados
* Tamaño de la traza: 20
* Tamaño del grupo: 32
* Tamaño del dominio de evaluación: 128
* Tamaño de la prueba: 595
* Tamaño de la prueba incluyendo 10 queries: 47922
* Tiempo promedio de ejecución: 0.03636028000037186

---

### Estrategia 4
Dos columnas

#### Resultados
* Tamaño de la traza: 10 (doble traza)
* Tamaño del grupo: 16
* Tamaño del dominio de evaluación: 64
* Tamaño de la prueba A: 531
* Tamaño de la prueba B: 530
* Tamaño de la prueba total: 1061
* Tamaño de la prueba total incluyendo 10 queries: 74519
* Tiempo promedio de ejecución: 0.04752717000083066

---

## Verificación

Además de la generación de las pruebas, hicimos la verificación tal como la hubiera hecho un verifier que sólo recibe los mensajes en el canal.

## Conclusión
De todas las estrategias, las más sencillas de implementar, por lo menos en este primer acercamiento, fueron las primeras dos, ya que las constraints eran simples y faciles de describir. En cuánto a tiempos, podemos decir que la estrategia 3 es la más rápida, seguida de la 4. Sin embargo, esta última se puede paralelizar haciendo más rápida la ejecución, lo que podría llegar a ser una ventaja. En cuánto a tamaños y memoria, vemos que la estrategia 2 es la peor de todas, teniendo la traza más grande de 61 elementos.
