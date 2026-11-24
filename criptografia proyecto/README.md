# Simulador de ataques criptográficos

Herramienta educativa en Python que demuestra cómo se vulneran algoritmos de cifrado
mediante **fuerza bruta**, **ataque de diccionario** y **análisis de frecuencias**,
midiendo el tiempo y el número de intentos de cada ataque.

> Uso exclusivamente educativo. Las claves son deliberadamente débiles.

---

## 1. Estructura del proyecto

```
simulador_ataques_criptograficos/
├── main.py            # Menú interactivo en consola (punto de entrada)
├── cifradores.py      # Algoritmos: César, XOR y AES-128 (clave débil)
├── ataques.py         # Motores de ataque y medición de métricas
├── diccionario.txt    # Lista de contraseñas comunes de ejemplo
├── requirements.txt   # Dependencias (pycryptodome)
└── README.md          # Esta guía
```

Arquitectura modular: `cifradores.py` no sabe nada de ataques, y `ataques.py` solo
recibe texto cifrado. `main.py` es el único que une ambos mundos. Así, agregar un
algoritmo nuevo no obliga a tocar los ataques.

---

## 2. Instalación

Requisitos: **Python 3.9 o superior**.

```bash
pip install -r requirements.txt
```

Solo se necesita una librería externa, `pycryptodome`, para AES. César, XOR y los
ataques usan únicamente la biblioteca estándar de Python.

---

## 3. Ejecución

```bash
python main.py
```

Menú principal:

1. **Generar un cifrado de demostración**: eliges algoritmo, texto y clave. El
   simulador muestra la clave real y el cifrado, y lo guarda para atacarlo luego.
2. **Atacar un texto cifrado**: usa el último cifrado generado o pega uno propio,
   elige el método y ve el resultado con las métricas.
3. **Explicación de los ataques**: resumen en pantalla.
4. **Salir**.

---

## 4. Casos de prueba

Cada caso indica qué escribir en el menú. Los resultados son los que se obtuvieron
al probar el proyecto.

### Caso 1: César por fuerza bruta (cifrado de ejemplo ya calculado)

Atacar un texto pegado manualmente:

- Menú **2** → algoritmo **1** (César) → no hay cifrado guardado, así que se pega:
  `JQ XJHWJYT IJ QF ANIF`
- Método **1** (Fuerza bruta)

Resultado esperado: clave **5**, texto **EL SECRETO DE LA VIDA**, **6 intentos**.

### Caso 2: César por análisis de frecuencias

- Menú **1** → algoritmo **1** → texto:
  `La criptografia es el arte de proteger la informacion mediante codigos. Durante siglos, los gobiernos y los ejercitos usaron mensajes secretos para comunicarse con sus aliados.`
  → desplazamiento **9**
- Menú **2** → algoritmo **1** → responder **s** → método **2** (Análisis de frecuencias)

Resultado esperado: clave **9**, **26 intentos**. Este método necesita textos largos
para ser fiable; con textos de pocas palabras puede fallar.

### Caso 3: XOR por fuerza bruta

- Menú **1** → algoritmo **2** (XOR) → texto `el secreto de la vida` → clave `k7`
- Menú **2** → algoritmo **2** → responder **s** → método **1** (Fuerza bruta)

Resultado esperado: clave **k7**, **7244 intentos**, tiempo menor a 0,05 s.

### Caso 4: XOR por diccionario

- Menú **1** → algoritmo **2** → texto `el secreto de la vida` → clave `clave`
- Menú **2** → algoritmo **2** → responder **s** → método **2** (Ataque de diccionario)

Resultado esperado: clave **clave**, **7 intentos** (es la séptima palabra de `diccionario.txt`).

### Caso 5: AES-128 por fuerza bruta (PIN de 4 dígitos)

- Menú **1** → algoritmo **3** (AES) → texto `el secreto de la vida` → clave `1234`
- Menú **2** → algoritmo **3** → responder **s** → método **1** (Fuerza bruta)

Resultado esperado: clave **1234**, **2345 intentos**, tiempo de unas decenas de milisegundos.

### Caso 6: AES-128 por diccionario

- Menú **1** → algoritmo **3** → texto `el secreto de la vida` → clave `clave`
- Menú **2** → algoritmo **3** → responder **s** → método **2** (Ataque de diccionario)

Resultado esperado: clave **clave**, **7 intentos**.

### Caso 7 (prueba de límite): clave fuera del espacio de búsqueda

- Menú **1** → algoritmo **3** → texto `el secreto de la vida` → clave `abc`
- Menú **2** → algoritmo **3** → **s** → método **1**

Resultado esperado: **no encontrada**. La fuerza bruta solo prueba claves numéricas
de hasta 4 dígitos, así que una clave con letras queda fuera. Es útil para explicar
que el éxito de un ataque depende de su espacio de búsqueda.

---

## 5. Cómo funciona cada ataque

### Fuerza bruta
Genera **todas** las claves de un espacio definido y prueba cada una. Para cada
candidato se descifra el texto y se verifica si parece español (ver verificador).

| Algoritmo | Espacio de búsqueda | Tamaño |
|-----------|---------------------|--------|
| César     | Desplazamientos 0–25 | 26 |
| XOR       | Caracteres ASCII imprimibles, longitud 1–2 | 9 120 |
| AES-128   | PIN numéricos de 1–4 dígitos | 11 110 |

### Ataque de diccionario
Prueba solo las palabras de `diccionario.txt`, que son contraseñas que la gente
usa con frecuencia. Es mucho más rápido que la fuerza bruta, pero **solo tiene
éxito si la clave está en la lista**. Para AES se omiten palabras de más de
16 bytes, porque AES-128 no admite claves más largas.

### Análisis de frecuencias (solo César)
1. Cuenta cuántas veces aparece cada letra en el cifrado.
2. Para cada desplazamiento, compara esa distribución con la del español
   usando el **test chi-cuadrado**: suma `(observada − esperada)² / esperada`.
3. Elige el desplazamiento con el valor más bajo, porque es el más parecido al español.

En español la E aparece en torno al 12 % de las letras; por eso, si la letra más
frecuente del cifrado es X, lo más probable es que X represente a la E.

### Verificador de texto válido
Todos los ataques usan la misma función para decidir si un descifrado es correcto.
Un candidato se acepta si cumple tres condiciones:

1. Se decodifica como UTF-8.
2. Al menos el 90 % de sus caracteres son letras, números o espacios.
3. Al menos el 25 % de sus palabras están en la lista de palabras comunes
   (`de`, `la`, `el`, `que`, `y`, `en`, …).

### Métricas
- **Tiempo**: `time.perf_counter()`, que es un reloj de alta precisión. Se muestra en
  segundos y milisegundos.
- **Intentos**: cada candidato probado cuenta como un intento.
- **Velocidad**: intentos por segundo, para comparar algoritmos y métodos.

---

## 6. Limitaciones conocidas

- **Falsos positivos en XOR.** Como XOR es lineal, invertir las mayúsculas de la
  clave produce el texto con mayúsculas invertidas, que también puede parecer
  válido. Por eso conviene probar con claves que incluyan dígitos o símbolos.
- **Textos cortos.** El verificador necesita palabras comunes. Un texto como
  `HOLA MUNDO` no contiene ninguna, así que no se reconoce.
- **Análisis de frecuencias.** Solo funciona bien con textos largos y solo para
  César. No sirve para el cifrado por sustitución general.
- **AES en ECB.** El modo ECB es inseguro: bloques iguales producen cifrados
  iguales. Se usa aquí solo con fines didácticos.
- **Claves débiles.** Los ataques solo son viables porque la clave es corta. Con
  una clave aleatoria de 128 bits, la fuerza bruta sería inviable.

---

## 7. Guía de mantenimiento

**Agregar un algoritmo nuevo** (por ejemplo, Vigenère):

1. En `cifradores.py`, escribir `vigenere_cifrar` y `vigenere_descifrar`.
2. En `ataques.py`, escribir `fuerza_bruta_vigenere` usando el verificador
   `parece_texto_espanol` y el mismo `ResultadoAtaque`.
3. En `main.py`, agregar el algoritmo a `ALGORITMOS`, a `METODOS` y a `ejecutar_ataque`.

**Ampliar el diccionario:** agregar una palabra por línea en `diccionario.txt`.
Las líneas que empiezan con `#` se ignoran.

---

## 8. Despliegue y entrega

Para entregar el proyecto, comprimir la carpeta:

```bash
zip -r simulador_ataques_criptograficos.zip simulador_ataques_criptograficos/
```

Para la presentación, ejecutar `python main.py` y seguir los casos 1 y 5 del punto 4.
El caso 1 demuestra un ataque inmediato, y el caso 5 muestra el tiempo medido.
