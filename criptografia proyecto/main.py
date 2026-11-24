
from cifradores import cesar_cifrar, xor_cifrar, aes_cifrar
from ataques import (
    fuerza_bruta_cesar,
    analisis_frecuencias_cesar,
    fuerza_bruta_xor,
    ataque_diccionario_xor,
    fuerza_bruta_aes,
    ataque_diccionario_aes,
    cargar_diccionario,
)

# Algoritmos disponibles (opción del menú -> nombre)
ALGORITMOS = {"1": "César", "2": "XOR", "3": "AES"}

# Métodos de ataque que admite cada algoritmo
METODOS = {
    "César": ["Fuerza bruta", "Análisis de frecuencias"],
    "XOR": ["Fuerza bruta", "Ataque de diccionario"],
    "AES": ["Fuerza bruta", "Ataque de diccionario"],
}

# Último cifrado generado en la sesión, para atacarlo sin volver a pegarlo
ultimo_cifrado = None


# ---------------------------------------------------------------------------
# Utilidades de menú
# ---------------------------------------------------------------------------
def pedir_opcion(mensaje, opciones):
    """Repite la pregunta hasta que el usuario escriba una opción válida."""
    while True:
        valor = input(mensaje).strip()
        if valor in opciones:
            return valor
        print(f"  Opción no válida. Elige entre: {', '.join(opciones)}")


def mostrar_menu_principal():
    print("\n" + "=" * 58)
    print("        SIMULADOR DE ATAQUES CRIPTOGRÁFICOS")
    print("=" * 58)
    print("  1. Generar un cifrado de demostración")
    print("  2. Atacar un texto cifrado")
    print("  3. Explicación de los ataques")
    print("  4. Salir")
    print("-" * 58)


# ---------------------------------------------------------------------------
# Opción 1: generar un cifrado de demostración
# ---------------------------------------------------------------------------
def generar_cifrado():
    """Cifra un texto con el algoritmo elegido y lo guarda como último cifrado."""
    global ultimo_cifrado

    print("\nAlgoritmos:  1) César   2) XOR   3) AES-128 (clave débil)")
    nombre = ALGORITMOS[pedir_opcion("Elige el algoritmo: ", ["1", "2", "3"])]

    texto = input("Texto en claro: ").strip()
    if not texto:
        print("  El texto no puede estar vacío.")
        return

    try:
        if nombre == "César":
            clave = str(int(input("Desplazamiento (0-25): ")))
            cifrado = cesar_cifrar(texto, int(clave))
        elif nombre == "XOR":
            clave = input("Clave XOR (ej. k7): ").strip()
            if not clave:
                print("  La clave no puede estar vacía.")
                return
            cifrado = xor_cifrar(texto, clave)
        else:
            clave = input("Clave AES corta (máx. 16 caracteres, ej. 1234): ").strip()
            if not clave:
                print("  La clave no puede estar vacía.")
                return
            cifrado = aes_cifrar(texto, clave)
    except ValueError as error:
        print(f"  Error: {error}")
        return

    ultimo_cifrado = {"algoritmo": nombre, "cifrado": cifrado, "clave": clave}

    print("\n  Cifrado generado correctamente")
    print(f"  Algoritmo : {nombre}")
    print(f"  Clave real: {clave}   <- la que el ataque debe descubrir")
    print(f"  Cifrado   : {cifrado}")
    print("  (Quedó guardado: usa la opción 2 para atacarlo)")


# ---------------------------------------------------------------------------
# Opción 2: atacar un texto cifrado
# ---------------------------------------------------------------------------
def atacar():
    print("\nAlgoritmos:  1) César   2) XOR   3) AES-128")
    nombre = ALGORITMOS[pedir_opcion("Algoritmo a atacar: ", ["1", "2", "3"])]

    # Si hay un cifrado guardado del mismo algoritmo, se puede reutilizar
    clave_real = None
    if ultimo_cifrado and ultimo_cifrado["algoritmo"] == nombre:
        usar = input("¿Atacar el último cifrado generado? (s/n): ").strip().lower()
        if usar == "s":
            cifrado = ultimo_cifrado["cifrado"]
            clave_real = ultimo_cifrado["clave"]

    if clave_real is None:
        formato = "texto cifrado" if nombre == "César" else "texto cifrado en hexadecimal"
        cifrado = input(f"Pega el {formato}: ").strip()

    metodos = METODOS[nombre]
    print("\nMétodos disponibles:")
    for numero, metodo in enumerate(metodos, start=1):
        print(f"  {numero}. {metodo}")
    metodo = metodos[int(pedir_opcion("Método: ", [str(n) for n in range(1, len(metodos) + 1)])) - 1]

    print(f"\nEjecutando {metodo} sobre {nombre}... (puede tardar unos segundos)")
    try:
        resultado = ejecutar_ataque(nombre, metodo, cifrado)
    except ValueError:
        print("  Error: el texto cifrado no es hexadecimal válido.")
        return
    except FileNotFoundError:
        print("  Error: no se encontró el archivo diccionario.txt.")
        return

    mostrar_resultado(resultado, clave_real)


def ejecutar_ataque(nombre, metodo, cifrado):
    """Llama al motor de ataque adecuado según el algoritmo y el método."""
    if nombre == "César":
        if metodo == "Fuerza bruta":
            return fuerza_bruta_cesar(cifrado)
        return analisis_frecuencias_cesar(cifrado)

    if nombre == "XOR":
        if metodo == "Fuerza bruta":
            return fuerza_bruta_xor(cifrado, longitud_max=2)
        return ataque_diccionario_xor(cifrado, cargar_diccionario())

    # AES
    if metodo == "Fuerza bruta":
        return fuerza_bruta_aes(cifrado, longitud_max=4)
    return ataque_diccionario_aes(cifrado, cargar_diccionario())


def mostrar_resultado(resultado, clave_real=None):
    """Muestra el resultado y las métricas: tiempo exacto e intentos."""
    print("\n" + "-" * 58)
    print("  RESULTADO DEL ATAQUE")
    print("-" * 58)
    print(f"  Método           : {resultado.metodo}")
    print(f"  Algoritmo        : {resultado.algoritmo}")
    if resultado.encontrado:
        print(f"  Clave encontrada : {resultado.clave}")
        print(f"  Texto recuperado : {resultado.texto}")
    else:
        print("  No se encontró la clave en el espacio de búsqueda.")
    if clave_real is not None:
        print(f"  Clave real       : {clave_real}")
    print(f"  Intentos         : {resultado.intentos:,}")
    print(f"  Tiempo           : {resultado.tiempo_seg:.4f} s ({resultado.tiempo_seg * 1000:.2f} ms)")
    if resultado.tiempo_seg > 0:
        print(f"  Velocidad        : {resultado.intentos / resultado.tiempo_seg:,.0f} intentos/s")
    print("-" * 58)


# ---------------------------------------------------------------------------
# Opción 3: explicación breve
# ---------------------------------------------------------------------------
def explicar():
    print("""
  FUERZA BRUTA
    Prueba todas las claves de un espacio definido hasta encontrar
    el texto con sentido. Es lenta cuanto más larga es la clave.

  ATAQUE DE DICCIONARIO
    Prueba solo las palabras de una lista de contraseñas comunes.
    Es rápido si la clave está en la lista, y falla si no lo está.

  ANÁLISIS DE FRECUENCIAS (solo César)
    En español, la letra E aparece ~12% de las veces. Si la letra más
    frecuente del cifrado es X, probablemente X corresponda a la E.
    Se elige el desplazamiento cuya distribución se parece más al español.

  Métricas: se mide el tiempo con time.perf_counter() y se cuenta
  cada candidato probado como un intento.
""")


# ---------------------------------------------------------------------------
# Bucle principal
# ---------------------------------------------------------------------------
def main():
    while True:
        mostrar_menu_principal()
        opcion = pedir_opcion("Selecciona una opción: ", ["1", "2", "3", "4"])
        if opcion == "1":
            generar_cifrado()
        elif opcion == "2":
            atacar()
        elif opcion == "3":
            explicar()
        else:
            print("¡Hasta luego!")
            break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nPrograma interrumpido por el usuario.")
