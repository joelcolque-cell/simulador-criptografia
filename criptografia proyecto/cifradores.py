"""
cifradores.py
-------------
Contiene los algoritmos de cifrado que el simulador va a ATACAR:

  1. Cifrado César : sustitución monoalfabética (desplaza cada letra N posiciones).
  2. Cifrado XOR   : operación bit a bit con una clave que se repite.
  3. AES-128       : cifrado moderno. Aquí se usa con claves CORTAS (débiles)
                     para que el ataque sea posible en segundos.

Nota: AES necesita la librería externa 'pycryptodome' (pip install pycryptodome).
"""

import unicodedata

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

ALFABETO = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
TAMANO_CLAVE_AES = 16  # AES-128 usa claves de 16 bytes

# Utilidad común

def normalizar(texto):
    """
    Pasa el texto a MAYÚSCULAS y elimina tildes (á -> A, ñ -> N).
    César solo trabaja con las 26 letras A-Z, por eso se normaliza primero.
    """
    descompuesto = unicodedata.normalize("NFKD", texto)
    sin_tildes = "".join(c for c in descompuesto if not unicodedata.combining(c))
    return sin_tildes.upper()



# 1. CIFRADO CÉSAR

def cesar_cifrar(texto, desplazamiento):
    """
    Cada letra se reemplaza por la que está 'desplazamiento' posiciones más
    adelante en el alfabeto (con la vuelta Z -> A).
    Ejemplo con desplazamiento 3: A -> D, B -> E, ...
    """
    resultado = []
    for caracter in normalizar(texto):
        if caracter in ALFABETO:
            indice = (ALFABETO.index(caracter) + desplazamiento) % 26
            resultado.append(ALFABETO[indice])
        else:
            resultado.append(caracter)  # espacios, números y signos se conservan
    return "".join(resultado)


def cesar_descifrar(texto, desplazamiento):
    """Descifrar es cifrar con el desplazamiento contrario."""
    return cesar_cifrar(texto, -desplazamiento)



# 2. CIFRADO XOR

def xor_bytes(datos, clave):
    """
    Aplica XOR byte a byte entre los datos y la clave.
    Si la clave es más corta que los datos, se repite (clave cíclica).
    """
    return bytes(d ^ clave[i % len(clave)] for i, d in enumerate(datos))


def xor_cifrar(texto, clave):
    """
    Cifra con XOR. El resultado se devuelve en hexadecimal porque
    los bytes resultantes no siempre son caracteres legibles.
    """
    return xor_bytes(texto.encode("utf-8"), clave.encode("utf-8")).hex()


def xor_descifrar(cifrado_hex, clave):
    """XOR es simétrico: cifrar y descifrar son la misma operación."""
    datos = bytes.fromhex(cifrado_hex)
    return xor_bytes(datos, clave.encode("utf-8")).decode("utf-8", errors="replace")



# 3. AES-128 con claves débiles

def preparar_clave(clave_corta):
    """
    AES exige una clave de 16 bytes. Si la clave es más corta (p. ej. "1234"),
    se completa con ceros a la derecha. Esa clave es DÉBIL: su espacio de
    búsqueda es minúsculo comparado con las 2^128 claves posibles de AES-128.
    """
    bytes_clave = clave_corta.encode("utf-8")
    if len(bytes_clave) > TAMANO_CLAVE_AES:
        raise ValueError("La clave no puede superar 16 bytes para AES-128.")
    return bytes_clave.ljust(TAMANO_CLAVE_AES, b"\x00")


def aes_cifrar(texto, clave_corta):
    """
    Cifra con AES-128 en modo ECB.
    ECB es un modo INSEGURO que se usa solo con fines didácticos.
    En sistemas reales se usan modos como CBC o GCM.
    """
    cipher = AES.new(preparar_clave(clave_corta), AES.MODE_ECB)
    return cipher.encrypt(pad(texto.encode("utf-8"), AES.block_size)).hex()


def aes_descifrar(cifrado_hex, clave_corta):
    """
    Intenta descifrar con la clave dada.
    Devuelve los bytes del texto, o None si la clave es incorrecta
    (en ese caso el relleno PKCS#7 resulta inválido).
    """
    try:
        cipher = AES.new(preparar_clave(clave_corta), AES.MODE_ECB)
        return unpad(cipher.decrypt(bytes.fromhex(cifrado_hex)), AES.block_size)
    except ValueError:
        return None
