"""
ataques.py
----------
Motores de ataque del simulador:

  - Fuerza bruta      : prueba todas las claves de un espacio definido.
  - Diccionario       : prueba palabras de una lista de contraseñas comunes.
  - Análisis de frecuencias : compara la frecuencia de letras del cifrado
                        con la frecuencia típica del español (solo César).

Todas las funciones devuelven un ResultadoAtaque con:
  si tuvo éxito, la clave, el texto recuperado, el número de intentos
  y el tiempo empleado (métricas que pide el proyecto).
"""

import itertools
import os
import re
import string
import time
from collections import Counter
from dataclasses import dataclass
from typing import Optional

from cifradores import (
    ALFABETO,
    normalizar,
    cesar_descifrar,
    xor_bytes,
    aes_descifrar,
)

# Frecuencia relativa (%) de cada letra en el español (valores aproximados)
FRECUENCIAS_ES = {
    "A": 11.53, "B": 2.22, "C": 4.02, "D": 5.01, "E": 12.18, "F": 0.69,
    "G": 1.77, "H": 0.70, "I": 6.25, "J": 0.49, "K": 0.01, "L": 4.97,
    "M": 3.16, "N": 6.71, "O": 8.68, "P": 2.51, "Q": 0.88, "R": 6.87,
    "S": 7.98, "T": 4.63, "U": 3.93, "V": 0.90, "W": 0.02, "X": 0.22,
    "Y": 0.90, "Z": 0.52,
}

# Palabras muy frecuentes en español. Si un candidato contiene alguna,
# se considera "texto real" (criterio de validación de los ataques).
PALABRAS_COMUNES = {
    "de", "la", "el", "que", "y", "en", "un", "una", "es", "los",
    "las", "para", "con", "del", "por", "se", "lo",
}

# Caracteres posibles para claves XOR: ASCII imprimible (32 a 126)
CARACTERES_CLAVE = [chr(c) for c in range(32, 127)]


@dataclass
class ResultadoAtaque:
    """Resultado de un ataque, con las métricas de rendimiento."""
    metodo: str
    algoritmo: str
    encontrado: bool
    clave: Optional[str]
    texto: Optional[str]
    intentos: int
    tiempo_seg: float


# Funciones auxiliares

def parece_texto_espanol(datos):
    """
    Verificador de candidatos. Un descifrado se acepta si:
      1) se puede decodificar como UTF-8,
      2) al menos el 90% de sus caracteres son letras, números o espacios
         (la puntuación no cuenta: el ruido binario la contiene mucho),
      3) al menos el 25% de sus palabras son palabras comunes del español.
    Devuelve el texto si es válido, o None si no lo es.
    """
    if isinstance(datos, bytes):
        try:
            texto = datos.decode("utf-8")
        except UnicodeDecodeError:
            return None
    else:
        texto = datos

    if not texto:
        return None

    legibles = sum(1 for c in texto if c.isalnum() or c.isspace())
    if legibles / len(texto) < 0.9:
        return None

    palabras = re.findall(r"[a-záéíóúñü]+", texto.lower())
    if not palabras:
        return None
    comunes = sum(1 for p in palabras if p in PALABRAS_COMUNES)
    if comunes / len(palabras) < 0.25:
        return None
    return texto


def _resultado(metodo, algoritmo, clave, texto, intentos, inicio):
    """Arma el ResultadoAtaque calculando el tiempo transcurrido."""
    return ResultadoAtaque(
        metodo=metodo,
        algoritmo=algoritmo,
        encontrado=clave is not None,
        clave=clave,
        texto=texto,
        intentos=intentos,
        tiempo_seg=time.perf_counter() - inicio,
    )


def cargar_diccionario(ruta=None):
    """Lee el archivo diccionario.txt (una palabra por línea, ignora los comentarios #)."""
    if ruta is None:
        ruta = os.path.join(os.path.dirname(os.path.abspath(__file__)), "diccionario.txt")
    with open(ruta, encoding="utf-8") as archivo:
        return [linea.strip() for linea in archivo if linea.strip() and not linea.startswith("#")]



# CÉSAR

def fuerza_bruta_cesar(cifrado):
    """
    Prueba los 26 desplazamientos posibles.
    Como César solo tiene 26 claves, el ataque es inmediato.
    """
    inicio = time.perf_counter()
    intentos = 0
    for desplazamiento in range(26):
        intentos += 1
        candidato = parece_texto_espanol(cesar_descifrar(cifrado, desplazamiento))
        if candidato is not None:
            return _resultado("Fuerza bruta", "César", str(desplazamiento), candidato, intentos, inicio)
    return _resultado("Fuerza bruta", "César", None, None, intentos, inicio)


def analisis_frecuencias_cesar(cifrado):
    """
    Análisis de frecuencias:
      1. Cuenta cuántas veces aparece cada letra en el cifrado.
      2. Para cada desplazamiento, mide qué tan parecida es la distribución
         resultante a la del español (test chi-cuadrado).
      3. Elige el desplazamiento con menor diferencia.
    Funciona mejor con textos largos (más de 100 caracteres).
    """
    inicio = time.perf_counter()
    letras = [c for c in normalizar(cifrado) if c in ALFABETO]
    if not letras:
        return _resultado("Análisis de frecuencias", "César", None, None, 0, inicio)

    total = len(letras)
    conteo = Counter(letras)
    mejor_desplazamiento, mejor_puntaje = 0, float("inf")
    intentos = 0

    for desplazamiento in range(26):
        intentos += 1
        puntaje = 0.0
        for i, letra_clara in enumerate(ALFABETO):
            # Si la clave es 'desplazamiento', la letra clara i aparece cifrada como i+desplazamiento
            letra_cifrada = ALFABETO[(i + desplazamiento) % 26]
            observada = conteo.get(letra_cifrada, 0) / total
            esperada = FRECUENCIAS_ES[letra_clara] / 100
            puntaje += (observada - esperada) ** 2 / esperada  
        if puntaje < mejor_puntaje:
            mejor_desplazamiento, mejor_puntaje = desplazamiento, puntaje

    texto = cesar_descifrar(cifrado, mejor_desplazamiento)
    return _resultado("Análisis de frecuencias", "César", str(mejor_desplazamiento), texto, intentos, inicio)



# XOR

def fuerza_bruta_xor(cifrado_hex, longitud_max=2):
    """
    Prueba todas las claves formadas por caracteres imprimibles,
    de 1 hasta 'longitud_max' caracteres.
    Con longitud 2 hay 95 + 9025 = 9120 combinaciones.
    """
    inicio = time.perf_counter()
    datos = bytes.fromhex(cifrado_hex)  # puede lanzar ValueError si el hex es inválido
    intentos = 0

    for longitud in range(1, longitud_max + 1):
        for tupla in itertools.product(CARACTERES_CLAVE, repeat=longitud):
            intentos += 1
            clave = "".join(tupla)
            candidato = parece_texto_espanol(xor_bytes(datos, clave.encode("utf-8")))
            if candidato is not None:
                return _resultado("Fuerza bruta", "XOR", clave, candidato, intentos, inicio)

    return _resultado("Fuerza bruta", "XOR", None, None, intentos, inicio)


def ataque_diccionario_xor(cifrado_hex, palabras):
    """Prueba cada palabra de la lista como clave XOR."""
    inicio = time.perf_counter()
    datos = bytes.fromhex(cifrado_hex)
    intentos = 0

    for palabra in palabras:
        intentos += 1
        candidato = parece_texto_espanol(xor_bytes(datos, palabra.encode("utf-8")))
        if candidato is not None:
            return _resultado("Ataque de diccionario", "XOR", palabra, candidato, intentos, inicio)

    return _resultado("Ataque de diccionario", "XOR", None, None, intentos, inicio)



# AES-128 (claves débiles)

def fuerza_bruta_aes(cifrado_hex, longitud_max=4, caracteres=string.digits):
    """
    Prueba todos los PIN numéricos de 1 a 'longitud_max' dígitos.
    Con 4 dígitos hay 10 + 100 + 1000 + 10000 = 11110 combinaciones.
    """
    inicio = time.perf_counter()
    intentos = 0

    for longitud in range(1, longitud_max + 1):
        for tupla in itertools.product(caracteres, repeat=longitud):
            intentos += 1
            clave = "".join(tupla)
            descifrado = aes_descifrar(cifrado_hex, clave)
            if descifrado is None:
                continue
            texto = parece_texto_espanol(descifrado)
            if texto is not None:
                return _resultado("Fuerza bruta", "AES", clave, texto, intentos, inicio)

    return _resultado("Fuerza bruta", "AES", None, None, intentos, inicio)


def ataque_diccionario_aes(cifrado_hex, palabras):
    """Prueba cada palabra del diccionario como clave AES (si cabe en 16 bytes)."""
    inicio = time.perf_counter()
    intentos = 0

    for palabra in palabras:
        if len(palabra.encode("utf-8")) > 16:
            continue  # AES-128 no admite claves más largas
        intentos += 1
        descifrado = aes_descifrar(cifrado_hex, palabra)
        if descifrado is None:
            continue
        texto = parece_texto_espanol(descifrado)
        if texto is not None:
            return _resultado("Ataque de diccionario", "AES", palabra, texto, intentos, inicio)

    return _resultado("Ataque de diccionario", "AES", None, None, intentos, inicio)
