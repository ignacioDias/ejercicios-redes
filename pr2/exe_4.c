#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

// Función para calcular el checksum de 16 bits
uint16_t calcular_checksum(uint16_t *datos, int n) {
    uint32_t suma = 0;
    // Sumar todas las palabras de 16 bits
    for (int i = 0; i < n; i++) {
        suma += datos[i];
        // Si hay acarreo de 16 bits, se suma al resultado (wrap-around)
        if (suma & 0x10000) {   // si hay un bit extra en la posición 17
            suma = (suma & 0xFFFF) + 1;
        }
    }
    // Complemento a uno
    return (uint16_t)(~suma);
}

// Función para verificar un mensaje recibido (datos + checksum)
bool verificar_mensaje(uint16_t *datos, int n, uint16_t checksum) {
    uint32_t suma = 0;
    // Sumar datos
    for (int i = 0; i < n; i++) {
        suma += datos[i];
        if (suma & 0x10000) {
            suma = (suma & 0xFFFF) + 1;
        }
    }
    // Sumar el checksum recibido
    suma += checksum;
    if (suma & 0x10000) {
        suma = (suma & 0xFFFF) + 1;
    }
    // Si el resultado es 0xFFFF, el mensaje es válido
    return (suma == 0xFFFF);
}

int main() {
    uint16_t datos[] = {0x1234, 0x5678, 0xABCD, 0x1111};
    int n = sizeof(datos) / sizeof(datos[0]);

    uint16_t checksum = calcular_checksum(datos, n);
    printf("Checksum calculado: 0x%04X\n", checksum);

    if (verificar_mensaje(datos, n, checksum)) {
        printf("Mensaje recibido SIN errores.\n");
    } else {
        printf("Mensaje recibido CON errores.\n");
    }

    datos[2] ^= 0x0001;  // cambiamos un bit

    if (verificar_mensaje(datos, n, checksum)) {
        printf("Mensaje recibido SIN errores.\n");
    } else {
        printf("Mensaje recibido CON errores.\n");
    }

    return 0;
}
