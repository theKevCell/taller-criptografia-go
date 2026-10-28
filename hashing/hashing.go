package hashing

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// CalcularHashPayload recibe los datos (el payload) de un evento,
// lo convierte a formato JSON y calcula su hash SHA-256.
// Al recibir el 'payload' como 'interface{}', este módulo se vuelve
// completamente compatible con cualquier estructura que haya diseñado
// la "Persona 1", permitiendo un trabajo en equipo fluido sin errores de dependencias.
func CalcularHashPayload(payload interface{}) (string, error) {
	// Convertimos la estructura de datos (payload) a una cadena de bytes JSON
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("error al convertir payload a JSON: %w", err)
	}

	// Calculamos el hash SHA-256 de los bytes del JSON
	hash := sha256.Sum256(payloadBytes)

	// Convertimos el hash binario a una cadena hexadecimal legible
	return hex.EncodeToString(hash[:]), nil
}

// CalcularHashArchivo lee un archivo completo desde el disco duro
// y calcula su hash SHA-256.
// Esta misma función sirve para cumplir tus requisitos de:
// - Calcular el hash del log original
// - Calcular el hash del archivo cifrado
// - Calcular el hash del archivo descifrado
func CalcularHashArchivo(rutaArchivo string) (string, error) {
	// Leemos todo el contenido del archivo de una sola vez
	data, err := os.ReadFile(rutaArchivo)
	if err != nil {
		return "", fmt.Errorf("error al leer el archivo %s: %w", rutaArchivo, err)
	}

	// Calculamos el hash SHA-256 de los bytes del archivo
	hash := sha256.Sum256(data)

	// Convertimos a hexadecimal
	return hex.EncodeToString(hash[:]), nil
}

// CompararHashes verifica si dos cadenas hash son idénticas.
// Retorna un booleano y un mensaje descriptivo para facilitar la impresión
// de resultados por parte de la "Persona 4".
func CompararHashes(hashOriginal, hashDescifrado string) (bool, string) {
	if hashOriginal == hashDescifrado {
		return true, "¡ÉXITO! Los hashes coinciden. La integridad de los datos se ha mantenido intacta."
	}
	return false, "¡ALERTA! Los hashes NO coinciden. El archivo ha sido alterado o el descifrado falló."
}