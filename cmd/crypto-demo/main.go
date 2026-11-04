// crypto-demo demuestra los pasos 6 y 8 sobre outputs/log_original.json:
// cifra, descifra, compara hashes y comprueba que una alteración se detecta.
// Se ejecuta desde la raíz del proyecto, después de cmd/events-demo.
package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"taller-criptografia-go/cryptography"
	"taller-criptografia-go/hashing"
)

const (
	rutaOriginal   = "outputs/log_original.json"
	rutaClave      = "outputs/clave.key"
	rutaCifrado    = "outputs/log_cifrado.bin"
	rutaNonce      = "outputs/log_cifrado.nonce"
	rutaDescifrado = "outputs/log_descifrado.json"
)

func main() {
	fmt.Println("=== Cifrado del log con AES-256-GCM ===")

	clave, err := cryptography.ObtenerClave(rutaClave)
	if err != nil {
		log.Fatal("Error con la clave: ", err)
	}

	err = cryptography.CifrarArchivo(rutaOriginal, rutaCifrado, rutaNonce, clave)
	if err != nil {
		log.Fatal("Error al cifrar: ", err)
	}

	err = cryptography.DescifrarArchivo(rutaCifrado, rutaNonce, rutaDescifrado, clave)
	if err != nil {
		log.Fatal("Error al descifrar: ", err)
	}

	hashOriginal := calcularHash(rutaOriginal)
	hashCifrado := calcularHash(rutaCifrado)
	hashDescifrado := calcularHash(rutaDescifrado)

	fmt.Printf("\nClave:      %s\n", rutaClave)
	fmt.Printf("Nonce:      %s\n", rutaNonce)
	fmt.Printf("Cifrado:    %s\n", rutaCifrado)
	fmt.Printf("Descifrado: %s\n", rutaDescifrado)

	fmt.Printf("\nSHA-256 original:   %s\n", hashOriginal)
	fmt.Printf("SHA-256 cifrado:    %s\n", hashCifrado)
	fmt.Printf("SHA-256 descifrado: %s\n", hashDescifrado)

	_, mensaje := hashing.CompararHashes(hashOriginal, hashDescifrado)
	fmt.Printf("\n%s\n", mensaje)

	fmt.Println("\n=== Prueba de alteración del archivo cifrado ===")

	if err := probarAlteracion(clave); err != nil {
		log.Fatal("Error en la prueba de alteración: ", err)
	}
}

// probarAlteracion cambia un bit de una copia del cifrado e intenta descifrarla.
func probarAlteracion(clave []byte) error {
	carpeta, err := os.MkdirTemp("", "crypto-demo")
	if err != nil {
		return err
	}
	defer os.RemoveAll(carpeta)

	contenido, err := os.ReadFile(rutaCifrado)
	if err != nil {
		return err
	}

	posicion := len(contenido) / 2
	contenido[posicion] ^= 1

	rutaAlterado := filepath.Join(carpeta, "log_alterado.bin")
	if err := os.WriteFile(rutaAlterado, contenido, 0600); err != nil {
		return err
	}

	rutaSalida := filepath.Join(carpeta, "salida.json")
	fmt.Printf("Se cambió 1 bit en el byte %d de una copia del cifrado.\n", posicion)

	errDescifrado := cryptography.DescifrarArchivo(rutaAlterado, rutaNonce, rutaSalida, clave)
	if !errors.Is(errDescifrado, cryptography.ErrAutenticacion) {
		return fmt.Errorf("la alteración no fue detectada: %v", errDescifrado)
	}

	if _, err := os.Stat(rutaSalida); !errors.Is(err, os.ErrNotExist) {
		return errors.New("se generó una salida a partir de un archivo alterado")
	}

	fmt.Printf("DETECTADO: %v\n", errDescifrado)
	fmt.Println("No se generó ningún archivo descifrado.")

	return nil
}

func calcularHash(ruta string) string {
	hash, err := hashing.CalcularHashArchivo(ruta)
	if err != nil {
		log.Fatal("Error al calcular el hash: ", err)
	}

	return hash
}
