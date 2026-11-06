package app

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"taller-criptografia-go/cryptography"
	"taller-criptografia-go/hashing"
	"taller-criptografia-go/internal/events"
)

// Result contiene los artefactos y las verificaciones de integridad.
type Result struct {
	EventCount        int
	EventTypes        map[events.EventType]int
	OriginalPath      string
	EncryptedPath     string
	DecryptedPath     string
	KeyPath           string
	NoncePath         string
	OriginalHashPath  string
	EncryptedHashPath string
	OriginalHash      string
	EncryptedHash     string
	DecryptedHash     string
	HashesMatch       bool
	IntegrityMessage  string
}

// RunWorkflow ejecuta los pasos 2 a 9 del taller en el orden del enunciado:
// genera el log, guarda el hash del original antes de cifrar, cifra, guarda
// el hash del cifrado, descifra y compara contra el hash guardado.
func RunWorkflow(count int, outputDir string) (Result, error) {
	if outputDir == "" {
		return Result{}, fmt.Errorf("la carpeta de salida no puede estar vacía")
	}

	// Paso 2: generación aleatoria de eventos.
	logData, err := events.GenerateLog(count)
	if err != nil {
		return Result{}, fmt.Errorf("no se pudieron generar los eventos: %w", err)
	}

	result := Result{
		EventCount:        logData.EventCount,
		EventTypes:        make(map[events.EventType]int),
		OriginalPath:      filepath.Join(outputDir, "log_original.json"),
		EncryptedPath:     filepath.Join(outputDir, "log_cifrado.bin"),
		DecryptedPath:     filepath.Join(outputDir, "log_descifrado.json"),
		KeyPath:           filepath.Join(outputDir, "clave.key"),
		NoncePath:         filepath.Join(outputDir, "log_cifrado.nonce"),
		OriginalHashPath:  filepath.Join(outputDir, "hash_original.sha256"),
		EncryptedHashPath: filepath.Join(outputDir, "hash_cifrado.sha256"),
	}
	for _, event := range logData.Events {
		result.EventTypes[event.EventType]++
	}

	// Paso 3: hash del payload de cada evento. Se calcula sobre una copia con
	// Hash vacío; omitempty lo saca del JSON y así se evita la circularidad.
	for i := range logData.Events {
		event := logData.Events[i]
		event.Hash = ""
		eventHash, err := hashing.CalcularHashPayload(event)
		if err != nil {
			return Result{}, fmt.Errorf(
				"no se pudo calcular el hash del evento %s: %w",
				logData.Events[i].EventUID,
				err,
			)
		}
		logData.Events[i].Hash = eventHash
	}

	// Paso 4: log estructurado completo.
	if err := events.SaveJSON(result.OriginalPath, logData); err != nil {
		return Result{}, fmt.Errorf("no se pudo guardar el log original: %w", err)
	}

	key, err := cryptography.ObtenerClave(result.KeyPath)
	if err != nil {
		return Result{}, fmt.Errorf("no se pudo obtener la clave de cifrado: %w", err)
	}

	// Paso 5: hash del log en claro, justo antes de cifrar, en su propio archivo.
	result.OriginalHash, err = hashing.CalcularHashArchivo(result.OriginalPath)
	if err != nil {
		return Result{}, fmt.Errorf("no se pudo calcular el hash original: %w", err)
	}
	if err := guardarHash(result.OriginalHashPath, result.OriginalHash, result.OriginalPath); err != nil {
		return Result{}, err
	}

	// Paso 6: cifrado del log en reposo.
	if err := cryptography.CifrarArchivo(
		result.OriginalPath,
		result.EncryptedPath,
		result.NoncePath,
		key,
	); err != nil {
		return Result{}, fmt.Errorf("no se pudo cifrar el log: %w", err)
	}

	// Paso 7: hash del log cifrado, justo después de cifrar, en su propio archivo.
	result.EncryptedHash, err = hashing.CalcularHashArchivo(result.EncryptedPath)
	if err != nil {
		return Result{}, fmt.Errorf("no se pudo calcular el hash cifrado: %w", err)
	}
	if err := guardarHash(result.EncryptedHashPath, result.EncryptedHash, result.EncryptedPath); err != nil {
		return Result{}, err
	}

	// Paso 8: descifrado. Si la etiqueta GCM no es válida no se escribe salida.
	if err := cryptography.DescifrarArchivo(
		result.EncryptedPath,
		result.NoncePath,
		result.DecryptedPath,
		key,
	); err != nil {
		return Result{}, fmt.Errorf("no se pudo descifrar el log: %w", err)
	}

	// Paso 9: hash del descifrado comparado con el hash guardado en el paso 5.
	result.DecryptedHash, err = hashing.CalcularHashArchivo(result.DecryptedPath)
	if err != nil {
		return Result{}, fmt.Errorf("no se pudo calcular el hash descifrado: %w", err)
	}

	hashReferencia, err := leerHash(result.OriginalHashPath)
	if err != nil {
		return Result{}, err
	}

	result.HashesMatch, result.IntegrityMessage = hashing.CompararHashes(
		hashReferencia,
		result.DecryptedHash,
	)

	return result, nil
}

// guardarHash escribe el hash en el formato de sha256sum
// ("<hash>  <archivo>"), de modo que desde la carpeta de salida se puede
// verificar con: sha256sum -c hash_original.sha256
func guardarHash(rutaHash, hash, rutaArchivo string) error {
	contenido := fmt.Sprintf("%s  %s\n", hash, filepath.Base(rutaArchivo))

	if err := os.WriteFile(rutaHash, []byte(contenido), 0644); err != nil {
		return fmt.Errorf("no se pudo guardar el hash en %s: %w", rutaHash, err)
	}

	return nil
}

// leerHash recupera el hash de un archivo escrito por guardarHash y valida
// que sea un SHA-256 en hexadecimal.
func leerHash(rutaHash string) (string, error) {
	contenido, err := os.ReadFile(rutaHash)
	if err != nil {
		return "", fmt.Errorf("no se pudo leer el hash guardado en %s: %w", rutaHash, err)
	}

	campos := strings.Fields(string(contenido))
	if len(campos) == 0 {
		return "", fmt.Errorf("el archivo de hash %s está vacío", rutaHash)
	}

	hash := campos[0]
	if decodificado, err := hex.DecodeString(hash); err != nil || len(decodificado) != 32 {
		return "", fmt.Errorf("el archivo %s no contiene un SHA-256 válido", rutaHash)
	}

	return hash, nil
}
