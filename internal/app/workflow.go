package app

import (
	"fmt"
	"path/filepath"

	"taller-criptografia-go/cryptography"
	"taller-criptografia-go/hashing"
	"taller-criptografia-go/internal/events"
)

// Result contiene los artefactos y las verificaciones de integridad.
type Result struct {
	EventCount       int
	EventTypes       map[events.EventType]int
	OriginalPath     string
	EncryptedPath    string
	DecryptedPath    string
	KeyPath          string
	NoncePath        string
	OriginalHash     string
	EncryptedHash    string
	DecryptedHash    string
	HashesMatch      bool
	IntegrityMessage string
}

// RunWorkflow genera un log, lo cifra y descifra, y compara sus hashes.
func RunWorkflow(count int, outputDir string) (Result, error) {
	if outputDir == "" {
		return Result{}, fmt.Errorf("la carpeta de salida no puede estar vacía")
	}

	logData, err := events.GenerateLog(count)
	if err != nil {
		return Result{}, fmt.Errorf("no se pudieron generar los eventos: %w", err)
	}

	result := Result{
		EventCount:    logData.EventCount,
		EventTypes:    make(map[events.EventType]int),
		OriginalPath:  filepath.Join(outputDir, "log_original.json"),
		EncryptedPath: filepath.Join(outputDir, "log_cifrado.bin"),
		DecryptedPath: filepath.Join(outputDir, "log_descifrado.json"),
		KeyPath:       filepath.Join(outputDir, "clave.key"),
		NoncePath:     filepath.Join(outputDir, "log_cifrado.nonce"),
	}
	for _, event := range logData.Events {
		result.EventTypes[event.EventType]++
	}
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

	if err := events.SaveJSON(result.OriginalPath, logData); err != nil {
		return Result{}, fmt.Errorf("no se pudo guardar el log original: %w", err)
	}

	key, err := cryptography.ObtenerClave(result.KeyPath)
	if err != nil {
		return Result{}, fmt.Errorf("no se pudo obtener la clave de cifrado: %w", err)
	}

	if err := cryptography.CifrarArchivo(
		result.OriginalPath,
		result.EncryptedPath,
		result.NoncePath,
		key,
	); err != nil {
		return Result{}, fmt.Errorf("no se pudo cifrar el log: %w", err)
	}

	if err := cryptography.DescifrarArchivo(
		result.EncryptedPath,
		result.NoncePath,
		result.DecryptedPath,
		key,
	); err != nil {
		return Result{}, fmt.Errorf("no se pudo descifrar el log: %w", err)
	}

	result.OriginalHash, err = hashing.CalcularHashArchivo(result.OriginalPath)
	if err != nil {
		return Result{}, fmt.Errorf("no se pudo calcular el hash original: %w", err)
	}

	result.EncryptedHash, err = hashing.CalcularHashArchivo(result.EncryptedPath)
	if err != nil {
		return Result{}, fmt.Errorf("no se pudo calcular el hash cifrado: %w", err)
	}

	result.DecryptedHash, err = hashing.CalcularHashArchivo(result.DecryptedPath)
	if err != nil {
		return Result{}, fmt.Errorf("no se pudo calcular el hash descifrado: %w", err)
	}

	result.HashesMatch, result.IntegrityMessage = hashing.CompararHashes(
		result.OriginalHash,
		result.DecryptedHash,
	)

	return result, nil
}
