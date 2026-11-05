package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"taller-criptografia-go/hashing"
	"taller-criptografia-go/internal/events"
)

func TestRunWorkflow(t *testing.T) {
	result, err := RunWorkflow(12, t.TempDir())
	if err != nil {
		t.Fatalf("RunWorkflow devolvió un error: %v", err)
	}

	if result.EventCount != 12 {
		t.Errorf("se generaron %d eventos; se esperaban 12", result.EventCount)
	}

	if result.EventTypes[events.Registration] == 0 ||
		result.EventTypes[events.Modification] == 0 {
		t.Errorf("faltan tipos de evento en el resultado: %v", result.EventTypes)
	}

	if !result.HashesMatch {
		t.Errorf("los hashes original y descifrado no coinciden: %s", result.IntegrityMessage)
	}
	if result.OriginalHash != result.DecryptedHash {
		t.Error("el hash descifrado debe coincidir con el original")
	}
	if result.EncryptedHash == result.OriginalHash {
		t.Error("el hash cifrado no debe coincidir con el original")
	}

	original, err := os.ReadFile(result.OriginalPath)
	if err != nil {
		t.Fatalf("no se pudo leer el log original: %v", err)
	}
	var logData events.Log
	if err := json.Unmarshal(original, &logData); err != nil {
		t.Fatalf("el log original no contiene JSON válido: %v", err)
	}
	for _, event := range logData.Events {
		storedHash := event.Hash
		event.Hash = ""
		calculatedHash, err := hashing.CalcularHashPayload(event)
		if err != nil {
			t.Fatalf("no se pudo recalcular el hash del evento %s: %v", event.EventUID, err)
		}
		if storedHash == "" || storedHash != calculatedHash {
			t.Errorf("el hash del evento %s no coincide", event.EventUID)
		}
	}

	for _, path := range []string{
		result.OriginalPath,
		result.EncryptedPath,
		result.DecryptedPath,
		result.KeyPath,
		result.NoncePath,
	} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("no se creó el artefacto %s: %v", path, err)
		}
	}
}

func TestRunWorkflowReusesClaveSinSobrescribir(t *testing.T) {
	outputDir := t.TempDir()

	first, err := RunWorkflow(3, outputDir)
	if err != nil {
		t.Fatalf("primera ejecución: %v", err)
	}
	keyBefore, err := os.ReadFile(first.KeyPath)
	if err != nil {
		t.Fatal(err)
	}

	second, err := RunWorkflow(4, outputDir)
	if err != nil {
		t.Fatalf("segunda ejecución: %v", err)
	}
	keyAfter, err := os.ReadFile(second.KeyPath)
	if err != nil {
		t.Fatal(err)
	}

	if string(keyBefore) != string(keyAfter) {
		t.Error("la clave existente fue reemplazada")
	}
	if _, err := os.Stat(filepath.Join(outputDir, "log_original.json")); err != nil {
		t.Errorf("no se actualizó el log de salida: %v", err)
	}
}
