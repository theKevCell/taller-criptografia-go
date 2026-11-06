package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
		result.OriginalHashPath,
		result.EncryptedHashPath,
	} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("no se creó el artefacto %s: %v", path, err)
		}
	}
}

// Pasos 5 y 7: los hashes del original y del cifrado quedan en archivos
// separados, en formato sha256sum, y coinciden con los archivos que describen.
func TestRunWorkflowGuardaHashesEnArchivos(t *testing.T) {
	result, err := RunWorkflow(5, t.TempDir())
	if err != nil {
		t.Fatalf("RunWorkflow devolvió un error: %v", err)
	}

	casos := []struct {
		rutaHash    string
		rutaArchivo string
		hash        string
	}{
		{result.OriginalHashPath, result.OriginalPath, result.OriginalHash},
		{result.EncryptedHashPath, result.EncryptedPath, result.EncryptedHash},
	}

	for _, caso := range casos {
		contenido, err := os.ReadFile(caso.rutaHash)
		if err != nil {
			t.Fatalf("no se pudo leer %s: %v", caso.rutaHash, err)
		}

		esperado := caso.hash + "  " + filepath.Base(caso.rutaArchivo) + "\n"
		if string(contenido) != esperado {
			t.Errorf("%s contiene %q; se esperaba %q", caso.rutaHash, contenido, esperado)
		}

		recalculado, err := hashing.CalcularHashArchivo(caso.rutaArchivo)
		if err != nil {
			t.Fatal(err)
		}
		if recalculado != caso.hash {
			t.Errorf("el hash guardado en %s no corresponde a %s", caso.rutaHash, caso.rutaArchivo)
		}
	}

	guardado, err := leerHash(result.OriginalHashPath)
	if err != nil {
		t.Fatalf("leerHash: %v", err)
	}
	if guardado != result.DecryptedHash {
		t.Error("el hash del descifrado debe coincidir con el guardado en el paso 5")
	}
}

func TestLeerHashRechazaContenidoInvalido(t *testing.T) {
	dir := t.TempDir()

	for nombre, contenido := range map[string]string{
		"vacio.sha256":  "",
		"corto.sha256":  "abc123  log.json\n",
		"no-hex.sha256": strings.Repeat("z", 64) + "  log.json\n",
	} {
		ruta := filepath.Join(dir, nombre)
		if err := os.WriteFile(ruta, []byte(contenido), 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := leerHash(ruta); err == nil {
			t.Errorf("leerHash aceptó el contenido inválido de %s", nombre)
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
