package cryptography

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"taller-criptografia-go/hashing"
	"taller-criptografia-go/internal/events"
)

func claveDePrueba(t *testing.T) []byte {
	t.Helper()

	clave, err := GenerarClave()
	if err != nil {
		t.Fatalf("no se pudo generar la clave: %v", err)
	}

	return clave
}

func TestCifrarYDescifrarRecuperaElOriginal(t *testing.T) {
	clave := claveDePrueba(t)

	casos := map[string][]byte{
		"vacío":   {},
		"corto":   []byte("nota: 4.50"),
		"binario": {0x00, 0xff, 0x00, 0x7f},
		"grande":  bytes.Repeat([]byte("evento "), 200000),
	}

	for nombre, original := range casos {
		t.Run(nombre, func(t *testing.T) {
			cifrado, nonce, err := Cifrar(original, clave)
			if err != nil {
				t.Fatalf("error al cifrar: %v", err)
			}

			if len(cifrado) != len(original)+TamanoEtiqueta {
				t.Errorf("el cifrado mide %d bytes, se esperaban %d",
					len(cifrado), len(original)+TamanoEtiqueta)
			}

			recuperado, err := Descifrar(cifrado, clave, nonce)
			if err != nil {
				t.Fatalf("error al descifrar: %v", err)
			}

			if !bytes.Equal(recuperado, original) {
				t.Error("el contenido recuperado difiere del original")
			}
		})
	}
}

// Vectores de la especificación de GCM (McGrew y Viega), casos 13 y 14:
// clave y nonce en ceros. Prueban que esto es AES-256-GCM estándar y no solo
// que el cifrado y el descifrado coinciden entre sí.
func TestVectoresConocidos(t *testing.T) {
	clave := make([]byte, TamanoClave)
	nonce := make([]byte, TamanoNonce)

	casos := []struct {
		nombre     string
		textoPlano []byte
		cifrado    string
	}{
		{"caso 13", nil, "530f8afbc74536b9a963b4f1c4cb738b"},
		{
			"caso 14",
			make([]byte, 16),
			"cea7403d4d606b6e074ec5d3baf39d18" +
				"d0d1c8a799996bf0265b98b5d48ab919",
		},
	}

	for _, caso := range casos {
		t.Run(caso.nombre, func(t *testing.T) {
			cifrado, err := hex.DecodeString(caso.cifrado)
			if err != nil {
				t.Fatal(err)
			}

			recuperado, err := Descifrar(cifrado, clave, nonce)
			if err != nil {
				t.Fatalf("el vector fue rechazado: %v", err)
			}

			if !bytes.Equal(recuperado, caso.textoPlano) {
				t.Errorf("texto plano incorrecto: %x", recuperado)
			}
		})
	}
}

func TestCadaCifradoUsaUnNonceNuevo(t *testing.T) {
	clave := claveDePrueba(t)
	original := []byte("mismo contenido")
	vistos := make(map[string]bool)

	for i := 0; i < 10000; i++ {
		cifrado, nonce, err := Cifrar(original, clave)
		if err != nil {
			t.Fatalf("error al cifrar: %v", err)
		}

		if len(nonce) != TamanoNonce {
			t.Fatalf("el nonce mide %d bytes", len(nonce))
		}

		if vistos[string(nonce)] || vistos[string(cifrado)] {
			t.Fatal("se repitió un nonce o un texto cifrado")
		}

		vistos[string(nonce)] = true
		vistos[string(cifrado)] = true
	}
}

func TestDetectaModificacionDeCualquierBit(t *testing.T) {
	clave := claveDePrueba(t)

	cifrado, nonce, err := Cifrar([]byte("EVT-0001 nota 4.50"), clave)
	if err != nil {
		t.Fatalf("error al cifrar: %v", err)
	}

	// Recorre el cuerpo cifrado y también la etiqueta.
	for posicion := range cifrado {
		for bit := 0; bit < 8; bit++ {
			alterado := bytes.Clone(cifrado)
			alterado[posicion] ^= 1 << bit

			_, err := Descifrar(alterado, clave, nonce)
			if !errors.Is(err, ErrAutenticacion) {
				t.Fatalf("byte %d, bit %d: no se detectó el cambio (%v)",
					posicion, bit, err)
			}
		}
	}
}

func TestDetectaOtrasManipulaciones(t *testing.T) {
	clave := claveDePrueba(t)

	cifrado, nonce, err := Cifrar([]byte("EVT-0001 nota 4.50"), clave)
	if err != nil {
		t.Fatalf("error al cifrar: %v", err)
	}

	nonceAlterado := bytes.Clone(nonce)
	nonceAlterado[0] ^= 1

	casos := []struct {
		nombre  string
		cifrado []byte
		clave   []byte
		nonce   []byte
	}{
		{"truncado", cifrado[:len(cifrado)-1], clave, nonce},
		{"sin etiqueta", cifrado[:len(cifrado)-TamanoEtiqueta], clave, nonce},
		{"vacío", nil, clave, nonce},
		{"con bytes añadidos", append(bytes.Clone(cifrado), 0), clave, nonce},
		{"nonce alterado", cifrado, clave, nonceAlterado},
		{"nonce corto", cifrado, clave, nonce[:8]},
		{"nonce vacío", cifrado, clave, nil},
		{"clave incorrecta", cifrado, claveDePrueba(t), nonce},
	}

	for _, caso := range casos {
		t.Run(caso.nombre, func(t *testing.T) {
			recuperado, err := Descifrar(caso.cifrado, caso.clave, caso.nonce)

			if !errors.Is(err, ErrAutenticacion) {
				t.Errorf("se esperaba ErrAutenticacion, se obtuvo %v", err)
			}

			if recuperado != nil {
				t.Error("no se deben entregar datos sin autenticar")
			}
		})
	}
}

func TestRechazaClavesQueNoSonAES256(t *testing.T) {
	for _, tamano := range []int{0, 16, 24, 31, 33} {
		clave := make([]byte, tamano)

		if _, _, err := Cifrar([]byte("dato"), clave); err == nil {
			t.Errorf("Cifrar aceptó una clave de %d bytes", tamano)
		}

		if _, err := Descifrar(make([]byte, 32), clave, make([]byte, TamanoNonce)); err == nil {
			t.Errorf("Descifrar aceptó una clave de %d bytes", tamano)
		}
	}
}

func TestClaveNoSeSobrescribe(t *testing.T) {
	ruta := filepath.Join(t.TempDir(), "secretos", "clave.key")

	primera, err := ObtenerClave(ruta)
	if err != nil {
		t.Fatalf("no se pudo crear la clave: %v", err)
	}

	segunda, err := ObtenerClave(ruta)
	if err != nil {
		t.Fatalf("no se pudo cargar la clave: %v", err)
	}

	if !bytes.Equal(primera, segunda) {
		t.Error("ObtenerClave cambió una clave existente")
	}

	if err := GuardarClave(ruta, claveDePrueba(t)); !errors.Is(err, fs.ErrExist) {
		t.Errorf("GuardarClave debe negarse a sobrescribir, se obtuvo %v", err)
	}
}

func TestCargarClaveInvalida(t *testing.T) {
	casos := map[string]string{
		"no hexadecimal": "esto no es una clave",
		"muy corta":      "abcd",
	}

	for nombre, contenido := range casos {
		t.Run(nombre, func(t *testing.T) {
			ruta := filepath.Join(t.TempDir(), "clave.key")

			if err := os.WriteFile(ruta, []byte(contenido), 0600); err != nil {
				t.Fatal(err)
			}

			if _, err := CargarClave(ruta); err == nil {
				t.Error("se aceptó una clave inválida")
			}

			// Tampoco debe reemplazarla por una nueva.
			if _, err := ObtenerClave(ruta); err == nil {
				t.Error("ObtenerClave ocultó una clave dañada")
			}
		})
	}
}

// Recorre los pasos 5 a 9 con un log real y los módulos de los demás.
func TestCicloCompletoConLogDelTaller(t *testing.T) {
	dir := t.TempDir()
	rutaOriginal := filepath.Join(dir, "log_original.json")
	rutaCifrado := filepath.Join(dir, "log_cifrado.bin")
	rutaNonce := filepath.Join(dir, "log_cifrado.nonce")
	rutaDescifrado := filepath.Join(dir, "log_descifrado.json")

	logData, err := events.GenerateLog(50)
	if err != nil {
		t.Fatalf("error al generar eventos: %v", err)
	}

	if err := events.SaveJSON(rutaOriginal, logData); err != nil {
		t.Fatalf("error al guardar el log: %v", err)
	}

	clave := claveDePrueba(t)

	if err := CifrarArchivo(rutaOriginal, rutaCifrado, rutaNonce, clave); err != nil {
		t.Fatalf("error al cifrar: %v", err)
	}

	contenidoCifrado, err := os.ReadFile(rutaCifrado)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Contains(contenidoCifrado, []byte("REGISTRO_NOTA")) {
		t.Error("el archivo cifrado expone contenido del log")
	}

	if err := DescifrarArchivo(rutaCifrado, rutaNonce, rutaDescifrado, clave); err != nil {
		t.Fatalf("error al descifrar: %v", err)
	}

	hashOriginal, err := hashing.CalcularHashArchivo(rutaOriginal)
	if err != nil {
		t.Fatal(err)
	}

	hashCifrado, err := hashing.CalcularHashArchivo(rutaCifrado)
	if err != nil {
		t.Fatal(err)
	}

	hashDescifrado, err := hashing.CalcularHashArchivo(rutaDescifrado)
	if err != nil {
		t.Fatal(err)
	}

	if iguales, mensaje := hashing.CompararHashes(hashOriginal, hashDescifrado); !iguales {
		t.Error(mensaje)
	}

	if hashOriginal == hashCifrado {
		t.Error("el hash del cifrado no debe coincidir con el del original")
	}
}

func TestArchivoAlteradoNoGeneraSalida(t *testing.T) {
	dir := t.TempDir()
	rutaOriginal := filepath.Join(dir, "log_original.json")
	rutaCifrado := filepath.Join(dir, "log_cifrado.bin")
	rutaNonce := filepath.Join(dir, "log_cifrado.nonce")
	rutaDescifrado := filepath.Join(dir, "log_descifrado.json")

	if err := os.WriteFile(rutaOriginal, []byte(`{"events":[]}`), 0644); err != nil {
		t.Fatal(err)
	}

	clave := claveDePrueba(t)

	if err := CifrarArchivo(rutaOriginal, rutaCifrado, rutaNonce, clave); err != nil {
		t.Fatalf("error al cifrar: %v", err)
	}

	contenido, err := os.ReadFile(rutaCifrado)
	if err != nil {
		t.Fatal(err)
	}

	contenido[0] ^= 1

	if err := os.WriteFile(rutaCifrado, contenido, 0644); err != nil {
		t.Fatal(err)
	}

	err = DescifrarArchivo(rutaCifrado, rutaNonce, rutaDescifrado, clave)
	if !errors.Is(err, ErrAutenticacion) {
		t.Fatalf("se esperaba ErrAutenticacion, se obtuvo %v", err)
	}

	if _, err := os.Stat(rutaDescifrado); !errors.Is(err, fs.ErrNotExist) {
		t.Error("se escribió una salida a partir de un archivo alterado")
	}
}
