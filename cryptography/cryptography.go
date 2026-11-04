// Package cryptography protege el log en reposo con AES-256-GCM (pasos 6 y 8
// del taller). Usa únicamente la biblioteca estándar de Go.
//
// Cada cifrado produce dos artefactos: el texto cifrado, que incluye la
// etiqueta de autenticación de 16 bytes al final, y el nonce. La clave se
// guarda aparte. Los tres son necesarios para descifrar.
package cryptography

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	// TamanoClave es la longitud en bytes de una clave AES-256.
	TamanoClave = 32
	// TamanoNonce es la longitud en bytes recomendada para GCM (96 bits).
	TamanoNonce = 12
	// TamanoEtiqueta es la longitud en bytes de la etiqueta de autenticación.
	TamanoEtiqueta = 16
)

// ErrAutenticacion indica que GCM rechazó el contenido: el cifrado, la
// etiqueta o el nonce fueron alterados, o la clave no es la correcta.
// GCM no distingue entre estos casos, y eso es intencional.
var ErrAutenticacion = errors.New(
	"autenticación fallida: el contenido fue alterado o la clave es incorrecta",
)

// GenerarClave crea una clave AES-256 con el generador seguro del sistema.
func GenerarClave() ([]byte, error) {
	return bytesAleatorios(TamanoClave)
}

// GenerarNonce crea un nonce de 96 bits con el generador seguro del sistema.
// Repetir un nonce con la misma clave rompe GCM, así que cada cifrado usa uno
// nuevo.
func GenerarNonce() ([]byte, error) {
	return bytesAleatorios(TamanoNonce)
}

// GuardarClave escribe la clave en hexadecimal con permisos restringidos.
// Falla si el archivo ya existe: sobrescribir una clave dejaría sin
// posibilidad de descifrado a todo lo que se cifró con ella.
func GuardarClave(ruta string, clave []byte) error {
	if len(clave) != TamanoClave {
		return errorTamanoClave(len(clave))
	}

	if err := crearCarpeta(ruta); err != nil {
		return err
	}

	archivo, err := os.OpenFile(ruta, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("no se pudo crear el archivo de clave: %w", err)
	}

	_, errEscritura := archivo.WriteString(hex.EncodeToString(clave))
	errCierre := archivo.Close()

	if err := errors.Join(errEscritura, errCierre); err != nil {
		return fmt.Errorf("no se pudo guardar la clave: %w", err)
	}

	return nil
}

// CargarClave lee una clave en hexadecimal y valida su longitud.
func CargarClave(ruta string) ([]byte, error) {
	clave, err := leerHex(ruta)
	if err != nil {
		return nil, fmt.Errorf("no se pudo cargar la clave: %w", err)
	}

	if len(clave) != TamanoClave {
		return nil, errorTamanoClave(len(clave))
	}

	return clave, nil
}

// ObtenerClave carga la clave de la ruta indicada. Si no existe, genera una
// nueva y la guarda ahí.
func ObtenerClave(ruta string) ([]byte, error) {
	clave, err := CargarClave(ruta)
	if err == nil {
		return clave, nil
	}

	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	clave, err = GenerarClave()
	if err != nil {
		return nil, err
	}

	if err := GuardarClave(ruta, clave); err != nil {
		return nil, err
	}

	return clave, nil
}

// Cifrar protege textoPlano con un nonce nuevo. Devuelve el texto cifrado
// (con la etiqueta al final) y el nonce usado.
func Cifrar(textoPlano, clave []byte) (cifrado, nonce []byte, err error) {
	aead, err := nuevoAEAD(clave)
	if err != nil {
		return nil, nil, err
	}

	nonce, err = GenerarNonce()
	if err != nil {
		return nil, nil, err
	}

	return aead.Seal(nil, nonce, textoPlano, nil), nonce, nil
}

// Descifrar verifica la etiqueta y recupera el texto plano. Si el contenido
// fue alterado, devuelve un error que cumple errors.Is(err, ErrAutenticacion)
// y ningún dato.
func Descifrar(cifrado, clave, nonce []byte) ([]byte, error) {
	aead, err := nuevoAEAD(clave)
	if err != nil {
		return nil, err
	}

	// aead.Open entra en pánico con un nonce de longitud incorrecta, y ese
	// valor viene de un archivo que pudo ser manipulado.
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf(
			"%w: el nonce mide %d bytes y debe medir %d",
			ErrAutenticacion, len(nonce), aead.NonceSize(),
		)
	}

	textoPlano, err := aead.Open(nil, nonce, cifrado, nil)
	if err != nil {
		return nil, ErrAutenticacion
	}

	return textoPlano, nil
}

// CifrarArchivo cifra rutaOriginal y guarda el resultado y el nonce como
// artefactos separados (paso 6). El original no se modifica.
func CifrarArchivo(rutaOriginal, rutaCifrado, rutaNonce string, clave []byte) error {
	textoPlano, err := os.ReadFile(rutaOriginal)
	if err != nil {
		return fmt.Errorf("no se pudo leer el log original: %w", err)
	}

	cifrado, nonce, err := Cifrar(textoPlano, clave)
	if err != nil {
		return err
	}

	if err := crearCarpeta(rutaCifrado); err != nil {
		return err
	}

	if err := os.WriteFile(rutaCifrado, cifrado, 0644); err != nil {
		return fmt.Errorf("no se pudo guardar el archivo cifrado: %w", err)
	}

	if err := crearCarpeta(rutaNonce); err != nil {
		return err
	}

	contenidoNonce := []byte(hex.EncodeToString(nonce))
	if err := os.WriteFile(rutaNonce, contenidoNonce, 0644); err != nil {
		return fmt.Errorf("no se pudo guardar el nonce: %w", err)
	}

	return nil
}

// DescifrarArchivo recupera el contenido original (paso 8). Solo escribe
// rutaDescifrado si la autenticación fue exitosa, de modo que un archivo
// alterado nunca genera una salida.
func DescifrarArchivo(rutaCifrado, rutaNonce, rutaDescifrado string, clave []byte) error {
	cifrado, err := os.ReadFile(rutaCifrado)
	if err != nil {
		return fmt.Errorf("no se pudo leer el archivo cifrado: %w", err)
	}

	nonce, err := leerHex(rutaNonce)
	if err != nil {
		return fmt.Errorf("no se pudo leer el nonce: %w", err)
	}

	textoPlano, err := Descifrar(cifrado, clave, nonce)
	if err != nil {
		return err
	}

	if err := crearCarpeta(rutaDescifrado); err != nil {
		return err
	}

	// El resultado vuelve a ser dato sensible en claro.
	if err := os.WriteFile(rutaDescifrado, textoPlano, 0600); err != nil {
		return fmt.Errorf("no se pudo guardar el log descifrado: %w", err)
	}

	return nil
}

func nuevoAEAD(clave []byte) (cipher.AEAD, error) {
	// aes.NewCipher también aceptaría 16 y 24 bytes; aquí solo vale AES-256.
	if len(clave) != TamanoClave {
		return nil, errorTamanoClave(len(clave))
	}

	bloque, err := aes.NewCipher(clave)
	if err != nil {
		return nil, fmt.Errorf("no se pudo inicializar AES: %w", err)
	}

	aead, err := cipher.NewGCM(bloque)
	if err != nil {
		return nil, fmt.Errorf("no se pudo inicializar GCM: %w", err)
	}

	return aead, nil
}

func bytesAleatorios(tamano int) ([]byte, error) {
	datos := make([]byte, tamano)

	if _, err := rand.Read(datos); err != nil {
		return nil, fmt.Errorf("no se pudieron generar bytes aleatorios: %w", err)
	}

	return datos, nil
}

func leerHex(ruta string) ([]byte, error) {
	contenido, err := os.ReadFile(ruta)
	if err != nil {
		return nil, err
	}

	// Un editor de texto puede agregar un salto de línea al final.
	return hex.DecodeString(strings.TrimSpace(string(contenido)))
}

func crearCarpeta(ruta string) error {
	if err := os.MkdirAll(filepath.Dir(ruta), 0755); err != nil {
		return fmt.Errorf("no se pudo crear la carpeta de salida: %w", err)
	}

	return nil
}

func errorTamanoClave(tamano int) error {
	return fmt.Errorf(
		"la clave mide %d bytes y AES-256 requiere %d", tamano, TamanoClave,
	)
}
