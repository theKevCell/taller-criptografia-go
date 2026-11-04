# Cifrado del log en reposo con AES-256-GCM

Módulo `cryptography/`, pasos 6 (cifrado) y 8 (descifrado) del taller. Usa solo la biblioteca estándar de Go: `crypto/aes`, `crypto/cipher` y `crypto/rand`.

## Qué protege

| Propiedad | Cómo se obtiene |
|---|---|
| Confidencialidad | Sin la clave, el archivo cifrado no revela el contenido del log. |
| Integridad | Cualquier cambio en el cifrado, la etiqueta o el nonce hace fallar la verificación. |
| Autenticidad | Solo quien tiene la clave puede producir una etiqueta válida. |

## Cómo funciona el algoritmo

AES-256-GCM es un cifrado autenticado (AEAD). Combina dos componentes:

- **AES-256**: cifrado de bloques de 128 bits con clave de 256 bits y 14 rondas.
- **GCM (Galois/Counter Mode)**: usa AES en modo contador para generar un flujo de bytes que se combina con XOR con el log. Luego calcula sobre el texto cifrado, con la función GHASH, una etiqueta de 128 bits.

**Al cifrar**, las entradas son la clave, el nonce y el log. Las salidas son el texto cifrado, del mismo tamaño que el log, y la etiqueta de 16 bytes. `aead.Seal` entrega la etiqueta pegada al final del texto cifrado.

**Al descifrar**, `aead.Open` recalcula la etiqueta y la compara en tiempo constante antes de entregar datos. Si no coincide, devuelve error y ningún byte de texto plano.

## Por qué AES-256-GCM

| Alternativa | Motivo para descartarla |
|---|---|
| AES-ECB | Bloques iguales producen cifrados iguales, lo que filtra patrones. No detecta cambios. |
| AES-CBC o AES-CTR solos | Dan confidencialidad, pero no detectan alteraciones. |
| AES-CBC + HMAC | Es seguro si se compone bien, pero exige dos claves y un orden correcto de operaciones. GCM lo resuelve en una sola primitiva. |
| ChaCha20-Poly1305 | Es igual de sólido, pero vive en `golang.org/x/crypto`, que no es biblioteca estándar y el taller exige usar bibliotecas nativas. |

## Decisiones de diseño

**Clave.** Son 32 bytes de `crypto/rand`, guardados en hexadecimal en `outputs/clave.key`. `GuardarClave` se niega a sobrescribir un archivo existente, porque perder la clave deja irrecuperable todo lo cifrado con ella. `ObtenerClave` la reutiliza si existe y solo genera una nueva si no existe. Si el archivo existe pero está dañado, falla en lugar de reemplazarlo. La extensión `.key` está en `.gitignore`, así que la clave no se sube al repositorio.

**Nonce.** Son 12 bytes de `crypto/rand`, generados de nuevo en cada `Cifrar`. Es el tamaño recomendado por NIST SP 800-38D. Repetir un nonce con la misma clave expone el XOR de los textos planos y permite falsificar etiquetas. NIST limita a 2³² los cifrados por clave con nonces aleatorios, muy por encima del uso de este taller. No es secreto, pero sí necesario para descifrar.

**Generador aleatorio.** La clave y el nonce usan `crypto/rand`. El `math/rand` del módulo de eventos sirve para datos simulados, pero es predecible y no debe usarse aquí.

**Validaciones.** Solo se aceptan claves de 32 bytes, aunque `aes.NewCipher` también admite 16 y 24 y bajaría la seguridad sin avisar. La longitud del nonce se valida antes de llamar a `aead.Open`, que entra en pánico si es incorrecta.

**Sin salida ante un fallo.** `DescifrarArchivo` solo escribe el log si la autenticación fue exitosa. Un archivo alterado nunca produce un descifrado parcial.

**Datos adicionales (AAD).** No se usan, porque el taller no pide autenticar datos fuera del log.

## Artefactos

| Archivo | Contenido | Sensible |
|---|---|---|
| `outputs/log_cifrado.bin` | Texto cifrado + etiqueta. Mide 16 bytes más que el log. | No |
| `outputs/log_cifrado.nonce` | Nonce en hexadecimal (24 caracteres). | No |
| `outputs/clave.key` | Clave en hexadecimal (64 caracteres). | **Sí** |
| `outputs/log_descifrado.json` | Log recuperado, idéntico al original. | **Sí** |

Cada ejecución sobrescribe el cifrado y su nonce, que siempre van juntos: uno sin el otro no sirve para descifrar.

## Comprobaciones

`go test ./cryptography/` cubre:

- **Estándar:** vectores 13 y 14 de la especificación de GCM.
- **Recuperación exacta:** contenidos vacío, corto, binario y de 1,4 MB.
- **Detección de alteraciones:** cambio de cada bit del cifrado y de la etiqueta, truncamiento, bytes añadidos, nonce alterado o de otro tamaño, y clave incorrecta.
- **Nonce:** 10 000 cifrados sin repetición.
- **Claves:** rechazo de tamaños distintos a 32 bytes y de archivos dañados, sin sobrescribir la clave existente.
- **Ciclo completo:** log generado por `internal/events`, comparado con `hashing`.

`go run ./cmd/crypto-demo` lo muestra sobre `outputs/log_original.json`. Se ejecuta desde la raíz del proyecto y sirve para el video: cifra, descifra, compara los hashes y demuestra el rechazo de un cifrado con un bit alterado.

El archivo de prueba también se descifró con Node.js, ajeno a Go, y el resultado fue idéntico al original byte a byte.

## Límites conocidos

- **Clave junto a los datos.** El taller pide almacenar los insumos, pero en producción la clave iría en un KMS o HSM. Quien lea `clave.key` puede descifrar y falsificar.
- **Permisos en Windows.** El modo `0600` solo tiene efecto en Linux y macOS. En Windows el archivo hereda los permisos de la carpeta.
- **Reversión.** GCM prueba que el contenido salió de quien tiene la clave, pero no que sea la versión más reciente. Si se reemplazan el cifrado y su nonce por un par anterior válido, se aceptará. El hash almacenado en el paso 7 solo lo detecta si está guardado donde el atacante no pueda cambiarlo.
- **El hash no reemplaza la etiqueta.** SHA-256 no usa clave, por lo que un atacante puede recalcularlo después de alterar un archivo. La etiqueta GCM no se puede recalcular sin la clave.
- **Log en claro.** `log_original.json` y `log_descifrado.json` quedan sin cifrar para poder compararlos en los pasos 9 y 10. En un sistema real se eliminarían.

## Uso desde el menú

```go
clave, err := cryptography.ObtenerClave("outputs/clave.key")

// Paso 6
err = cryptography.CifrarArchivo(
	"outputs/log_original.json",
	"outputs/log_cifrado.bin",
	"outputs/log_cifrado.nonce",
	clave,
)

// Paso 8
err = cryptography.DescifrarArchivo(
	"outputs/log_cifrado.bin",
	"outputs/log_cifrado.nonce",
	"outputs/log_descifrado.json",
	clave,
)
if errors.Is(err, cryptography.ErrAutenticacion) {
	// El contenido fue alterado o la clave es incorrecta.
}
```

Si necesitan trabajar en memoria, `Cifrar` y `Descifrar` hacen lo mismo sobre `[]byte`.
