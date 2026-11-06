# Taller de criptografía en Go

La aplicación integra la generación de eventos académicos, hashes SHA-256 y
cifrado autenticado AES-256-GCM en un menú interactivo de consola.

## Ejecutar

Desde la raíz del proyecto:

```sh
go run .
```

Selecciona **Ejecutar flujo completo** e ingresa una cantidad positiva de
eventos. La aplicación calcula el hash SHA-256 individual de cada evento y
genera `outputs/log_original.json`. Justo antes de cifrarlo guarda su hash en
`outputs/hash_original.sha256` (paso 5) y, justo después de cifrar, guarda el
hash del cifrado en `outputs/hash_cifrado.sha256` (paso 7). Luego descifra el
log y compara su hash con el guardado en el paso 5. También muestra la
cantidad por tipo de evento y las rutas de todos los artefactos.

Los archivos de hash usan el formato de `sha256sum`, así que se pueden
verificar con herramientas estándar:

```sh
cd outputs && sha256sum -c hash_original.sha256 hash_cifrado.sha256
```

Los diagramas de estructura y de comportamiento están en `docs/diagramas/`.

La clave se guarda en `outputs/clave.key` con permisos restringidos y se
reutiliza en ejecuciones posteriores. No compartas esa clave: es necesaria
para descifrar los archivos. Los demos independientes siguen disponibles con
`go run ./cmd/events-demo` y `go run ./cmd/crypto-demo`.

## Pruebas

```sh
go test ./...
```
