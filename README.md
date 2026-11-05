# Taller de criptografía en Go

La aplicación integra la generación de eventos académicos, hashes SHA-256 y
cifrado autenticado AES-256-GCM en un menú interactivo de consola.

## Ejecutar

Desde la raíz del proyecto:

```sh
go run .
```

Selecciona **Ejecutar flujo completo** e ingresa una cantidad positiva de
eventos. La aplicación calcula el hash SHA-256 individual de cada evento,
genera `outputs/log_original.json`, lo cifra, lo descifra y compara los hashes
del original y del archivo recuperado. También muestra la cantidad por tipo
de evento y el hash del archivo cifrado.

La clave se guarda en `outputs/clave.key` con permisos restringidos y se
reutiliza en ejecuciones posteriores. No compartas esa clave: es necesaria
para descifrar los archivos. Los demos independientes siguen disponibles con
`go run ./cmd/events-demo` y `go run ./cmd/crypto-demo`.

## Pruebas

```sh
go test ./...
```
