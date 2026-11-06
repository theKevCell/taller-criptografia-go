package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"

	"taller-criptografia-go/internal/app"
	"taller-criptografia-go/internal/events"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func run() error {
	var action string
	if err := huh.NewSelect[string]().
		Title("Taller de criptografía").
		Options(
			huh.NewOption("Ejecutar flujo completo", "run"),
			huh.NewOption("Salir", "exit"),
		).
		Value(&action).
		Run(); err != nil {
		return fmt.Errorf("no se pudo completar el menú: %w", err)
	}

	if action == "exit" {
		fmt.Println("Hasta luego.")
		return nil
	}

	var countText string
	if err := huh.NewInput().
		Title("¿Cuántos eventos deseas generar?").
		Placeholder("Ejemplo: 10").
		Value(&countText).
		Validate(func(value string) error {
			count, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil || count < 1 {
				return fmt.Errorf("ingresa un número entero mayor que cero")
			}
			return nil
		}).
		Run(); err != nil {
		return fmt.Errorf("no se pudo leer la cantidad de eventos: %w", err)
	}

	count, err := strconv.Atoi(strings.TrimSpace(countText))
	if err != nil {
		return fmt.Errorf("cantidad de eventos inválida: %w", err)
	}

	result, err := app.RunWorkflow(count, "outputs")
	if err != nil {
		return err
	}

	fmt.Println("\n=== Resultado de la ejecución ===")
	fmt.Printf("Eventos generados: %d\n", result.EventCount)
	fmt.Println("Tipos de eventos:")
	for _, eventType := range []events.EventType{
		events.Registration,
		events.Modification,
	} {
		fmt.Printf("  %s: %d\n", eventType, result.EventTypes[eventType])
	}

	fmt.Printf("\nSHA-256 original:   %s\n", result.OriginalHash)
	fmt.Printf("SHA-256 cifrado:    %s\n", result.EncryptedHash)
	fmt.Printf("SHA-256 descifrado: %s\n", result.DecryptedHash)
	fmt.Printf("\nComparación de integridad: %s\n", result.IntegrityMessage)
	fmt.Println("\nArchivos generados:")
	fmt.Printf("  Original:         %s\n", result.OriginalPath)
	fmt.Printf("  Hash original:    %s\n", result.OriginalHashPath)
	fmt.Printf("  Cifrado:          %s\n", result.EncryptedPath)
	fmt.Printf("  Hash cifrado:     %s\n", result.EncryptedHashPath)
	fmt.Printf("  Nonce:            %s\n", result.NoncePath)
	fmt.Printf("  Descifrado:       %s\n", result.DecryptedPath)
	fmt.Printf("  Clave:            %s\n", result.KeyPath)

	return nil
}
