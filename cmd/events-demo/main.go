package main

import (
	"fmt"
	"log"

	"taller-criptografia-go/internal/events"
)

func main() {
	var count int

	fmt.Println("=== Generador de eventos académicos ===")
	fmt.Print("¿Cuántos eventos deseas generar? ")

	if _, err := fmt.Scan(&count); err != nil {
		log.Fatal("Debes ingresar un número entero: ", err)
	}

	logData, err := events.GenerateLog(count)
	if err != nil {
		log.Fatal("Error al generar eventos: ", err)
	}

	outputPath := "outputs/log_original.json"

	if err := events.SaveJSON(outputPath, logData); err != nil {
		log.Fatal("Error al guardar el JSON: ", err)
	}

	fmt.Printf("\nEventos generados: %d\n", logData.EventCount)
	fmt.Printf("Archivo creado: %s\n\n", outputPath)

	for _, event := range logData.Events {
		fmt.Printf(
			"%s | %s | Nota nueva: %.2f\n",
			event.EventUID,
			event.EventType,
			event.NewGrade,
		)

		if event.OldGrade != nil {
			fmt.Printf("   Nota anterior: %.2f\n", *event.OldGrade)
		}
	}
}
