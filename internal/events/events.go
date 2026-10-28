package events

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"time"
)

// EventType identifica el tipo de operación académica.
type EventType string

const (
	Registration EventType = "REGISTRO_NOTA"
	Modification EventType = "MODIFICACION_NOTA"
)

// Event representa una operación académica.
type Event struct {
	EventUID   string    `json:"event_uid"`
	Timestamp  time.Time `json:"timestamp"`
	EventType  EventType `json:"event_type"`
	ActorUID   string    `json:"actor_uid"`
	ActorRole  string    `json:"actor_role"`
	StudentUID string    `json:"student_uid"`
	CourseUID  string    `json:"course_uid"`
	GradeUID   string    `json:"grade_uid"`
	OldGrade   *float64  `json:"old_grade,omitempty"`
	NewGrade   float64   `json:"new_grade"`
	Hash       string    `json:"hash,omitempty"`
}

// Log agrupa todos los eventos generados.
type Log struct {
	SchemaVersion string    `json:"schema_version"`
	GeneratedAt   time.Time `json:"generated_at"`
	EventCount    int       `json:"event_count"`
	Events        []Event   `json:"events"`
}

// GradeRecord conserva el estado actual de una nota.
type GradeRecord struct {
	StudentUID string
	CourseUID  string
	GradeUID   string
	Value      float64
}

// GenerateLog crea una cantidad determinada de eventos.
func GenerateLog(count int) (Log, error) {
	if count < 1 {
		return Log{}, errors.New(
			"la cantidad de eventos debe ser mayor que cero",
		)
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	students := []string{
		"EST-001", "EST-002", "EST-003", "EST-004",
	}

	teachers := []string{
		"DOC-001", "DOC-002", "DOC-003",
	}

	courses := []string{
		"ASI-001", "ASI-002", "ASI-003",
	}

	grades := make([]GradeRecord, 0, count)
	generatedEvents := make([]Event, 0, count)

	for i := 0; i < count; i++ {
		// El primer evento registra una nota.
		// El segundo la modifica, si se solicitan al menos dos.
		// Los siguientes eligen aleatoriamente el tipo.
		eventType := Registration

		if i == 1 {
			eventType = Modification
		} else if i >= 2 && rng.Intn(2) == 1 {
			eventType = Modification
		}

		actorUID := teachers[rng.Intn(len(teachers))]

		if eventType == Registration {
			studentUID := students[rng.Intn(len(students))]
			courseUID := courses[rng.Intn(len(courses))]
			gradeUID := fmt.Sprintf("NOT-%04d", len(grades)+1)
			newGrade := randomGrade(rng)

			grades = append(grades, GradeRecord{
				StudentUID: studentUID,
				CourseUID:  courseUID,
				GradeUID:   gradeUID,
				Value:      newGrade,
			})

			generatedEvents = append(generatedEvents, Event{
				EventUID:   fmt.Sprintf("EVT-%04d", i+1),
				Timestamp:  time.Now().UTC(),
				EventType:  Registration,
				ActorUID:   actorUID,
				ActorRole:  "DOCENTE",
				StudentUID: studentUID,
				CourseUID:  courseUID,
				GradeUID:   gradeUID,
				NewGrade:   newGrade,
			})

			continue
		}

		// Selecciona una nota previamente registrada.
		index := rng.Intn(len(grades))
		record := &grades[index]

		oldGrade := record.Value
		newGrade := randomGrade(rng)

		// Garantiza que la modificación cambie el valor.
		for newGrade == oldGrade {
			newGrade = randomGrade(rng)
		}

		record.Value = newGrade

		generatedEvents = append(generatedEvents, Event{
			EventUID:   fmt.Sprintf("EVT-%04d", i+1),
			Timestamp:  time.Now().UTC(),
			EventType:  Modification,
			ActorUID:   actorUID,
			ActorRole:  "DOCENTE",
			StudentUID: record.StudentUID,
			CourseUID:  record.CourseUID,
			GradeUID:   record.GradeUID,
			OldGrade:   &oldGrade,
			NewGrade:   newGrade,
		})
	}

	return Log{
		SchemaVersion: "1.0",
		GeneratedAt:   time.Now().UTC(),
		EventCount:    len(generatedEvents),
		Events:        generatedEvents,
	}, nil
}

// randomGrade genera notas entre 0.00 y 5.00.
func randomGrade(rng *rand.Rand) float64 {
	return float64(rng.Intn(501)) / 100.0
}

// SaveJSON guarda el log completo en un archivo JSON.
func SaveJSON(path string, logData Log) error {
	if path == "" {
		return errors.New("la ruta del archivo no puede estar vacía")
	}

	data, err := json.MarshalIndent(logData, "", "  ")
	if err != nil {
		return fmt.Errorf("no se pudo convertir el log a JSON: %w", err)
	}

	dir := filepath.Dir(path)

	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("no se pudo crear la carpeta de salida: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("no se pudo guardar el archivo JSON: %w", err)
	}

	return nil
}
