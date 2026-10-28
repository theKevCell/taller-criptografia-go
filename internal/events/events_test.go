package events

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type gradeState struct {
	studentUID string
	courseUID  string
	value      float64
}

func TestGenerateLog(t *testing.T) {
	const total = 20

	logData, err := GenerateLog(total)
	if err != nil {
		t.Fatalf("error al generar el log: %v", err)
	}

	if logData.EventCount != total {
		t.Errorf("se esperaban %d eventos, se obtuvieron %d",
			total, logData.EventCount)
	}

	if len(logData.Events) != total {
		t.Fatalf("la lista contiene %d eventos, se esperaban %d",
			len(logData.Events), total)
	}

	seenEvents := make(map[string]bool)
	grades := make(map[string]gradeState)

	registrations := 0
	modifications := 0

	for _, event := range logData.Events {
		if event.EventUID == "" || event.ActorUID == "" ||
			event.StudentUID == "" || event.CourseUID == "" ||
			event.GradeUID == "" {
			t.Errorf("el evento %s tiene identificadores vacíos",
				event.EventUID)
		}

		if seenEvents[event.EventUID] {
			t.Errorf("identificador de evento duplicado: %s",
				event.EventUID)
		}
		seenEvents[event.EventUID] = true

		if event.NewGrade < 0 || event.NewGrade > 5 {
			t.Errorf("nota fuera del rango permitido: %.2f",
				event.NewGrade)
		}

		switch event.EventType {
		case Registration:
			registrations++

			if event.OldGrade != nil {
				t.Errorf("un registro nuevo no debe tener nota anterior")
			}

			if _, exists := grades[event.GradeUID]; exists {
				t.Errorf("nota registrada más de una vez: %s",
					event.GradeUID)
				continue
			}

			grades[event.GradeUID] = gradeState{
				studentUID: event.StudentUID,
				courseUID:  event.CourseUID,
				value:      event.NewGrade,
			}

		case Modification:
			modifications++

			if event.OldGrade == nil {
				t.Errorf("la modificación %s no tiene nota anterior",
					event.EventUID)
				continue
			}

			previous, exists := grades[event.GradeUID]
			if !exists {
				t.Errorf("se modificó una nota no registrada: %s",
					event.GradeUID)
				continue
			}

			if *event.OldGrade != previous.value {
				t.Errorf("la nota anterior no coincide con el registro")
			}

			if event.StudentUID != previous.studentUID ||
				event.CourseUID != previous.courseUID {
				t.Errorf("la modificación cambió la identidad de la nota")
			}

			if event.NewGrade == previous.value {
				t.Errorf("la modificación no cambió el valor de la nota")
			}

			grades[event.GradeUID] = gradeState{
				studentUID: previous.studentUID,
				courseUID:  previous.courseUID,
				value:      event.NewGrade,
			}

		default:
			t.Errorf("tipo de evento desconocido: %s",
				event.EventType)
		}
	}

	if registrations == 0 {
		t.Error("no se generaron registros de notas")
	}

	if modifications == 0 {
		t.Error("no se generaron modificaciones de notas")
	}
}

func TestGenerateLogRejectsZero(t *testing.T) {
	_, err := GenerateLog(0)

	if err == nil {
		t.Error("se esperaba un error al solicitar cero eventos")
	}
}

func TestSaveJSON(t *testing.T) {
	logData, err := GenerateLog(3)
	if err != nil {
		t.Fatalf("error al generar eventos: %v", err)
	}

	path := filepath.Join(
		t.TempDir(),
		"outputs",
		"log_original.json",
	)

	if err := SaveJSON(path, logData); err != nil {
		t.Fatalf("error al guardar el JSON: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no se pudo leer el JSON: %v", err)
	}

	var recovered Log

	if err := json.Unmarshal(data, &recovered); err != nil {
		t.Fatalf("el archivo no contiene JSON válido: %v", err)
	}

	if recovered.EventCount != 3 ||
		len(recovered.Events) != 3 {
		t.Error("el JSON recuperado no contiene los tres eventos")
	}
}
