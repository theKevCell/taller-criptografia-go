# Diagramas de diseño

Las fuentes están en Mermaid (`.mmd`) y las imágenes (`.png`, `.svg`) se generaron a partir de ellas. GitHub renderiza los bloques de abajo directamente.

Para regenerar las imágenes con Mermaid CLI:

```sh
npx -p @mermaid-js/mermaid-cli mmdc -i estructura.mmd -o estructura.png -b white -s 2
npx -p @mermaid-js/mermaid-cli mmdc -i comportamiento.mmd -o comportamiento.png -b white -s 2
```

## Diagrama de estructura

Paquetes del módulo y sus dependencias. Las flechas sólidas son `import`; la punteada es lectura y escritura de archivos en `outputs/`.

![Diagrama de estructura](estructura.png)

```mermaid
flowchart TB
    usuario(["Usuario en la terminal"])

    cli["<b>main.go</b> · package main<br/>menú y validación · Paso 1<br/>reporte de resultados · Paso 10"]
    ed["<b>cmd/events-demo</b><br/>demo del generador"]
    app["<b>internal/app</b><br/>RunWorkflow → Result<br/>orquesta los Pasos 2 a 9<br/>guardarHash · leerHash"]
    cd["<b>cmd/crypto-demo</b><br/>demo de cifrado y<br/>alteración de 1 bit"]
    evt["<b>internal/events</b><br/>Event · Log · GradeRecord<br/>GenerateLog · SaveJSON"]
    hsh["<b>hashing</b><br/>CalcularHashPayload<br/>CalcularHashArchivo<br/>CompararHashes"]
    cry["<b>cryptography</b><br/>AES-256-GCM<br/>ObtenerClave<br/>CifrarArchivo<br/>DescifrarArchivo"]

    huh[["<b>charmbracelet/huh</b><br/>librería de terceros<br/>para terminal"]]
    stdlib[["<b>Biblioteca estándar de Go</b><br/>crypto/sha256 · crypto/aes<br/>crypto/cipher · crypto/rand<br/>encoding/json · encoding/hex<br/>math/rand · os"]]
    disco[("<b>outputs/</b><br/>log_original.json<br/>hash_original.sha256<br/>log_cifrado.bin · .nonce<br/>hash_cifrado.sha256<br/>log_descifrado.json<br/>clave.key")]

    usuario --> cli
    cli --> huh
    cli --> app
    app --> evt
    app --> hsh
    app --> cry
    ed --> evt
    cd --> hsh
    cd --> cry
    evt --> stdlib
    hsh --> stdlib
    cry --> stdlib
    app -. "escribe y lee archivos<br/>(directo y vía events · cryptography)" .-> disco

    classDef propio fill:#E6F7FB,stroke:#0891B2,stroke-width:1.5px,color:#0B1220
    classDef orquestador fill:#CCEFF7,stroke:#0E7490,stroke-width:2.5px,color:#0B1220
    classDef demo fill:#F8FAFC,stroke:#64748B,stroke-width:1.2px,stroke-dasharray:4 3,color:#0B1220
    classDef externo fill:#F3EEFF,stroke:#7C3AED,stroke-width:1.5px,color:#0B1220
    classDef almacen fill:#F1F5F9,stroke:#475569,stroke-width:1.5px,color:#0B1220
    class cli,evt,hsh,cry propio
    class app orquestador
    class ed,cd demo
    class huh,stdlib externo
    class disco almacen
```

## Diagrama de comportamiento

Secuencia completa de `RunWorkflow`, del Paso 1 al Paso 10, incluida la rama de error cuando la etiqueta GCM no es válida.

![Diagrama de comportamiento](comportamiento.png)

```mermaid
sequenceDiagram
    actor U as Usuario
    participant CLI as main.go<br/>(CLI · huh)
    participant APP as internal/app<br/>RunWorkflow
    participant EVT as internal/events
    participant HSH as hashing
    participant CRY as cryptography
    participant FS as outputs/<br/>(disco)

    rect rgba(8, 145, 178, 0.10)
        Note over U,FS: Generación del log estructurado
        U->>CLI: Elige "Ejecutar flujo completo"
        CLI-->>U: ¿Cuántos eventos deseas generar?
        U->>CLI: Paso 1 · n (entero mayor que cero)
        CLI->>APP: RunWorkflow(n, "outputs")
        APP->>EVT: Paso 2 · GenerateLog(n)
        EVT-->>APP: Log con n eventos (registro y modificación)
        loop por cada evento
            APP->>HSH: Paso 3 · CalcularHashPayload(evento con hash vacío)
            HSH-->>APP: SHA-256 del payload
        end
        APP->>EVT: Paso 4 · SaveJSON(log_original.json)
        EVT->>FS: escribe log_original.json
    end

    rect rgba(124, 58, 237, 0.10)
        Note over U,FS: Protección en reposo
        APP->>CRY: ObtenerClave(clave.key)
        CRY-->>APP: clave AES-256 (32 bytes)
        APP->>HSH: Paso 5 · CalcularHashArchivo(log_original.json)
        HSH-->>APP: hash original
        APP->>FS: escribe hash_original.sha256
        APP->>CRY: Paso 6 · CifrarArchivo(original, clave)
        CRY->>FS: escribe log_cifrado.bin y log_cifrado.nonce
        APP->>HSH: Paso 7 · CalcularHashArchivo(log_cifrado.bin)
        HSH-->>APP: hash cifrado
        APP->>FS: escribe hash_cifrado.sha256
    end

    rect rgba(22, 163, 74, 0.10)
        Note over U,FS: Recuperación y verificación
        APP->>CRY: Paso 8 · DescifrarArchivo(cifrado, nonce, clave)
        alt etiqueta GCM válida
            CRY->>FS: escribe log_descifrado.json
            CRY-->>APP: descifrado correcto
            APP->>HSH: Paso 9 · CalcularHashArchivo(log_descifrado.json)
            HSH-->>APP: hash descifrado
            APP->>FS: lee hash_original.sha256
            APP->>HSH: CompararHashes(hash guardado, hash descifrado)
            HSH-->>APP: coinciden + mensaje
            APP-->>CLI: Result
            CLI-->>U: Paso 10 · reporte con hashes y veredicto
        else contenido alterado o clave incorrecta
            CRY-->>APP: ErrAutenticacion (no se escribe ninguna salida)
            APP-->>CLI: error
            CLI-->>U: Error: no se pudo descifrar el log
        end
    end
```
