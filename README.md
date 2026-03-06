# CUERVO

Un cuervo no irrumpe en el mundo: lo observa.

Desde lo alto, recorre el terreno con paciencia, atento a los pequeños destellos que otros pasan por alto. No destruye el paisaje ni altera su equilibrio; simplemente detecta lo que ya está allí, visible para quien sabe mirar. Un reflejo entre las piedras, un objeto olvidado, una grieta que revela algo bajo la superficie.
CUERVO trabaja de la misma manera.

Como el ave que le da nombre, el programa sobrevuela la superficie pública de un sistema con curiosidad metódica. No fuerza puertas ni rompe cerraduras: se limita a recorrer lo expuesto, registrar lo que encuentra y ordenar esas piezas dispersas hasta que el mapa completo empieza a aparecer. Lo que para otros es ruido, para el cuervo es señal.
En la naturaleza, los cuervos son conocidos por su inteligencia, su memoria y su habilidad para encontrar cosas valiosas en lugares inesperados. En el ámbito técnico, CUERVO adopta ese mismo principio: explorar con paciencia, observar con criterio y recoger los indicios que revelan cómo está construido realmente un entorno digital.
Porque, igual que en el vuelo de un cuervo, a veces lo importante no es llegar primero, sino ver lo que siempre estuvo ahí y nadie se detuvo a notar.


**CUERVO** es una herramienta CLI escrita en **Go** orientada a **descubrimiento técnico, inventario de superficie pública y análisis OSINT de infraestructura web**.

El objetivo del proyecto es asistir a desarrolladores, administradores de sistemas y profesionales de seguridad en la **identificación y organización de recursos expuestos públicamente** durante auditorías técnicas autorizadas.

CUERVO no implementa explotación de vulnerabilidades ni técnicas destructivas. Su enfoque está centrado en **enumeración, análisis de recursos accesibles públicamente y organización de hallazgos técnicos**.

---

# Características

* CLI modular y extensible
* Descubrimiento de recursos web
* Análisis OSINT técnico
* Manejo flexible de wordlists
* Sistema estructurado de hallazgos
* Exportación en JSON
* Memoria local opcional de descubrimientos
* Arquitectura preparada para crecimiento modular

---

# Requisitos

* **Go 1.20+**
* Linux recomendado (Kali Linux ideal)
* Conectividad a internet para análisis de objetivos

Verificar instalación:

```
go version
```

---

# Compilación

Clonar el repositorio:

```
git clone https://github.com/usuario/cuervo.git
cd cuervo
```

Compilar el binario:

```
go build -o cuervo cuervo.go
```

Esto generará el ejecutable:

```
./cuervo
```

Opcionalmente instalar globalmente:

```
sudo mv cuervo /usr/local/bin/
```

Luego se podrá ejecutar desde cualquier lugar:

```
cuervo
```

---

# Uso

Formato general:

```
cuervo <modulo> <target> [flags]
```

Ejemplo simple:

```
cuervo expose https://example.com
```

---

# Módulos

### passive

Recopilación de información pasiva sobre el objetivo.

```
cuervo passive https://example.com
```

Puede incluir:

* resolución DNS
* cabeceras HTTP
* metadatos públicos

---

### map

Organiza y correlaciona recursos descubiertos.

```
cuervo map https://example.com
```

---

### expose

Busca rutas o archivos potencialmente expuestos utilizando wordlists.

```
cuervo expose https://example.com --wordlists base
```

---

### js

Analiza archivos JavaScript públicos para identificar:

* endpoints
* dominios
* rutas internas

```
cuervo js https://example.com
```

---

### fuzz

Exploración controlada de rutas utilizando listas de palabras.

```
cuervo fuzz https://example.com --wordlists base,extra
```

---

# Sistema de Wordlists

CUERVO permite combinar múltiples listas:

```
--wordlists base
--wordlists extra
--wordlists base,extra
--wordlists extra,base
--wordlists base,custom.txt
```

Características:

* preserva el orden definido por el usuario
* elimina duplicados
* permite agregar listas personalizadas

---

# Salida JSON

Para integración con otras herramientas:

```
cuervo expose https://example.com --json
```

---

# Sistema de Hallazgos

Cada módulo genera hallazgos estructurados con el siguiente formato:

* **target**
* **module**
* **type**
* **value**
* **tags**
* **timestamp**
* **evidence** (opcional)

Esto permite:

* correlación entre módulos
* exportación uniforme
* generación de reportes técnicos

---

# Memoria local

CUERVO puede guardar descubrimientos para reutilizarlos en ejecuciones futuras.

```
--save-memory
```

Esto permite priorizar rutas o patrones observados previamente.

La memoria utiliza almacenamiento local simple y **no utiliza inteligencia artificial**.

---

# Ejemplos

Descubrimiento de rutas expuestas:

```
cuervo expose https://example.com
```

Análisis de JavaScript:

```
cuervo js https://example.com
```

Fuzzing con múltiples wordlists:

```
cuervo fuzz https://example.com --wordlists base,extra
```

Salida JSON:

```
cuervo expose https://example.com --json
```

---

# Estructura del proyecto (planeada)

```
cuervo
│
├── cmd/
│   └── cuervo
│
├── modules/
│   ├── passive
│   ├── expose
│   ├── js
│   ├── fuzz
│   └── map
│
├── wordlists/
│
├── memory/
│
├── internal/
│
└── pkg/
```

---

# Filosofía del proyecto

CUERVO prioriza:

* simplicidad
* modularidad
* reproducibilidad
* herramientas auditables

El objetivo es crear una utilidad que pueda integrarse fácilmente en **flujos de auditoría técnica, OSINT y análisis de infraestructura**.

---

# Disclaimer legal

Esta herramienta está diseñada **exclusivamente para auditorías autorizadas, análisis de infraestructura propia, investigación de seguridad y tareas legítimas de administración de sistemas**.

El uso de CUERVO contra sistemas sin autorización explícita del propietario **puede violar leyes locales, nacionales o internacionales**.


**usalo para auditoría, laboratorio o aprendizaje…
y si decidís hacer algo ilegal, hacete cargo rey.**

---

# Licencia

Proyecto distribuido bajo licencia **MIT**.

Ver archivo `LICENSE` para más detalles.

---

# Autor

Proyecto experimental orientado a tooling de auditoría técnica y OSINT.

**CUERVO**
