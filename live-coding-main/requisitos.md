# Requisitos detallados por tipo de proyecto

Este documento amplía cada opción del hackathon con requisitos de **login**, **registro** y **especificaciones técnicas** que debe cumplir cada ejemplo.

---

## Requisitos comunes a todos los proyectos

### Registro de usuario
- Formulario con: **email** (o nombre de usuario único) y **contraseña** (y confirmación de contraseña).

### Login (inicio de sesión)
- Formulario con identificador (email o usuario) y contraseña.

### Especificaciones técnicas base
- **Frontend:** HTML5 + CSS (Pico.css, Bootstrap u otro). JavaScript para llamadas a la API y manejo de formularios.
- **Backend:** Express.js (Node) o Flask (Python). Rutas REST para auth y para la lógica del proyecto.
- **Persistencia:** SQLite o archivo JSON en carpeta `/backend`. Al menos una tabla (o estructura) de usuarios con contraseña hasheada.
- **Despliegue:** Docker (Dockerfile en `/backend`) y `docker-compose.yml` en la raíz del proyecto; la app debe levantarse con `docker-compose up --build`.
- **Validación:** no confiar solo en frontend; validar y sanitizar siempre en el backend.
- **Errores:** respuestas HTTP adecuadas y mensajes de error controlados, sin exponer stack traces ni rutas del sistema.

---

## 1. Gestor de Notas Privadas

### Descripción
El usuario se registra, inicia sesión y escribe notas que **solo él** puede ver. Cada nota pertenece a un único usuario.

### Registro y login
- Cumplir los requisitos comunes de registro y login anteriores.
- Tras el login, el usuario solo debe ver sus propias notas.

### Funcionalidad específica
- **Crear nota:** título y contenido (texto); guardar asociada al usuario autenticado.
- **Listar notas:** solo las notas del usuario logueado, ordenadas por fecha (por ejemplo, más recientes primero).
- **Ver una nota:** solo si pertenece al usuario actual
- **Editar nota:** solo el dueño puede modificar título y/o contenido.
- **Eliminar nota:** solo el dueño puede borrarla.

### Modelo de datos (ejemplo)
- **usuarios:** `id`, `email` (o `username`), `password`, `created_at`.
- **notas:** `id`, `user_id` (FK), `titulo`, `contenido`, `created_at`, `updated_at`.

### Especificaciones técnicas
- API protegida: todas las rutas de notas exigen autenticación y comprobación de que el recurso pertenece al usuario.
- En respuestas JSON no incluir campos sensibles (p. ej. `password`); devolver solo lo necesario (id, email o username, etc.).
- Validación: título y contenido no vacíos; límite razonable de longitud para evitar abusos.

---

## 2. Foro de Mensajes (muro público)

### Descripción
El usuario se registra, inicia sesión y puede **publicar mensajes en un muro público** que cualquier usuario autenticado (o incluso visitantes, según diseño) puede ver.

### Registro y login
- Cumplir los requisitos comunes de registro y login.
- Decidir si el muro es visible sin login (solo lectura) o si hace falta estar logueado para ver y publicar.

### Funcionalidad específica
- **Publicar mensaje:** texto del mensaje; guardar con referencia al usuario autor y fecha/hora.
- **Listar mensajes:** mostrar todos los mensajes del muro (o los últimos N), con autor y fecha; si solo usuarios registrados pueden ver, comprobar sesión.
- **Opcional:** editar o borrar solo los mensajes propios (mismo `user_id`).

### Modelo de datos (ejemplo)
- **usuarios:** `id`, `email` (o `username`), `password`, `created_at`.
- **mensajes:** `id`, `user_id` (FK), `texto`, `created_at`.

### Especificaciones técnicas
- Las rutas de escritura (publicar, y si aplica editar/borrar) deben requerir autenticación.
- En listados, devolver solo datos necesarios (autor público, texto, fecha); no incluir datos sensibles de usuarios.
- Validación: mensaje no vacío; longitud máxima para evitar payloads enormes.
- Si hay edición/borrado: comprobar en backend que el mensaje pertenece al usuario que hace la petición.

---

## 3. Mini-Tienda

### Descripción
El usuario se registra, inicia sesión y puede **ver productos**, **comprar** (añadir al carrito y “finalizar compra”) y **vender** (dar de alta productos).

### Registro y login
- Cumplir los requisitos comunes de registro y login.
- Distinguir flujos: ver catálogo (según diseño, puede ser público o solo logueados), comprar y vender requieren estar logueados.

### Funcionalidad específica
- **Catálogo:** listar productos (nombre, descripción, precio, imagen o placeholder, usuario vendedor si aplica).
- **Vender:** formulario para crear producto (nombre, descripción, precio, opcionalmente imagen); el producto queda asociado al usuario logueado.
- **Comprar:** añadir producto(s) al carrito (en sesión o en BD) y simular “finalizar compra” (registrar pedido o venta asociada al comprador y al producto).
- **Mis productos / Mis compras:** el usuario ve solo sus productos en venta y/o sus compras/pedidos.

### Modelo de datos (ejemplo)
- **usuarios:** `id`, `email` (o `username`), `password`, `created_at`.
- **productos:** `id`, `user_id` (vendedor), `nombre`, `descripcion`, `precio`, `created_at`.
- **pedidos o ventas:** `id`, `comprador_id`, `producto_id`, `cantidad` (si aplica), `fecha`, etc.

### Especificaciones técnicas
- Rutas de creación/edición de productos y de compra protegidas por autenticación.
- Solo el vendedor puede editar o eliminar sus productos; solo el comprador ve sus pedidos.
- Validación: precios numéricos y positivos; nombres/descripciones no vacíos; longitud máxima.
- Gestionar dinero del usuario y las transacciones de compra y venta.

---

## 4. Sistema de Subida de CVs

### Descripción
El usuario se registra, inicia sesión y puede **subir un archivo PDF** con su currículum que se almacena en el servidor. Cada usuario tiene su propio CV (uno por usuario o uno “actual” que se reemplaza).

### Registro y login
- Cumplir los requisitos comunes de registro y login.
- Solo usuarios autenticados pueden subir, ver o descargar su CV.

### Funcionalidad específica
- **Subir CV:** formulario con input `type="file"`; guardar el archivo en el servidor (carpeta segura dentro de `/backend`) y guardar en BD la ruta o nombre de archivo asociado al `user_id`.
- **Descargar / ver mi CV:** el usuario solo puede descargar o ver su propio archivo; comprobar siempre `user_id` antes de servir el fichero.

### Modelo de datos (ejemplo)
- **usuarios:** `id`, `email` (o `username`), `password`, `created_at`.
- **cvs:** `id`, `user_id` (FK único o con lógica “solo uno activo”), `nombre_archivo` o `ruta`, `subido_at`.

### Especificaciones técnicas
- Validar en backend: solo archivos PDF, verificar que el archivo es un PDF y que el tamaño es razonable.
- Al servir el archivo, comprobar autenticación y que el recurso pertenece al usuario.

---

## Checklist de supervivencia (recordatorio)

Antes de entregar, comprobar en todos los proyectos:

- [ ] **Validación:** formularios vacíos o datos inválidos se rechazan en backend con mensajes claros.
- [ ] **Autenticación:** no se puede acceder a rutas protegidas solo escribiendo la URL sin estar logueado.
- [ ] **Autorización:** cada usuario solo accede a sus propios recursos (notas, mensajes propios, productos propios, su CV).
- [ ] **Reducción de información:** las respuestas no incluyen campos innecesarios ni sensibles (hashes, rutas internas).
- [ ] **Control de errores:** los fallos devuelven mensajes amigables y códigos HTTP adecuados, sin stack traces ni rutas del sistema.
