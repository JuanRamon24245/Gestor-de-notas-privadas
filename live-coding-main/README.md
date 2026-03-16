# **🚀 Hackathon DAM/DAW: De Cero a Producción en 12h**

Este documento es vuestra hoja de ruta. Tenéis 12 horas para construir una aplicación web funcional. Recordad: la próxima semana, otros compañeros intentarán encontrar fallos de seguridad en vuestro código. **¡Construid con cuidado\!**

## **1\. Opciones de Proyectos (Elegid uno)**

Estas ideas están diseñadas para ser completadas en el tiempo previsto usando un stack sencillo (HTML/JS/Node o Python/Flask o PHP).

| Proyecto | Descripción Core |
| :---- | :---- |
| **Gestor de Notas Privadas** | Un usuario se registra, inicia sesión y escribe notas que solo él puede ver. |
| **Foro de Mensajes** | Un usuario se registra, inicia sesión y puede publicar mensajes en un muro público donde cualquiera puede verlos. |
| **Mini-Tienda** | Un usuario se registra, inicia sesión y puede visualizar, comprar y vender productos. |
| **Sistema de Subida de CVs** | Un usuario se registra, inicia sesión y puede subir un archivo .pdf con su currículum que se almacenará en el servidor. |

Tenéis los requisitos detallados en el archivo [requisitos.md](./requisitos.md).

---

**2\. Requisitos de Despliegue (Mínimos)**

Para que vuestra app sea evaluable, debe cumplir esta estructura básica:

### **A. Estructura de Datos**

* **Base de Datos:** Podéis usar SQLite o JSON (un archivo local, lo más rápido).  
* **Usuarios:** Debe haber al menos una tabla de usuarios con contraseñas (¡pensad si las guardáis en texto plano o con hash\!).

### **B. Infraestructura**

Debéis desplegar vuestra aplicación en un contenedor Docker. También podéis elegir desplegarla en un PaaS como **Railway.app** o **Render.com** (conectando vuestro repo de GitHub).

--- 

**3\. Ejemplo de Arquitectura Sugerida**

Si no sabéis por dónde empezar, usad este esquema estándar:

**Frontend:** HTML5 \+ CSS (Framework como Pico.css o Bootstrap para no perder tiempo en diseño).

**Backend:** Express.js (Node) o Flask (Python).

**Persistencia:** Archivo JSON o SQLite.

---

**4\. Checklist de "Supervivencia"**

Antes de entregar, aseguraos de que vuestra app no cae ante lo más básico:

* \[ \] **Validación:** ¿Qué pasa si envío un formulario vacío?  
* \[ \] **Autenticación:** ¿Puedo acceder a una ruta simplemente escribiendo la URL sin loguearme?  
* \[ \] **Reducción:** ¿Mando únicamente la información necesaria o toda la disponible?  
* \[ \] **Control de Errores:** Si algo falla, ¿la app muestra el error feo del servidor con rutas de carpetas o un mensaje amigable?

---

**5\. Herramientas Útiles**

* **Para el desarrollo:** Visual Studio Code \+ Extensiones de lenguaje.  
* **Para bases de datos:** [DBeaver](https://dbeaver.io/) para visualizar vuestras tablas fácilmente.
