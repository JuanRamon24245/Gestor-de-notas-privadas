# **🛠️ Guía Técnica: Despliegue con Docker Compose**

Para que vuestro proyecto sea evaluado y posteriormente auditado por vuestros compañeros, debe poder levantarse en cualquier ordenador con **un solo comando**. La herramienta que utilizaremos es **Docker Compose**.

## **1\. Estructura de Archivos del Proyecto**

Vuestra carpeta de proyecto debe verse algo parecido a esto para que todo funcione correctamente:

```
/mi-proyecto
├── backend/
│   ├── app.js (o app.py)
│   ├── package.json
│   └── Dockerfile
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── script.js
└── docker-compose.yml  <-- El "director de orquesta"
```

---

## **2\. El Corazón del Despliegue: docker-compose.yml**

En la raíz de vuestro proyecto, cread un archivo llamado docker-compose.yml. Este archivo le dirá a Docker qué piezas (servicios) necesita vuestra app.

Tenéis la plantilla en el archivo [docker-compose.yml](./mi-proyecto/docker-compose.yml).

---

## **3\. Creando el Dockerfile (en la carpeta /backend)**

El Dockerfile es la receta para montar vuestro servidor. En el archivo [Dockerfile](./mi-proyecto/backend/Dockerfile) hay un ejemplo para **Node.js**.

---

## **4\. Comandos de Supervivencia ⚡**

Una vez tengáis vuestros archivos listos, usad la terminal dentro de la carpeta del proyecto:

* **Levantar la aplicación:** `docker-compose up --build`  
  *(Este comando construye las imágenes y arranca todo el sistema).*  
* **Parar la aplicación:** `Ctrl + C` en la terminal o `docker-compose down`.  
* **Ver si los contenedores están vivos:** docker ps

---

## **5\. Reglas de Oro para el Éxito**

1. **Puertos:** Si vuestro backend escucha en el puerto 3000, aseguraos de que en el `docker-compose.yml` aparezca `- "3000:3000"`.  
2. **Rutas en el Frontend:** Si desde vuestro HTML hacéis un fetch, recordad que ahora vuestra API estará en `http://localhost:3000`.  
3. **Persistencia de Datos:** Como vais a usar **SQLite o JSON**, el archivo de base de datos debe estar dentro de la carpeta /backend. Gracias a la línea de volumes en el Compose, los datos no se borrarán al apagar el contenedor.

