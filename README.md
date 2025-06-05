# DSSI
Repositorio para la prueba de FEU

# Para probar
1.	MySQL server 8 o superior. Revisar los datos de conexión en el archivo application.properties.
2.	Puerto 8080 libre para levantar el servicio.
3.	Ejecutar las consultas en la base de datos antes de hacer solicitudes.
INSERT INTO roles(name) VALUES('ROLE_USER');
INSERT INTO roles(name) VALUES('ROLE_MODERATOR');
INSERT INTO roles(name) VALUES('ROLE_ADMIN');
4.	Se puede probar el back-end con herramientas como Rest Client y pasar la información del body request en formato JSON. Ejemplo para POST signup: {"username":"alan","email":"alan@company.com","role":["admin"], "password":"djhfj39472389"}

