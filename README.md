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
16. [Web cache poisoning](#web-cache-poisoning)
17. [Insecure deserialization](#insecure-deserialization)
18. [Information disclosure](#information-disclosure)
19. [Business logic vulnerabilities](#business-logic-vulnerabilities)
20. [HTTP Host header attacks](#http-host-header-attacks)

---

## [SQL Injection](https://portswigger.net/web-security/sql-injection)

---

## [Cross-site scripting](https://portswigger.net/web-security/cross-site-scripting)

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

---

## [DOM-based vulnerabilities](https://portswigger.net/web-security/dom-based)

---

## [Cross-origin resource sharing (CORS)](https://portswigger.net/web-security/cors)

---

## [XML external entity (XXE) injection](https://portswigger.net/web-security/xxe)

---

## [Server-side request forgery (SSRF)](https://portswigger.net/web-security/ssrf)

---

## [HTTP request smuggling](https://portswigger.net/web-security/request-smuggling)

---

## [OS command injection](https://portswigger.net/web-security/os-command-injection)

---

## [Server-side template injection](https://portswigger.net/web-security/server-side-template-injection)

---

## [Directory traversal](https://portswigger.net/web-security/file-path-traversal)

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

## [Web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning)

---

## [Insecure deserialization](https://portswigger.net/web-security/deserialization)

---

## [Information disclosure](https://portswigger.net/web-security/information-disclosure)

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

---

## [HTTP Host header attacks](https://portswigger.net/web-security/host-header)
