// Middleware para la sanitización de datos
function sanitizeInput(req, res, next) {
    const { username, password } = req.body;
  
    // Sanitizar los valores de entrada
    req.sanitizedUsername = sanitizeInputString(username);
    req.sanitizedPassword = sanitizeInputString(password);
  
    next();
  }
  
  // Función para sanitizar una cadena de texto y evitar palabras prohibidas
  function sanitizeInputString(input) {
      if (typeof input !== 'string') {
        return null; // Retorna null si input no es una cadena de texto
      }
    
      // Resto del código de sanitización
      const forbiddenChars = ['"', "'", '/', ')', '(', '-', '+', '.', ',', ';', 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'ALTER', 'DROP', 'TRUNCATE', 'GRANT', 'REVOKE', 'UNION', 'JOIN', 'GROUP BY', 'HAVING'];
    
      // Verificar si se encuentran caracteres especiales o comandos SQL
      for (const char of forbiddenChars) {
        if (input.includes(char)) {
          return null; // Retorna null si se encuentra un carácter prohibido o comando SQL
        }
      }
    
      return input; // Retorna el valor de entrada sanitizado si es seguro
    }
    
  
  // Middleware para verificar inicio de sesión
  function authenticateUser(req, res, next) {
    if (!req.session.token) {
      return res.status(401).json({ message: 'Acceso no autorizado' });
    }
  
    try {
      const decodedToken = jwt.verify(req.session.token, 'mySecretKey');
      req.username = decodedToken.username;
      next();
    } catch (error) {
      res.status(401).json({ message: 'Acceso no autorizado' });
    }
  }