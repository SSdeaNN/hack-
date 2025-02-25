const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const bcrypt = require('bcryptjs');  // Para manejar contraseñas de manera segura
const app = express();
const db = new sqlite3.Database('./database.db');

// Configuración
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: 'secret', resave: false, saveUninitialized: true }));

// Crear tabla de usuarios y comentarios si no existen
db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY, comment TEXT)");
});

// Middleware para verificar si el usuario está autenticado
const isAuthenticated = (req, res, next) => {
    if (req.session.user) {
        return next();  // El usuario está autenticado, continuar con la solicitud
    } else {
        res.redirect('/login');  // El usuario no está autenticado, redirigir al login
    }
};

// Rutas
app.get('/', (req, res) => res.render('index'));
app.get('/login', (req, res) => res.render('login'));
app.get('/register', (req, res) => res.render('register'));

// Ruta de comentarios protegida
app.get('/comments', isAuthenticated, (req, res) => {
    db.all("SELECT comment FROM comments", (err, rows) => {
        res.render('comments', { comments: rows });
    });
});

// Ruta para registrar un usuario
app.post('/register', (req, res) => {
    const { username, password } = req.body;

    // Verificar si el usuario ya existe
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
        if (row) {
            return res.send('El usuario ya existe');
        }

        // Hashear la contraseña antes de almacenarla
        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) {
                return res.send('Error al procesar la contraseña');
            }

            // Insertar el nuevo usuario con la contraseña hasheada
            const query = "INSERT INTO users (username, password) VALUES (?, ?)";
            db.run(query, [username, hashedPassword], (err) => {
                if (err) {
                    return res.send('Error al registrar el usuario');
                }
                res.redirect('/login'); // Redirigir al login después de registrarse
            });
        });
    });
});

// Ruta para iniciar sesión
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Usar consultas preparadas para evitar SQL injection
    const query = "SELECT * FROM users WHERE username = ?";
    db.get(query, [username], (err, row) => {
        if (err) {
            return res.send('Error en la base de datos');
        }

        if (row) {
            // Comparar la contraseña ingresada con la almacenada (hash)
            bcrypt.compare(password, row.password, (err, isMatch) => {
                if (err) {
                    return res.send('Error al comparar contraseñas');
                }

                if (isMatch) {
                    req.session.user = row.username;  // Crear sesión
                    return res.redirect('/comments');  // Redirigir a los comentarios
                } else {
                    res.send('Login failed: Incorrect password');
                }
            });
        } else {
            res.send('Login failed: User not found');
        }
    });
});

// Iniciar servidor
app.listen(4000, () => console.log('Server running on http://localhost:4000'));
