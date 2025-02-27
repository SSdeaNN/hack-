const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const xss = require('xss');

const app = express();
const db = new sqlite3.Database('./database.db');

// Configuración
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: 'secret', resave: false, saveUninitialized: true }));

// Límite de intentos de login para prevenir fuerza bruta y DoS
const loginLimiter = rateLimit({
    windowMs: 2 * 60 * 1000, // 2 minutos
    max: 3, // Máximo de 3 intentos
    message: "Demasiados intentos de inicio de sesión. Inténtelo de nuevo más tarde."
});

// Bloqueo de intentos de login después de varios fallos
const loginAttempts = {};

// Crear tablas si no existen
db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY, comment TEXT)");
});

const isAuthenticated = (req, res, next) => {
    if (req.session.user) {
        return next();
    }
    res.redirect('/login');
};

// Rutas
app.get('/', (req, res) => res.render('index'));
app.get('/login', (req, res) => res.render('login', { errorMessage: null }));
app.get('/register', (req, res) => res.render('register'));
app.get('/home', isAuthenticated, (req, res) => res.render('index'));

// Ruta de comentarios protegida
app.get('/comments', isAuthenticated, (req, res) => {
    db.all("SELECT comment FROM comments", (err, rows) => {
        if (err) return res.send("Error al obtener los comentarios");
        res.render('comments', { comments: rows });
    });
});

// Ruta para enviar comentarios evitando XSS
app.post('/comments', isAuthenticated, (req, res) => {
    const sanitizedComment = xss(req.body.comment);
    db.run("INSERT INTO comments (comment) VALUES (?)", [sanitizedComment], (err) => {
        if (err) return res.send("Error al guardar el comentario");
        res.redirect('/comments');
    });
});

app.post('/register', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
        if (row) return res.send('El usuario ya existe');

        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) return res.send('Error al procesar la contraseña');
            db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], (err) => {
                if (err) return res.send('Error al registrar el usuario');
                res.redirect('/login');
            });
        });
    });
});

app.post('/login', loginLimiter, (req, res) => {
    const { username, password } = req.body;

    if (!loginAttempts[username]) loginAttempts[username] = { count: 0, lockedUntil: null };

    const userAttempts = loginAttempts[username];
    if (userAttempts.lockedUntil && Date.now() < userAttempts.lockedUntil) {
        return res.render('login', { errorMessage: "Demasiados intentos fallidos. Inténtelo más tarde." });
    }

    db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
        if (err) return res.send('Error en la base de datos');

        if (row) {
            bcrypt.compare(password, row.password, (err, isMatch) => {
                if (err) return res.send('Error al comparar contraseñas');
                if (isMatch) {
                    req.session.user = row.username;
                    loginAttempts[username] = { count: 0, lockedUntil: null };
                    return res.redirect('/comments');
                } else {
                    userAttempts.count++;
                    if (userAttempts.count >= 3) {
                        userAttempts.lockedUntil = Date.now() + 2 * 60 * 1000; // Bloqueo por 2 minutos
                        return res.render('login', { errorMessage: "Demasiados intentos fallidos. Inténtelo más tarde." });
                    }
                    return res.render('login', { errorMessage: 'Login fallido: Contraseña incorrecta' });
                }
            });
        } else {
            res.render('login', { errorMessage: 'Login fallido: Usuario no encontrado' });
        }
    });
});

app.listen(4000, () => console.log('Servidor ejecutándose en http://localhost:4000'));
