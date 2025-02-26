const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const bcrypt = require('bcryptjs');
const app = express();
const db = new sqlite3.Database('./database.db');

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: 'secret', resave: false, saveUninitialized: true }));

db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY, comment TEXT)");
});


const isAuthenticated = (req, res, next) => {
    if (req.session.user) {
        return next(); 
    } else {
        res.redirect('/login');
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

app.post('/register', (req, res) => {
    const { username, password } = req.body;

    db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
        if (row) {
            return res.send('El usuario ya existe');
        }

        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) {
                return res.send('Error al procesar la contraseña');
            }

            const query = "INSERT INTO users (username, password) VALUES (?, ?)";
            db.run(query, [username, hashedPassword], (err) => {
                if (err) {
                    return res.send('Error al registrar el usuario');
                }
                res.redirect('/login'); 
            });
        });
    });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const query = "SELECT * FROM users WHERE username = ?";
    db.get(query, [username], (err, row) => {
        if (err) {
            return res.send('Error en la base de datos');
        }

        if (row) {
            bcrypt.compare(password, row.password, (err, isMatch) => {
                if (err) {
                    return res.send('Error al comparar contraseñas');
                }

                if (isMatch) {
                    req.session.user = row.username;  
                    return res.redirect('/comments');  
                } else {
                    res.send('Login failed: Incorrect password');
                }
            });
        } else {
            res.send('Login failed: User not found');
        }
    });
});


app.listen(4000, () => console.log('Server running on http://localhost:4000'));
