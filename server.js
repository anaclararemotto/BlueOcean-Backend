const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const Database = require("better-sqlite3");
const jwt = require('jsonwebtoken'); 

const app = express();
const PORT = 3000;
const SECRET_KEY = '222'; 

app.use(cors());
app.use(bodyParser.json());

const db = new Database(':memory:');

db.exec(`
  CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome_usuario TEXT,
    user TEXT,
    email TEXT,
    senha_hash TEXT
  );
  CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mensagem TEXT,
    user TEXT
  );
`);

const verifyUser = (email, senha_hash) => {
  return db.prepare('SELECT * FROM users WHERE email = ? AND senha_hash = ?').get(email, senha_hash);
};

app.post('/api/login', (req, res) => {
  const { email, senha_hash } = req.body;

  const user = verifyUser(email, senha_hash);
  if (!user) {
    return res.status(401).json({ message: 'Credenciais inválidas' });
  }

  const token = jwt.sign({ userId: user.id, email: user.email }, SECRET_KEY, { expiresIn: '1h' });
  res.json({ user, token });
});

app.post('/api/cadastro', (req, res) => {
  const { nome_usuario, user, email, senha_hash, confirma_senha_hash } = req.body;

  if (senha_hash !== confirma_senha_hash) {
    return res.status(400).json({ message: 'As senhas não coincidem' });
  }

  const stmt = db.prepare('INSERT INTO users (nome_usuario, user, email, senha_hash) VALUES (?, ?, ?, ?)');
  const info = stmt.run(nome_usuario, user, email, senha_hash);

  const newUser = { id: info.lastInsertRowid, nome_usuario, user, email };
  res.json({ 
    user: newUser, 
    token: jwt.sign({ userId: info.lastInsertRowid, email }, SECRET_KEY, { expiresIn: '1h' }) 
  });
});

app.post('/api/home', (req, res) => {
  const { mensagem, user } = req.body;
  const stmt = db.prepare('INSERT INTO messages (mensagem, user) VALUES (?, ?)');
  const info = stmt.run(mensagem, user);
  res.json({ id: info.lastInsertRowid, mensagem, user });
});

app.get('/api/messages', (req, res) => {
  const rows = db.prepare('SELECT * FROM messages').all();
  res.json(rows);
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
