const express = require('express');
const mysql2 = require('mysql2');
const mysql = require('mysql2/promise');

const app = express();
const cors = require('cors');

const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');

const bcrypt = require('bcrypt');

const saltRounds = 10;

const jwt = require('jsonwebtoken');

require('dotenv').config();

const { DB_HOST, DB_USER, DB_PASSWORD, DB_SCHEMA } = process.env;

const db = mysql2.createConnection({
  user: DB_USER,
  host: DB_HOST,
  password: DB_PASSWORD,
  database: DB_SCHEMA,
});

const db2 = mysql.createPool({
  host: DB_HOST,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_SCHEMA,
});

app.use(express.json());

app.use(
  cors({
    origin: ['http://localhost:3000'],
    methods: ['GET', 'POST'],
    credentials: true,
  })
);

app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  session({
    key: 'userId',
    secret: 'subscribe',
    resave: false,
    saveUninitialized: false,
    cookie: {
      expires: 600 * 600 * 240,
    },
  })
);

app.get('/list', async (req, res) => {
  try {
    const [list] = await db2.query('SELECT id, namelist FROM list');
    if (list.length) {
      res.status(200).json(list);
    } else {
      res.status(404).send('Lists not found');
    }
  } catch (err) {
    res.status(500).send('Error retrieving the lists');
  }
});

app.get('/listcontent/:idList', async (req, res) => {
  try {
    const { idList } = req.params;
    const [listcontent] = await db2.query(
      'SELECT id, namemovie, directormovie, yearmovie, picturemovie, idList FROM listcontent WHERE idList = ?',
      [idList]
    );
    if (listcontent.length) {
      res.status(200).json(listcontent);
    } else {
      res.status(404).send('Lists not found');
    }
  } catch (err) {
    res.status(500).send('Error retrieving the lists');
  }
});

app.post('/register', (req, res) => {
  const { username } = req.body;
  const { password } = req.body;
  bcrypt.hash(password, saltRounds, (err, hash) => {
    db.query(
      'INSERT INTO user(username, password) VALUES (?,?)',
      [username, hash],
      (err, result) => {
        res.send(err);
      }
    );
  });
});

const verifyJWT = (req, res, next) => {
  const token = req.headers['x-access-token'];
  if (!token) {
    res.send('Yo, we need a token, please give it to us next time!');
  } else {
    jwt.verify(token, 'jwtSecret', (err, decoded) => {
      if (err) {
        res.json({ auth: false, message: 'You failed to authentificate' });
      } else {
        req.userId = decoded.id;
        next();
      }
    });
  }
};

app.get('/isUserAuth', verifyJWT, (req, res) => {
  res.send('Yo, you are authenticated Congrats!');
});

app.get('/login', (req, res) => {
  if (req.session.user) {
    res.send({ loggedIn: true, user: req.session.user });
  } else {
    res.send({ loggedIn: false });
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy();
});

app.post('/login', (req, res) => {
  const { username } = req.body;
  const { password } = req.body;
  db.query('SELECT * FROM user WHERE username = ?', username, (err, result) => {
    if (err) {
      res.send(err);
    } else if (result.length > 0) {
      bcrypt.compare(password, result[0].password, (error, response) => {
        if (response) {
          const { id } = result[0].id;
          const token = jwt.sign({ id }, 'jwtSecret', {
            expiresIn: 300,
          });
          req.session.user = result;
          res.json({ auth: true, token, result });
        } else {
          res.json({
            auth: false,
            message: 'Wrong username/password combination',
          });
        }
      });
    } else {
      res.json({ auth: false, message: 'No user exists' });
    }
  });
});

app.listen(3001, () => {
  console.log('running server');
});
