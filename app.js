const express = require('express');
require('dotenv/config');
require('./db');
const app = express();
const PORT = process.env.PORT;
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
app.use(cookieParser());

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const cors = require('cors');

app.use(express.json());

app.use(
  cors({
    origin: ['http://localhost:3000', 'https://production.com'],
    credentials: true,
  })
);

const usersRouter = require('./routers/users');

app.use(`/users`, usersRouter);

// for development
app.listen(PORT, () => console.log(`Server running on ${PORT}`));

// for production
// app.listen(() => console.log(`Server running`));
