require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');

const User = require('./models/user');

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB Atlas connected!'))
  .catch(err => console.error('MongoDB connection error:', err));


const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: false }));
app.use(express.static('public')); // For serving CSS if needed
app.use(cookieParser());

// Auth middleware
function authMiddleware(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.redirect('/login');
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.redirect('/login');
  }
}

// ROUTES

app.get('/', (req, res) => res.redirect('/login'));

// Register (GET/POST)
app.get('/register', (req, res) => res.render('register', { error: null }));
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.render('register', { error: 'All fields required' });
  const exists = await User.findOne({ email });
  if (exists)
    return res.render('register', { error: 'Email already registered' });
  const hashed = await bcrypt.hash(password, 10);
  await User.create({ name, email, password: hashed });
  res.redirect('/login');
});

// Login (GET/POST)
app.get('/login', (req, res) => res.render('login', { error: null }));
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user)
    return res.render('login', { error: 'Invalid email or password' });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid)
    return res.render('login', { error: 'Invalid email or password' });
  // Include user's name in the token
  const token = jwt.sign({ name: user.name, email }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.cookie('token', token, { httpOnly: true });
  res.redirect('/dashboard');
});

// Dashboard (Protected)
app.get('/dashboard', authMiddleware, (req, res) => {
  res.render('dashboard', { user: req.user });
});

// Logout
app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});

// Start server
app.listen(3000, () => console.log('Running on http://localhost:3000'));
