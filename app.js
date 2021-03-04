// REQUIRED MODULES
const express = require('express');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const bcrypt = require('bcryptjs');
const LocalStrategy = require('passport-local').Strategy;
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

// DB CONNECTION DETAILS AND INITIALIZATION
const mongoDb =
  'mongodb+srv://jared_user:KpTP3bpuwragw5uZ@cluster0.nxpzr.mongodb.net/auth?retryWrites=true&w=majority';
mongoose.connect(mongoDb, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'mongo connection error'));

// INITIALIZE MONGOOSE MODEL
const User = mongoose.model(
  'User',
  new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true },
  })
);

// INITIALIZE APP AND SET VIEW ENGINE
const app = express();
app.set('views', __dirname);
app.set('view engine', 'ejs');

// PASSPORT FUNCTIONS
passport.use(
  new LocalStrategy((username, password, done) => {
    User.findOne({ username: username }, (err, user) => {
      if (err) {
        return done(err);
      }
      if (!user) {
        return done(null, false, { message: 'Incorrect username' });
      }
      // user is the returned value on success of findOne above
      bcrypt.compare(password, user.password, (err, res) => {
        if (res) {
          return done(null, user);
        } else {
          return done(null, false, { message: 'Incorrect password' });
        }
      });
      // The LocalStrategy done function appears to have 3 parameters (err, value, object{message}). Continues error first method of Express/Node
    });
  })
);
passport.serializeUser(function (user, done) {
  done(null, user.id);
});
passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

// ORDERED MIDDLEWARE
app.use(session({ secret: 'cats', resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

// MIDDLEWARE THAT SETS LOCAL.CURRENTUSER TO REQ.USER
app.use(function (req, res, next) {
  res.locals.currentUser = req.user;
  next();
});

// ROUTES
// ROOT
app.get('/', (req, res) => {
  // USER INFORMATION PROVIDED TO ALL PAGES AS MIDDLEWARE UNDER LOCALS.CURRENTUSER
  const message = req.session.message;
  res.render('index');
});

// SIGN UP
app.get('/sign-up', (req, res) => res.render('sign-up-form'));
app.post('/sign-up', (req, res, next) => {
  bcrypt.hash(req.body.password, 10, (err, hashedPassword) => {
    if (err) {
      return next(err);
    }
    const user = new User({
      username: req.body.username,
      password: hashedPassword,
    }).save((err) => {
      if (err) {
        return next(err);
      }
      res.redirect('/');
    });
  });
});

// LOG IN
app.post(
  '/log-in',
  passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/',
  })
);

// LOG OUT
app.get('/log-out', (req, res) => {
  req.logout();
  res.redirect('/');
});

// LISTENER
app.listen(3000, () => console.log('app listening on port 3000!'));
