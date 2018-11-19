const express = require('express');
const bcrypt = require('bcrypt');
const User = require('../models/User');
const passport = require('passport');
const router = express.Router();
const bcryptSalt = 10;

router.get('/signup', (req, res, next) => {
  res.render('auth/signup');
});

router.post('/signup', (req, res, next) => {

  const {
    username,
    password
  } = req.body;

  User.findOne({
      username
    })
    .then(user => {
      if (user !== null) {
        throw new Error("Username Already exists");
      }

      const salt = bcrypt.genSaltSync(bcryptSalt);
      const hashPass = bcrypt.hashSync(password, salt);

      const newUser = new User({
        username,
        password: hashPass,
      });

      return newUser.save()
    })
    .then(user => {
      res.redirect("/");
    })
    .catch(err => {
      res.render("auth/signup", {
        errorMessage: err.message
      });
    })
})


router.get('/login', (req, res, next) => {  
  res.render('auth/login');
});

router.post("/login", passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/auth/login",
    failureFlash: true,
    passReqToCallback: true
  })
)

// OAuth callback url
router.get('/slack/callback', 
  passport.authenticate('slack', { failureRedirect: '/login' }),
  (req, res) => {
    res.redirect('/')
  }
);

// path to start the OAuth flow
router.get('/slack', passport.authenticate('slack'), (req, res, next) => {
  next()
});

router.get('/logout' , (req,res) => {
  req.logout();
  res.redirect('/');
})


module.exports = router;