require("console-stamp")(console, "HH:MM:ss.l");

var express = require('express');
var config = require('config');

var adConfig = config.get('activeDirectory');
var ADClient = require('../ad-client.js');
var ad = new ADClient(adConfig);

var options = {
  login_url: '/signin',
  consent_url: '/consent',
  scopes: {
    foo: 'Access to foo special resource',
    bar: 'Access to bar special resource'
  },
  //when this line is enabled, user email appears in tokens sub field. By default, id is used as sub.
  //models:{user:{attributes:{sub:function() {return this.email;}}}},
  app: router
};
var oidc = require('openid-connect').oidc(options);

var router = express.Router();

var validateUser = function (req, next) {
  console.log('Attempting to authenticate ' + req.body.username);
  delete req.session.error;
  
  ad.authenticate(req.body.username, req.body.password, function(err, user) {
    if (err) {
      console.error(JSON.stringify(err));
      return next(new Error(JSON.stringify(err)));
    }
    
    if (user) {
      console.log('Authenticated ' + req.body.username, user);
      return next(null, user);
    }
    else {
      return next(new Error('Username or password incorrect.'));
    }
  });
};

var afterLogin = function (req, res, next) {
  res.redirect(req.body.return_url||req.query.return_url||req.params.return_url||'/');
};

var loginError = function (err, req, res, next) {
  req.session.error = err.message;
  res.redirect(req.path);
};

router.route('/')
.all(function(req, res, next) {
  res.render('index', { title: 'ADOID' });
});

router.route('/signin')
.get(function(req, res, next) {
  res.render('signin', { title: 'ADOID' });
})
.post(oidc.login(validateUser), afterLogin, loginError);

router.route('/consent')
.get(function(req, res, next) {
  res.render('consent', { title: 'ADOID' });
})
.post(oidc.consent());

router.route('/signout')
.all(oidc.removetokens(), function(req, res, next) { next(); });

router.route('/authorization')
.get(oidc.auth());

router.route('/token')
.get(oidc.token());

router.route('/api/user')
.get(oidc.userInfo());

module.exports = router;
