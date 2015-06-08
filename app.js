require("console-stamp")(console, "HH:MM:ss.l");
var config = require('config');

var adConfig = config.get('activeDirectory');
var ADClient = require('./ad-client.js');
var ad = new ADClient(adConfig);

var express = require('express');
var expressSession = require('express-session');
var rs = require('connect-redis')(expressSession);
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');

var app = express();

var options = {
  login_url: '/signin',
  consent_url: '/consent',
  scopes: {
    foo: 'Access to foo special resource',
    bar: 'Access to bar special resource'
  },
  //when this line is enabled, user email appears in tokens sub field. By default, id is used as sub.
  //models:{user:{attributes:{sub:function() {return this.email;}}}},
  app: app
};
var oidc = require('openid-connect').oidc(options);

var authui = require('./routes/authui');

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

// uncomment after placing your favicon in /public
//app.use(favicon(__dirname + '/public/favicon.ico'));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser(config.get('secret')));
app.use(express.static(path.join(__dirname, 'public')));

app.use(expressSession({
  store: new rs(config.get('redis')),
  secret: config.get('secret'),
  saveUninitialized: true,
  resave: true
}));

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
  res.redirect(req.param('return_url')||'/user');
};

var loginError = function (err, req, res, next) {
  req.session.error = err.message;
  res.redirect(req.path);
};

app.use('/', authui);

app.get('/authorization', oidc.auth());
//app.get('/signin', oidc.auth());
app.post('/signin', oidc.login(validateUser), afterLogin, loginError);
app.get('/signout', oidc.removetokens(), function(req, res, next) { next(); });
app.post('/consent', oidc.consent());
app.get('/token', oidc.token());
//app.get('/api/user', oidc.check('openid', /profile|email/), function(req, res, next) { next(); });
app.get('/api/user', oidc.userInfo());

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
  app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
      message: err.message,
      error: err
    });
  });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
  res.status(err.status || 500);
  res.render('error', {
    message: err.message,
    error: {}
  });
});


module.exports = app;
