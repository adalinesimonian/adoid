## ADOID

### What is ADOID?

ADOID is an Active Directory OpenID Connect provider that runs on [express](http://expressjs.com/).

### Using ADOID with passport-openidconnect

***NOTE:*** This may not be the way that ADOID will work in the future. In the meantime, however,
this seems to be what currently works.

```js
passport.use(new OIDCStrategy({
  authorizationURL: 'http://adoid/authorization',
  tokenURL: 'http://adoid/token',
  userInfoURL: 'http://adoid/userinfo',
  clientID: 'my-client-key',
  clientSecret: 'my-client-secret',
  callbackURL: '/callback',
  scope: ['profile']
}, function (iss, sub, profile, done) {
  var user = {
    sub: sub,
    displayName: profile.displayName,
    name: profile.name,
    email: profile.email,
    picture: profile.picture,
    roles: profile._json.roles
  };
  done(null, user);
}));

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

app.use(passport.initialize());
app.use(passport.session());

app.use(express.static(path.join(__dirname, 'public')));

app.get('/signin', 
passport.authenticate('openidconnect'),
function(req, res) {
});
app.get('/callback', 
passport.authenticate('openidconnect', { failureRedirect: '/', failureFlash: true }),
function(req, res) {
  res.redirect('/');
});
app.get('/signout', function(req, res){
req.logout();
res.redirect('/');
});
```