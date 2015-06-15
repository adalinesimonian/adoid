require("console-stamp")(console, "HH:MM:ss.l");

var crypto = require('crypto');
var express = require('express');
var config = require('config');
var validator = require('validator');

var adConfig = config.get('activeDirectory');
var ADClient = require('../ad-client.js');
var ad = new ADClient(adConfig);

var options = {
  login_url: '/signin',
  consent_url: '/consent',
  scopes: {
    openid: 'Know who you are',
    profile: 'View your name, e-mail address, phone number, and role in your organization'
  },
  models: { client: { attributes: { user: undefined } },
            user: { attributes: { id: { type: 'string', required: true, unique: true, primaryKey: true },
                                  roles: { type: 'array' } } } },
  app: router
};
var oidc = require('openid-connect').oidc(options);

var router = express.Router();

var ADRole = function(adGroup) {
  this.sid = adGroup.getAttribute('objectSid');
  this.dn = adGroup.dn;
};

ADRole.prototype = Object.create(null);

ADRole.prototype.valueOf = ADRole.prototype.toString = function() {
  return this.sid;
};

var adUserToOIDUser = function (adUser) {
  return {
    id: adUser.getAttribute('objectSid'),
    name: adUser.getAttribute('name'),
    given_name: adUser.getAttribute('givenName'),
    middle_name: adUser.getAttribute('middleName'),
    family_name: adUser.getAttribute('sn'),
    //profile: null,
    email: adUser.getAttribute('mail') ||
           adUser.getAttribute('userPrincipalName'),
    //password: null,
    //picture: null,
    //birthdate: null,
    //gender: null,
    phone_number: adUser.getAttribute('telephoneNumber') ||
                  adUser.getAttribute('mobile') ||
                  adUser.getAttribute('homePhone') ||
                  adUser.getAttribute('otherHomePhone') ||
                  adUser.getAttribute('otherTelephone') ||
                  adUser.getAttribute('ipPhone') ||
                  adUser.getAttribute('otherIpPhone'),
    roles: adUser.groups.map(function (group) { return new ADRole(group); })
  };
};

function userHasRoles(user, roles) {
  if (!roles || !roles.length || !user.roles || !user.roles.length) {
    return false;
  } else if (typeof roles === 'string') {
    roles = [ roles ];
  }
  var rlObj = {};
  for (var i = 0; i < roles.length; i++) {
    rlObj[roles[i]] = 1;
  }
  var tmp, matched = 0;
  for (i = 0; i < user.roles.length; i++) {
    if (rlObj[tmp = user.roles[i].sid] || rlObj[tmp = user.roles[i].dn]) {
      matched++;
    }
    if (matched === roles.length) {
      return true;
    }
  }
  return false;
}

function authRequest(roles, failure) {
  
  function authRequestHandler(req, res, next) {
    if (!req.session.user) {
      if (typeof failure === 'function') {
        failure(req, res, next);
      } else {
        res.redirect(options.login_url);
      }
    } else if (roles && !userHasRoles(req.session.userModel, roles)) {
      if (typeof failure === 'function') {
        failure(req, res, next);
      } else {
        var err = new Error('Not Found');
        err.status = 404;
        next(err);
      }
    } else {
      next();
    }
  }
  
  return authRequestHandler;
}

router.use(function(req, res, next) {
  res.locals.user = req.session.userModel;
  next();
});

router.route('/')
.all(authRequest(null, function (req, res, next) {
  res.redirect(options.login_url);
}))
.get(oidc.use(['consent', 'client']),
function(req, res, next) {
  req.model.consent.find({user: req.session.user}).populate('client').exec(function(err, consents) {
    res.render('authorizations', { title: 'Connected apps & sites', consents: consents, scopes: oidc.settings.scopes,
      isAdmin: userHasRoles(req.session.userModel, config.get('clientManagerGroups')) });
  });
  //res.render('index', { title: 'ADOID', isAdmin: userHasRoles(req.session.userModel, config.get('clientManagerGroups')) });
})
.post(oidc.use('consent'), function(req, res, next) {
  req.model.consent.findOne({user: req.session.user, client: req.body.revoke}, function(err, consent) {
    if (!err && consent) {
      req.model.consent.destroy({user: req.session.user, client: req.body.revoke}, function(err) {
        res.redirect('/');
      });
    } else if (err) {
      next(err);
    } else {
      res.redirect('/');
    }
  });
});

router.route('/signin')
.all(oidc.use({policies: {loggedIn: false}, models: 'user'}))
.get(authRequest(null, function (req, res, next) {
  res.render('signin', { title: 'ADOID' });
}),
function(req, res, next) {
  res.redirect(req.query.redirect_url || '/');
})
.post(oidc.login(function (req, next) {
  console.log('Attempting to authenticate ' + req.body.username);
  delete req.session.error;
  
  ad.authenticate(req.body.username, req.body.password, function(err, user) {
    if (err) {
      console.error(JSON.stringify(err));
      return next(new Error(JSON.stringify(err)));
    }
    
    if (user) {
      console.log('Authenticated ' + req.body.username);
      req.session.userModel = adUserToOIDUser(user);
      req.session.save(function(err) {
        if (err) {
          return next(err, null);
        } else {
          req.model.user.destroy({id: req.session.userModel.id}, function(err) {
            req.model.user.create(req.session.userModel, function(err, user) {
              console.error(err);
              return next(null, req.session.userModel);
            });
          });
        }
      });
    }
    else {
      return next(new Error('Username or password incorrect.'));
    }
  });
}), function (req, res, next) {
  res.redirect(req.body.return_url||req.query.return_url||req.params.return_url||'/');
}, function(err, req, res, next) {
  var errDetails = JSON.parse(err.message);
  if (errDetails.code == 49) {
    res.render('signin', { title: 'Sign in', badCredentials: true });
  } else {
    res.render('signin', { title: 'Sign in', error: errDetails });
  }
});;

router.route('/consent')
.all(authRequest())
.get(oidc.use('client'), function(req, res, next) {
  var scopes = [];
  for(var i in req.session.scopes) {
    if(req.session.scopes.hasOwnProperty(i)) {
      scopes.push({ name: i, explanation: req.session.scopes[i].explain });
    }
  }
  req.model.client.findOne({id: req.session.client_id}, function(err, client) {
    res.render('consent', { title: 'ADOID', scopes: scopes, client: client });
  });
})
.post(oidc.consent());

router.route('/signout')
.all(function(req, res, next) {
  if (!req.params.access_token) {
    next();
  } else {
    oidc.removetokens(req, res, next);
  }
}, function(req, res, next) {
  req.session.destroy(function (err) {
    if (err) {
      next(err);
    } else {
      res.redirect(req.query.redirect_url || '/');
    }
  });
});

router.route('/authorization')
.get(oidc.auth());

router.route('/token')
.post(oidc.token());

router.route('/userinfo')
.get(oidc.userInfo());

router.route('/user')
.all(authRequest())
.get(function(req, res, next) {
  res.render('user', {});
});

router.route('/clients')
.all(authRequest(config.get('clientManagerGroups')))
.all(oidc.use('client'), function(req, res, next) {
  req.model.client.find({}, function(err, clients) {
    res.render('clients/list', { title: 'Registered clients', clients: clients });
  });
});

router.route('/clients/register')
.all(authRequest(config.get('clientManagerGroups')))
.get(oidc.use('client'), function(req, res, next) {
  res.render('clients/manage', { title: 'Register client', register: true });
})
.post(oidc.use('client'), function(req, res, next) {
  var postInput = { name: req.body.name, redirect_uri: req.body.redirect_uri };
  var badInput = [];
  if (!req.body.name || !/^[^\s].{2,98}[^\s]$/.test(req.body.name)) {
    badInput.push('name');
  }
  if (!validator.isURL(req.body.redirect_uri)) {
    badInput.push('redirect_uri');
  }
  if (badInput.length > 0) {
    res.render('clients/manage', { title: 'Register client', register: true, badInput: badInput, postInput: postInput });
    return;
  }
  delete req.session.error;
  var createClient = function() {
    var key = crypto.randomBytes(32).toString('hex');
    req.model.client.findOne({key: key}, function(err, client) {
      if (!err && !client) {
        var newClient = {
          name: req.body.name,
          key: key,
          secret: crypto.randomBytes(32).toString('hex'),
          // user: req.session.user,
          redirect_uris: [ req.body.redirect_uri ] // req.body.redirect_uris.split(/[, ]+/)
        };
        req.body.key = key;
        req.model.client.create(newClient, function(err, client) {
          if(!err && client) {
            //res.redirect('/clients/'+client.id);
            res.redirect('/clients');
          } else {
            next(err);
          }
        });
      } else if (!err) {
        createClient();
      } else {
        next(err);
      }
    });
  };
  createClient();
});

router.route('/clients/:id')
.all(authRequest(config.get('clientManagerGroups')))
.get(oidc.use('client'), function(req, res, next) {
  req.model.client.findOne({id: req.params.id}, function(err, client) {
    if(err) {
      next(err);
    } else if(client) {
      res.render('clients/manage', { title: 'Manage client', client: client });
    } else {
      res.render('clients/manage', { title: 'Manage client' });
    }
  });
})
.post(oidc.use('client'), function(req, res, next) {
  req.model.client.findOne({id: req.params.id}, function(err, client) {
    if(err) {
      next(err);
    } else if(client) {
      if (req.body.delete == 'delete') {
        req.model.client.destroy({id: req.params.id}, function(err) {
          if (!err) {
            res.redirect('/clients');
          } else {
            next(err);
          }
        });
        return;
      }
      var postInput = { name: req.body.name, redirect_uri: req.body.redirect_uri };
      var badInput = [];
      if (!req.body.name || !/^[^\s].{2,98}[^\s]$/.test(req.body.name)) {
        badInput.push('name');
      }
      if (!validator.isURL(req.body.redirect_uri)) {
        badInput.push('redirect_uri');
      }
      if (badInput.length > 0) {
        res.render('clients/manage', { title: 'Register client', badInput: badInput, postInput: postInput });
        return;
      }
      delete req.session.error;
      req.model.client.update({id: req.params.id},
        {name: req.body.name, redirect_uris: [ req.body.redirect_uri]}, function(err, client) {
        if (!err) {
          res.redirect('/clients');
        } else {
          next(err);
        }
      });
    } else {
      res.render('clients/manage', { title: 'Manage client' });
    }
  });
});

module.exports = router;
