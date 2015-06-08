// Certain portions of this Active Directory client implementation are based on
// the node-activedirectory project, which is licensed under an MIT license, the
// text of which follows.
// 
// Copyright (c) 2014 George Heeres, All rights reserved.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE

require("console-stamp")(console, "HH:MM:ss.l");

var ldap = require('ldapjs');
var events = require('events');
var util = require('util');

//
// Host validation regex based on:
//
//   *  IPv6 validation regex by David M. Syzdek, available under a Creative
//      Commons Attribution-ShareAlike 3.0 license.
//      https://creativecommons.org/licenses/by-sa/3.0/us/
//
//   *  URL validation regex by Diego Perini, available under an MIT license.
//      (license follows)
//
// Copyright (c) 2010-2013 Diego Perini (http://www.iport.it)
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE
// 

var reHost = new RegExp(
  "^" +
    "(?:" +
      // IP address dotted notation octets
      // excludes loopback network 0.0.0.0
      // excludes reserved space >= 224.0.0.0
      // excludes network & broacast addresses
      // (first & last IP address of each class)
      "(?:[1-9]\\d?|1\\d\\d|2[01]\\d|22[0-3])" +
      "(?:\\.(?:1?\\d{1,2}|2[0-4]\\d|25[0-5])){2}" +
      "(?:\\.(?:[1-9]\\d?|1\\d\\d|2[0-4]\\d|25[0-4]))" +
    "|" +
      // IPv6 addresses
      "(?:" +
        // 1:2:3:4:5:6:7:8
        "(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|" +
        // 1::                              1:2:3:4:5:6:7::
        "(?:[0-9a-fA-F]{1,4}:){1,7}:|" +
        // 1::8             1:2:3:4:5:6::8  1:2:3:4:5:6::8
        "(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|" +
        // 1::7:8           1:2:3:4:5::7:8  1:2:3:4:5::8
        "(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|" +
        // 1::6:7:8         1:2:3:4::6:7:8  1:2:3:4::8
        "(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|" +
        // 1::5:6:7:8       1:2:3::5:6:7:8  1:2:3::8
        "(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|" +
        // 1::4:5:6:7:8     1:2::4:5:6:7:8  1:2::8
        "(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|" +
        // 1::3:4:5:6:7:8   1::3:4:5:6:7:8  1::8
        "[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|" +
        // ::2:3:4:5:6:7:8  ::2:3:4:5:6:7:8 ::8       ::
        ":(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|" +
        // fe80::7:8%eth0   fe80::7:8%1
        // (link-local IPv6 addresses with zone index)
        "fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|" +
        // ::255.255.255.255   ::ffff:255.255.255.255  ::ffff:0:255.255.255.255
        // (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
        "::(?:ffff(?::0{1,4}){0,1}:){0,1}" +
        "(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}" +
        "(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|" +
        "(?:[0-9a-fA-F]{1,4}:){1,4}:" +
        "(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}" +
        // 2001:db8:3:4::192.0.2.33  64:ff9b::192.0.2.33
        // (IPv4-Embedded IPv6 Address)
        "(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])" +
      ")" +
    "|" +
      // host name
      "(?:(?:[a-z\\u00a1-\\uffff0-9]-*)*[a-z\\u00a1-\\uffff0-9]+)" +
      // domain name
      "(?:\\.(?:[a-z\\u00a1-\\uffff0-9]-*)*[a-z\\u00a1-\\uffff0-9]+)*" +
      // TLD identifier
      "(?:\\.(?:[a-z\\u00a1-\\uffff]{2,}))" +
    ")" +
  "$", "i"
);

var adUnsafeChars = /[^ a-zA-Z0-9.&\-_[\]`~|@$%^?:{}!']/g;
var adSpecialChars = { ',': 1, '\\': 1, '#': 1, '+': 1, '<': 1, '>': 1, ';': 1, '"': 1, '=': 1 };

function escapeADString(str) {
  var hex, es = str.replace(adUnsafeChars, function (match) {
    if (adSpecialChars[match]) {
      return '\\' + match;
    } else {
      hex = match.charCodeAt(match).toString(16);
      if (hex.length % 2 !== 0) {
        hex = '0' + hex;
      }
      return '\\' + hex;
    }
  });
  if (es.charAt(0) === ' ') {
    es = '\\20' + (es.length > 1 ? es.substring(1) : '');
  }
  if (es.charAt(es.length - 1) === ' ') {
    es = (es.length > 1 ? es.substring(0, es.length - 1) : '') + '\\20';
  }
  return es;
}

var baseUserQuery = '(&(objectCategory=user)(objectClass=user)(|(distinguishedName=%s)(userPrincipalName=%s)(samAccountName=%s)))';
var baseGroupsForDNQuery = '(&(objectCategory=group)(objectClass=group)(member:1.2.840.113556.1.4.1941:=%s))';

function getUserQuery(username) {
  var escapedUsername = escapeADString(username);
  return util.format(baseUserQuery, escapedUsername, escapedUsername, escapedUsername);
}

function getGroupsForDNQuery(distinguishedName) {
  return util.format(baseGroupsForDNQuery, distinguishedName);
}

function notSuppliedError(param) {
  return new Error(util.format('%s not supplied.', param));
}

function invalidError(param) {
  return new Error(util.format('Invalid %s supplied.', param));
}

function ADClient(configuration) {
  if (!configuration) {
    throw notSuppliedError('Configuration');
  }
  
  // Only take the bits we need
  this.configuration = {};
  this.configuration.host = configuration.host;
  this.configuration.baseDN = configuration.baseDN;
  this.configuration.username = configuration.username;
  this.configuration.password = configuration.password;
  
  this.ldapClient = getLDAPClient(this.configuration);
}

function validateConfig(configuration) {
  if (!configuration) {
    throw notSuppliedError('Configuration');
  }
  
  if (!configuration.host || typeof configuration.host !== 'string') {
    throw notSuppliedError('Domain Controller host');
  }
  
  if (!reHost.test(configuration.host)) {
    throw invalidError('host');
  }
  
  if (!configuration.baseDN || typeof configuration.baseDN !== 'string') {
    throw notSuppliedError('Base DN');
  }
  
  try {
    ldap.parseDN(configuration.baseDN);
  } catch (err) {
    throw err;
  }
  
  if (!configuration.username || typeof configuration.username !== 'string') {
    throw notSuppliedError('Username');
  }
  
  if (!configuration.password || typeof configuration.password !== 'string') {
    throw notSuppliedError('Password');
  }
}

ADClient.prototype = Object.create(null);

ADClient.prototype.authenticate = function (username, password, callback) {
  var self = this;
  
  if (!callback || typeof callback !== 'function') {
    return;
  }
  
  if (!username || typeof username !== 'string') {
    callback(notSuppliedError('username'), null);
    return;
  }
  
  if (!password || typeof password !== 'string') {
    callback(notSuppliedError('password'), null);
    return;
  }
  
  var authClient;
  
  try {
    authClient = getLDAPClient(this.configuration, { username: username, password: password });
  } catch (err) {
    callback(err, null);
    return;
  }
  
  authClient.on('error', function(err) {
    // https://github.com/mcavage/node-ldapjs/issues/217#issuecomment-52884410
    if (!err || err.errno !== 'ECONNRESET') {
      callback(err, null);
      return;
    }
  });
  
  console.log('Binding LDAP client to ' + username);
  authClient.bind(username, password, function(err, result) {
    if (err) {
      authClient.unbind();
      callback(err, null);
      return;
    }
    
    getUser(username, authClient, self.configuration, callback);
  });
};

function execQuery(query, client, configuration, callback) {
  console.log('Executing ' + query);
  client.search(configuration.baseDN, { scope: 'sub', filter: query }, function(err, res) {
    if (err) {
      callback(err, null);
      return;
    }
    
    var results = [];
  
    res.on('searchEntry', function(entry) {
      delete entry.controls;
      results.push(entry);
    });
    
    res.on('searchReference', function(referral) {
      // TODO: Implement referrals.
    });
    
    res.on('error', function(err) {
      callback(err, null);
    });
    
    res.on('end', function(result) {
      if (results.length) {
        callback(null, results);
      } else {
        callback(null, null);
      }
    });
  });
}

function getUser(username, client, configuration, callback) {
  execQuery(getUserQuery(username), client, configuration, function(err, users) {
    if (err) {
      callback(err, null);
      return;
    }
    
    if (!users || !users.length || !users[0] || !users[0].dn) {
      callback(null, null);
      return;
    }
    
    var user = users[0];
    getGroupsForDN(user.dn, client, configuration, function(err, groups) {
      if (err) {
        callback(err, null);
        return;
      }
      
      user.groups = groups;
      callback(null, user);
    });
  });
}

function getGroupsForDN(distinguishedName, client, configuration, callback) {
  execQuery(getGroupsForDNQuery(distinguishedName), client, configuration, function(err, groups) {
    if (err) {
      callback(err, null);
      return;
    }
    
    if (!groups || !groups.length || !groups[0] || !groups[0].dn) {
      callback(null, null);
    }
    
    callback(null, groups);
  });
}


function getLDAPClient(configuration, authOptions) {
  validateConfig(configuration);
  if (authOptions && !(authOptions.username && authOptions.password)) {
    authOptions = null;
  }
  return ldap.createClient({
    url: 'ldap://' + configuration.host + '/',
    bindDN: authOptions ? authOptions.username : configuration.username,
    bindCredentials: authOptions ? authOptions.password : configuration.password,
    maxConnections: authOptions ? 1 : 20
  });
}

module.exports = ADClient;