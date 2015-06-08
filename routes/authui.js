var express = require('express');
var router = express.Router();

router.get('/', function(req, res, next) {
  res.render('index', { title: 'ADOID' });
});

router.get('/signin', function(req, res, next) {
  res.render('signin', { title: 'ADOID' });
});

module.exports = router;
