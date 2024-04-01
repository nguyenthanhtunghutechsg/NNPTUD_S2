var express = require('express');
var router = express.Router();
var userModel = require('../schemas/user')
var responseHandle = require('../helpers/responseHandle');
var { validationResult } = require('express-validator');
var check = require('../validators/auth');
const bcrypt = require('bcrypt');

var protect = require('../middlewares/protect')

router.get('/me', protect, async function (req, res, next) {
  let me = await userModel.findById(req.userId);
  responseHandle.renderResponse(res, true, me)
});


router.post('/register', check(), async function (req, res, next) {
  var result = validationResult(req);
  if (result.errors.length > 0) {
    responseHandle.renderResponse(res, false, result.errors)
    return;
  }
  try {
    var newUser = new userModel({
      username: req.body.username,
      password: req.body.password,
      email: req.body.email,
      role: ["USER"]
    })
    await newUser.save();
    responseHandle.renderResponse(res, true, newUser)
  } catch (error) {
    responseHandle.renderResponse(res, false, error)
  }
});
router.post('/login', async function (req, res, next) {
  if (!req.body.username || !req.body.password) {
    responseHandle.renderResponse(res, false, "nhap day du thong tin de dang nhap")
    return;
  }
  var user = await userModel.findOne({ username: req.body.username });
  if (!user) {
    responseHandle.renderResponse(res, false, "username hoac password khong dung");
    return;
  }
  var result = bcrypt.compareSync(req.body.password, user.password);
  if (result) {
    responseHandle.renderResponse(res, true, user.genJWT());
  } else {
    responseHandle.renderResponse(res, false, "username hoac password khong dung");
  }
});


module.exports = router;