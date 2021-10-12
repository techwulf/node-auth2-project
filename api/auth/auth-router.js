const bcrypt = require('bcryptjs');
const router = require("express").Router();

const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { ROUNDS } = require("../secrets"); // use this secret!
const Users = require('../users/users-model');
const buildToken = require('./token-builder');

router.post("/register", validateRoleName, (req, res, next) => {
  const user = req.body;
  const hash = bcrypt.hashSync(user.password, ROUNDS);
  user.password = hash;
  Users.add(user)
    .then(saved_user=> {
      res.status(201).json(saved_user);
    })
    .catch(next);
});

router.post("/login", checkUsernameExists, (req, res, next) => {
  const {password} = req.body
    if (bcrypt.compareSync(password, req.user.password)) {
      const token = buildToken(req.user);
      res.status(200).json({
        message: `${req.user.username} is back`,
        token
      })
    } else {
      next({status: 401, message: 'invalid credentials'});
    }
});

module.exports = router;
