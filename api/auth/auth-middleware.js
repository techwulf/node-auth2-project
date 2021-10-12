const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const Users = require('../users/users-model');

const restricted = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    return next({status: 401, message: 'Token required'});
  }
  jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
    if (err) {
      return next({status: 401, message: 'Token invalid'})
    }
    req.decodedToken = decodedToken;
    return next();
  });
}

const only = role_name => (req, res, next) => {
  if (req.decodedToken.role_name === role_name) {
    next();
  } else {
    next({status: 403, message: 'This is not for you'});
  }
}

const checkUsernameExists = (req, res, next) => {
  const {username} = req.body
  Users.findBy(username)
    .then(user => {
      if (user) {
        req.user = user;
        next();
      } else {
        next({status: 401, message: 'invalid credentials'});
      }
    })
    .catch(err => {
      next(err);
    });
}

const validateRoleName = (req, res, next) => {
  const user = req.body
  user.role_name = user.role_name ? user.role_name.trim() : '';
  if (user.role_name) {
    if (user.role_name === 'admin') {
      res.status(422).json({message: 'Role name can not be admin'});
    } else if (user.role_name.length > 32){
      res.status(422).json(
        {message: 'Role name can not be longer than 32 chars'}
      );
    }
  } else {
    user.role_name = 'student';
  }
  next();
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
