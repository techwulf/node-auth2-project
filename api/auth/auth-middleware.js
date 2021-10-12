const { JWT_SECRET } = require("../secrets"); // use this secret!
const Users = require('../users/users-model');

const restricted = (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
}

const only = role_name => (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
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
