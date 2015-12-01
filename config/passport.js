var localStrategy = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
var LinkedinStrategy = require('passport-linkedin').Strategy;
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;

var User = require('../app/models/user.js'); 
var configAuth = require('./auth.js');

module.exports = function(passport) { 
  
  passport.serializeUser(function(user, done) {
    done(null, user.id);
  });

  passport.deserializeUser(function(id, done){
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

  passport.use('local-signup', new localStrategy({
      usernameField: 'email',
      passwordField: 'password',
      passReqToCallback: true
    },
    function(req, email, password, done) {
      process.nextTick(function() {
        User.findOne({'google.email': email}, function (err, user) {
          if(err)
            return done(err);
          if(user){
            sign(user, profile, 'local', accessToken).save(function(err) {
              if(err)
                throw err;
              return done(null, user);
            });
          }else{
            User.findOne({'linkedin.email': email}, function (err, user) {
              if(err)
                return done(err);
              if(user){
                sign(user, profile, 'local', accessToken).save(function(err) {
                  if(err)
                    throw err;
                  return done(null, user);
                });
              }else{
                User.findOne({'facebook.email': email}, function (err, user) {
                  if(err)
                    return done(err);
                  if(user){
                    sign(user, profile, 'local', accessToken).save(function(err) {
                      if(err)
                        throw err;
                      return done(null, user);
                    });
                  }else{
                    User.findOne({'local.username': email}, function(err, user) {
                      if(err)
                        return done(err);
                      if(user){
                        return done(null, false, req.flash('signupMessage', 'That email already taken'));
                      }
                      if(!req.user){
                        var newUser = new User();
                        newUser.local.username = email;
                        newUser.local.password = newUser.generateHash(password);

                        newUser.save(function(err){
                          if(err)
                            throw err;
                          return done(null, newUser);
                        });
                      }else{
                        var user = req.user;
                        user.local.username = email;
                        user.local.password = user.generateHash(password);

                        user.save(function(err) {
                          if(err)
                            throw err;
                          return done(null, user);
                        });
                      }
                    });
                  }
                });
              }
            });
          }
        });
        
      });
    }
  ));

  passport.use('local-login', new localStrategy({
      usernameField: 'email',
      passwordField: 'password',
      passReqToCallback: true
    },
    function(req, email, password, done) {
      process.nextTick(function() {
        User.findOne({'local.username': email}, function(err, user) {
          if(err)
            return done(err);
          if(!user)
            return done(null, false, req.flash('loginMessage', 'No user found'));
          if(!user.validPassword(password))
            return done(null, false, req.flash('loginMessage', 'Invalid password'));
          return done(null, user);
        });
      });
    }
  ));

  passport.use(new FacebookStrategy({
      clientID: configAuth.facebookAuth.clientID,
      clientSecret: configAuth.facebookAuth.clientSecret,
      callbackURL: configAuth.facebookAuth.callbackURL,
      passReqToCallback: true,
      profileFields: ['id', 'first_name', 'last_name', 'displayName', 'emails']
    },
    function(req, accessToken, refreshToken, profile, done) {
      process.nextTick(function() {
        User.findOne({'google.email': profile.emails[0].value}, function (err, user) {
          if(err)
            return done(err);
          if(user){
            sign(user, profile, 'facebook', accessToken).save(function(err) {
              if(err)
                throw err;
              return done(null, user);
            });
          }else{
            User.findOne({'linkedin.email': profile.emails[0].value}, function (err, user) {
              if(err)
                return done(err);
              if(user){
                sign(user, profile, 'facebook', accessToken).save(function(err) {
                  if(err)
                    throw err;
                  return done(null, user);
                });
              }else{
                User.findOne({'local.username': profile.emails[0].value}, function (err, user) {
                  if(err)
                    return done(err);
                  if(user){
                    sign(user, profile, 'facebook', accessToken).save(function(err) {
                      if(err)
                        throw err;
                      return done(null, user);
                    });
                  }else{
                    User.findOne({'facebook.email': profile.emails[0].value}, function (err, user) {
                      if(!req.user){
                        if(err)
                          return done(err);
                        if(user){
                          if(!user.facebook.token){
                            sign(user, profile, 'facebook', accessToken).save(function(err){
                              if(err)
                                throw err;
                            });
                          }
                          return done(null, user);
                        }else{
                          var newUser = new User();

                          sign(newUser, profile, 'facebook', accessToken).save(function(err) {
                            if(err)
                              throw err;
                            return done(null, newUser);
                          });
                        }
                      }else{
                        var user = req.user;

                        sign(user, profile, 'facebook', accessToken).save(function(err) {
                          if(err)
                            throw err;
                          return done(null, user);
                        });
                      }
                    });
                  }
                });
              }
            });
          }
        });
      });
    }
  ));

  passport.use(new LinkedinStrategy({
      consumerKey: configAuth.linkedinAuth.consumerKey,
      consumerSecret: configAuth.linkedinAuth.consumerSecret,
      callbackURL: configAuth.linkedinAuth.callbackURL,
      passReqToCallback: true,
      profileFields: ['id', 'first-name', 'last-name', 'email-address']
    },
    function(req, accessToken, refreshToken, profile, done) {
      process.nextTick(function() {
        User.findOne({'facebook.email': profile.emails[0].value}, function (err, user) {
          if(err)
            return done(err);
          if(user){
            sign(user, profile, 'linkedin', accessToken).save(function(err) {
              if(err)
                throw err;
              return done(null, user);
            });
          }else{
            User.findOne({'google.email': profile.emails[0].value}, function (err, user) {
              if(err)
                return done(err);
              if(user){
                sign(user, profile, 'linkedin', accessToken).save(function(err) {
                  if(err)
                    throw err;
                  return done(null, user);
                });
              }else{
                User.findOne({'local.username': profile.emails[0].value}, function (err, user) {
                  if(err)
                    return done(err);
                  if(user){
                    sign(user, profile, 'linkedin', accessToken).save(function(err) {
                      if(err)
                        throw err;
                      return done(null, user);
                    });
                  }else{
                    User.findOne({'linkedin.email': profile.emails[0].value}, function (err, user) {
                      if(!req.user){
                        if(err)
                          return done(err);
                        if(user){
                          if(!user.linkedin.token){
                            sign(user, profile, 'linkedin', accessToken).save(function(err){
                              if(err)
                                throw err;
                            });
                          }
                          return done(null, user);
                        }else{
                          var newUser = new User();

                          sign(newUser, profile, 'linkedin', accessToken).save(function(err) {
                            if(err)
                              throw err;
                            return done(null, newUser);
                          });
                        }
                      }else{
                        var user = req.user;

                        sign(user, profile, 'linkedin', accessToken).save(function(err) {
                          if(err)
                            throw err;
                          return done(null, user);
                        });
                      }
                    });
                  }
                }); 
              }
            });
          }
        });
      });
    }
  ));

  passport.use(new GoogleStrategy({
      clientID: configAuth.googleAuth.clientID,
      clientSecret: configAuth.googleAuth.clientSecret,
      callbackURL: configAuth.googleAuth.callbackURL,
      passReqToCallback: true
    },
    function(req, accessToken, refreshToken, profile, done) {
      process.nextTick(function() {
        User.findOne({'facebook.email': profile.emails[0].value}, function (err, user) {
          if(err)
            return done(err);
          if(user){
            sign(user, profile, 'google', accessToken).save(function(err) {
              if(err)
                throw err;
              return done(null, user);
            });
          }else{
            User.findOne({'linkedin.email': profile.emails[0].value}, function (err, user) {
              if(err)
                return done(err);
              if(user){
                sign(user, profile, 'google', accessToken).save(function(err) {
                  if(err)
                    throw err;
                  return done(null, user);
                });
              }else{
                User.findOne({'local.username': profile.emails[0].value}, function (err, user) {
                  if(err)
                    return done(err);
                  if(user){
                    sign(user, profile, 'google', accessToken).save(function(err) {
                      if(err)
                        throw err;
                      return done(null, user);
                    });
                  }else{
                    User.findOne({'google.email': profile.emails[0].value}, function (err, user) {
                      if(!req.user){
                        if(err)
                          return done(err);
                        if(user){
                          if(!user.google.token){
                            sign(user, profile, 'google', accessToken).save(function(err){
                              if(err)
                                throw err;
                            });
                          }
                          return done(null, user);
                        }else{
                          var newUser = new User();

                          sign(newUser, profile, 'google', accessToken).save(function(err) {
                            if(err)
                              throw err;
                            return done(null, newUser);
                          });
                        }
                      }else{
                        var user = req.user;

                        sign(user, profile, 'google', accessToken).save(function(err) {
                          if(err)
                            throw err;
                          return done(null, user);
                        });
                      }
                    });
                  }
                });   
              }
            });
          }
        });
      });
    }
  ));
}

function sign(user, profile, provider, accessToken){
  user[provider].id = profile.id;
  user[provider].token = accessToken;
  user[provider].firstName = profile.name.givenName + " " + (profile.name.middleName || "");
  user[provider].lastName = profile.name.familyName;
  user[provider].email = profile.emails[0].value;
  return user;
}