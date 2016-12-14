const md5 = require('md5')
const passport = require('passport')
const session = require('express-session')
const GoogleStrategy = require('passport-google-oauth').OAuth2Strategy
const FacebookStrategy = require('passport-facebook').Strategy
const redis = require('redis').createClient(process.env.REDIS_URL)
const cookieParser = require('cookie-parser')

const isLocal = false

// # heroku config | grep REDIS
// # heroku config:set GOOGLE_SECRET foobar
// const clientSecret = process.env.GOOGLE_SECRET
const clientSecret = "Iu3m9HNilrQ5oSMPQB9p7UhA"
const clientID = "382295936765-f6ifjt2so64q0krvijg06rsoktetot0n.apps.googleusercontent.com"
const callbackURL = isLocal ? 'http://localhost:3000/auth/google_callback' : 'https://rb-backend-ys2016-final.herokuapp.com/auth/google_callback'
const configAuth = {clientSecret, clientID, callbackURL}

const fb_clientSecret = "95d96480c7eb36c46588417c479a703e"
const fb_clientID = "983028555174660"
const fb_callbackURL = isLocal ? 'http://localhost:3000/auth/facebook/callback' : 'https://rb-backend-ys2016-final.herokuapp.com/auth/facebook/callback'
const fb_configAuth = {clientSecret : fb_clientSecret, clientID : fb_clientID, callbackURL : fb_callbackURL}

const User = require('./model.js').User
const Profile = require('./model.js').Profile
const Article = require('./model.js').Article

const getUser = (username, callback) => {
    User.find({ username : username}).exec(callback)

}

const cookieKey = 'sid'
// key : sid, value : username
const sessionUser = {}


const generateCode = (userObj) => {
	const code = md5(userObj.username)
	return code
}

const mergeUserRecord = (userToLink, logginUser) => {
    console.log(`mergeUserRecord : ${userToLink}`)
    let query = { username : logginUser}
    let update = { auth : {'google' : userToLink, 'normal' : logginUser}}
    User.findOneAndUpdate(query, update, {new : true}).exec()
        .then(user => {
            if (user) {
                console.log(user)
            }
            // remove linking user record
            User.findOneAndRemove({username: userToLink}).exec()
                .then(doc => {
                    console.log(`findOneAndRemove ${doc}`)
                })
            // update all the linking user's articles author in parallel
            Article.update({author: userToLink}, {author: logginUser}).exec()
            // update all the comments
            query = {"comments.author": userToLink}
            update = {"$set": {"comments.$.author": logginUser}}
            Article.update(query, update).exec()
        })
        // merge all the followings
        .then(Profile.findOne({ username : userToLink}).exec()
            .then(profile => {
                if (profile) {
                    return profile.following
                }
            })
            .then(following => {
                update = {"$addToSet" : { "$each" : {following : following}}}
                console.log(update)
                Profile.findOneAndUpdate({username : logginUser},
                    update, {new : true}).exec()
                    .then(newProfile => {
                        console.log(newProfile)
                    })
            })

        )
        .catch(err => {
            console.log(err)
        })
}

// POST /login
// {username: username, password: password }	
// { username: :user, result: "success"}	
// log in to server, sets session id and hash cookies
const login = (req, res) => {
	console.log(req.body)
    console.log('call login')
    var username = req.body.username
	var password = req.body.password
	if (!username || !password) {
		res.status(400).send('does not provide username or password')
		return
	}
	getUser(username, function (err, users) {
        if (!err) {
            if (users.length === 0) {
                console.log(`can\'t find user ${username}`)
                return
            } else {
                console.log('find the user : ', users[0])
                const userObj =  users[0]
                console.log('login : ')
                console.log(userObj)
                if (!userObj) {
                    // unauthorized
                    res.status(401).send('user does not exist')
                    return
                }
                const hash = md5(userObj.salt + password)
                if (hash !== userObj.hash) {
                    // unauthorized
                    res.status(401).send('password does not match')
                    return
                }
                if (req.cookies['userToLink']) {
                    mergeUserRecord(req.cookies['userToLink'], username)
                }
                req.username = username
                // autherized, set cookie and send back message
                // Store the session id in an in-memory map from session to user
                const cookieValue = generateCode(userObj)
                // sessionUser[cookieValue] = username
                redis.hmset(cookieValue, userObj)
                res.cookie(cookieKey, cookieValue, { maxAge : 3600*1000, httpOnly : true})
                console.log('set cookies : ', req.cookies)
                const msg = {username : username, result : "success"}
                res.send(msg)
            }
        } else {
            throw err
        }
    })
}

// POST /register
// request payload : { username, email, dob, zipcode, password}	
// response payload : { result: 'success', username: username}	
const register = (req, res) => {
    console.log('call register')
	console.log(req.body)
	var username = req.body.username
	var password = req.body.password
	var email = req.body.email
	var dob = req.body.dob
	var zipcode = req.body.zipcode


    getUser(username, function (err, users) {
        if (!err) {
            if (users.length > 0) {
                console.log(`${username} has already been registered.`)
                res.send(409, {error : `${username} has already been registered.`})
                return
            } else {
                const userObj = { username }
                userObj.salt = 'some long long salt' + username +
                    Math.random().toString() + new Date().getTime().toString()
                userObj.hash = md5(userObj.salt + password)
                userObj.auth = {"normal" : username}
                // users.users.push(userObj)
                const profileObj = { username, email, dob, zipcode }
                profileObj.headline = ""
                profileObj.following = []
                profileObj.avatar = "http://ocramius.github.io/presentations/proxy-pattern-in-php/assets/img/gh.svg"

                new User(userObj).save(function(err, doc) {
                    if (err) {
                        res.send(err)
                    } else {
                        console.log('save user successfully! ', doc)
                        new Profile(profileObj).save(function (err, doc) {
                            if (err) {
                                res.send(err)
                            } else {
                                console.log('save profile successfully! ', doc)
                                const msg = {username : username, result : "success"}
                                res.send(msg)
                            }
                        })
                    }
                })
            }
        } else {
            throw err
            res.send(err)
        }
    })

}

const isLoggedIn = (req, res, next) => {
	// read cookie
    console.log('call isLoggedIn')
	console.log(req.cookies)
	const sid = req.cookies[cookieKey]
    if (req.cookies['userToLink']) {
	    req.userToLink = req.cookies['userToLink']
        console.log(`userToLink ${req.userToLink}`)
    }

    if (req.isAuthenticated()) {
	    console.log('third-party login successfully')
	    req.username = req.user.username
        next()
    } else {
        if (!sid) {
            return res.status(401).send('sid undefined - user session does not exist')
        }

        // const username = sessionUser[sid]
        redis.hgetall(sid, function (err, userObj) {
            console.log(sid + ' mapped to ', userObj.username)
            if (userObj.username) {
                const username = userObj.username
                req.username = username
                next()
            } else {
                res.status(401).send('user session does not exist')
            }
        })
    }

}

// PUT /logout
// /logout	PUT	none	OK	
// log out of server, clears session id
const logout = (req, res) => {
    if (req.isAuthenticated()) {
        req.logout()
    } else {
        const username = req.username
        console.log('log out as ', username)
        // clear session id and set empty cookie
        const sid = req.cookies[cookieKey]
        // delete sessionUser[sid]
        redis.del(sid)
        res.clearCookie(cookieKey)
    }
    res.clearCookie('userToLink')
	res.send('OK')
}

// /sample	GET	none
// [ { id: 1, author: Scott, ... }, { ... } ]	Array of sample posts.
const getSample = (req, res) => {
	res.send('array of sample posts.')
}

const profile = (req, res) => {
    console.log('log in as google')
    // console.log(req)
    res.send(`log in as google : ${req.username}`)
}

const fail = (req, res) => {
    res.send(401, 'log in failed.')
}

const updatePassword = (req, res) => {
    const user = req.username
    const query = { username : user}
    const newSalt = 'some long long salt' + user +
        Math.random().toString() + new Date().getTime().toString()
    const newHash = md5(newSalt + req.body.password)
    const update = { salt : newSalt,  hash : newHash}
    console.log(update)
    User.findOneAndUpdate(query, update, {new : true}).exec()
        .then(doc => {
            console.log('password change : ', doc)
            res.send({ username : user,
                message : 'Password has changed, please log out and log in again'})
        })
        .catch(err => {
            res.send(404, err)
        })
}

const getAuthType = (req, res) => {
    const user = req.username
    const query = { username : user}
    User.findOne(query).exec()
        .then(doc => {
            console.log('get authType', doc)
            res.send(doc.auth)
        })
        .catch(err => {
            res.send(404, err)
        })
}

// used to serialize the user for the session
passport.serializeUser(function(user, done) {
    console.log("serializeUser", user)
    done(null, user._id)
})

// used to deserialize the user
passport.deserializeUser(function(id, done) {
    console.log("deserializeUser", id)
    User.findOne({ _id : id}).exec()
        .then(user => {
            done(null, user)
        })
        .catch(err => {
            console.log(err)
        })
})

// Configure the Google strategy for use by Passport.js.
passport.use(new GoogleStrategy(configAuth, function (accessToken, refreshToken, profile, done) {
    // Extract the minimal profile information we need from the profile object
    process.nextTick(function () {
        console.log('TICK!')
        console.log(accessToken)
        console.log(profile)
        const displayName = (profile.displayName === '') ?
            `${profile.emails[0].value}@google` : `${profile.displayName}@google`
        User.findOne({ username : displayName }).exec()
            .then(user => {
                if (user) {
                    console.log(`${user} exist.`)
                    return done(null, user)
                } else {
                    // similar to register
                    const newUser = {}
                    newUser.auth = {"google" : displayName}
                    newUser.username = displayName
                    newUser.salt = ""
                    newUser.hash = ""
                    const newProfile = {}
                    newProfile.username = displayName
                    newProfile.email = profile.emails[0].value
                    newProfile.dob = new Date()
                    newProfile.zipcode = ""
                    newProfile.headline = ""
                    newProfile.following = []
                    newProfile.avatar = profile.photos[0].value
                    new User(newUser).save()
                        .then(doc => {
                            console.log('save user successfully! ', doc)
                            return doc
                        })
                        .then(doc => {
                            new Profile(newProfile).save()
                                .then(profile => {
                                    console.log('save profile successfully! ', profile)
                                })
                                return doc
                            }
                        )
                        .then(doc => {
                            return done(null, doc)
                        })
                }

            })
            .catch(err => {
                return done(err)
            })

    })
}))

passport.use(new FacebookStrategy(fb_configAuth, function (accessToken, refreshToken, profile, done) {
    // Extract the minimal profile information we need from the profile object
    process.nextTick(function () {
        console.log('TICK!')
        console.log(accessToken)
        return done(null, profile)
    })
}))


module.exports = {
    auth : (app) => {
        app.use(cookieParser())
        app.use(session({ secret : 'someSecret'}))
        app.use(passport.initialize())
        app.use(passport.session())
        app.post('/login', login)
        app.post('/register', register)
        app.get('/sample', getSample)
        app.use('/auth/google/login', (req, res, next) => {
                console.log(`oauth login from ${req.headers.referer}`)
                app.locals.frontend_url = req.headers.referer
                next()
            }, passport.authenticate('google', {scope : 'email'}))
        app.use('/auth/google_callback', passport.authenticate('google', {
            failureRedirect : '/fail'
        }), (req, res) => {
            const frontend_url = app.locals.frontend_url
            console.log(`redirect to ${frontend_url}`)
            res.redirect(frontend_url)
        })

        app.use('/auth/facebook/callback', passport.authenticate('facebook', {
            successRedirect : '/profile',
            failureRedirect : '/fail'
        }))
        app.use('/auth/facebook/login', passport.authenticate('facebook', {scope : 'email'}))

        app.put('/logout', isLoggedIn, logout)
        app.use('/profile', isLoggedIn, profile)
        app.use('/fail', fail)
        app.put('/password', isLoggedIn, updatePassword)
        app.get('/authType', isLoggedIn, getAuthType)
    },
    isLoggedIn
}
