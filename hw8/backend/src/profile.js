const multer = require('multer')
const stream = require('stream')
const uploadImage = require('./uploadCloudinary').uploadImage

if (!process.env.CLOUDINARY_URL) {
    process.env.CLOUDINARY_URL="cloudinary://365686241836513:d5_fD-24mTt6KFlYL7osaIaEDLg@hmzohj0ob"
}

const Profile = require('./model.js').Profile
const User = require('./model.js').User

const getProfile = (username, callback) => {
    Profile.find({ username : username}).exec(callback)

}

const updateProfile = (query, update, callback, options) => {
    console.log(query)
    console.log(update)
    Profile.findOneAndUpdate(query, update, options).exec(callback)
}

// get field for single user
const getField = (field) => {
    return (req, res) => {
        const user = req.params.user ? req.params.user : req.username
        getProfile(user, function (err, profile) {
            if (!err) {
                // console.log(profile)
                if (profile.length === 0) {
                    res.send(404, `can't find ${user}`)
                } else {
                    const result = {}
                    result["username"] = user
                    result[field] = profile[0][field]
                    res.send(result)
                }
            } else {
                res.send(404, err)
            }
        })
    }
}

// get field for a list of user
const getFieldWithIdList = (fields, field) => {
    return (req, res) => {
        const user = req.username
        const users = req.params.users ? req.params.users.split(',') : [req.username]

        // this returns only one headline, but we want to send
        // an array of all the requested user's headlines
        // const cond = {}
        console.log(`getFieldWithIdList ${users}`)
        const cond = { "username" : { "$in" : users}}

        Profile.find(cond).exec(function (err, profiles) {
            // console.log(profiles)
            if (err) {
                res.send(404, err)
                return
            }
            if (profiles) {
                const retList = profiles.map(x => {
                    const result = {}
                    result["username"] = x.username
                    result[field] = x[field]
                    return result
                })
                const ret = {}
                ret[fields] = retList
                res.send(ret)
            }
        })
    }
}

const putField = (field, data) => {
    return (req, res) => {
        const user = req.username
        const query = { username : user}
        const update = {}
        update[field] = (field === 'avatar') ? req[data] : req.body[data]
        updateProfile(query, update, function (err, doc) {
            if (!err) {
                // console.log(doc)
                update.username = user
                res.send(update)
            } else {
                res.send(404, err)
            }
        })
    }
}

const linkAccount = (req, res) => {
    // set the cookie with userToLink field
    // third party login
    if (req.isAuthenticated()) {
        const frontendUrl = req.headers.referer
        const user = req.username
        req.logout()
        res.cookie('userToLink', user, { maxAge : 3600*1000, httpOnly : true})
        console.log('linkAccount set cookies : ', req.cookies)
        res.redirect(frontendUrl)
    } else {
        res.redirect('/auth/google/login')
    }
}

const unlinkAccount = (req, res) => {
    const query = { username : req.username}
    const update = { auth : {'normal' : req.username}}
    User.findOneAndUpdate(query, update, {new : true}).exec()
        .then(doc => {
            console.log('unlinkAccount : ', doc)
            const frontendUrl = req.headers.referer
            res.redirect(frontendUrl)
        })
        .catch(err => {
            res.send(404, err)
        })
}

module.exports = {
    profile : app => {
        app.get('/headlines/:users*?', getFieldWithIdList('headlines', 'headline'))
        app.put('/headline', putField('headline', 'headline'))
        app.get('/email/:user?', getField('email'))
        app.put('/email', putField('email', 'email'))
        app.get('/zipcode/:user?', getField('zipcode'))
        app.put('/zipcode', putField('zipcode', 'zipcode'))
        app.get('/avatars/:users*?', getFieldWithIdList('avatars', 'avatar'))
        app.put('/avatar', uploadImage('avatar'), putField('avatar', 'fileurl'))
        app.get('/dob', getField('dob'))
        app.use('/linkAccount', linkAccount)
        app.use('/unlinkAccount', unlinkAccount)

    },
    getProfile,
    updateProfile,
    getField
}
