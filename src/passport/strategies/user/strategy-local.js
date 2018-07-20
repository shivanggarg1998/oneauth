/**
 * Created by championswimmer on 07/05/17.
 */
const Raven = require('raven')
const LocalStrategy = require('passport-local').Strategy
const models = require('../../../db/models').models

const passutils = require('../../../utils/password')


/**
 * This is to authenticate _users_ using a username and password
 * via a simple post request
 */

module.exports = new LocalStrategy(async function (username, password, cb) {

    Raven.setContext({extra: {file: 'localstrategy'}})
    try{
        const re = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        var userLocal;
        if(re.test(username))
        {
        userLocal = await models.UserLocal.findOne({
            include: [{model: models.User, where: {email: username}}],
        })
    }else{
        userLocal = await models.UserLocal.findOne({
            include: [{model: models.User, where: {username: username}}],
        })
    }
        if (!userLocal) {
            return cb(null, false, {message: 'Invalid Username/Email'})
        }

        const match = await passutils.compare2hash(password, userLocal.password)
        if (match) {
            return cb(null, userLocal.user.get())
        } else {
            return cb(null, false, {message: 'Invalid Password'})
        }

    }catch(err) {
        Raven.captureException(err)
        return cb(null, false, {message: 'Could not create account'})
    }
})
