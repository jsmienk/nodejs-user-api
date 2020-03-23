const mongoose = require('mongoose')
const Schema = mongoose.Schema

const NAME_REGEX = require('config').NAME_REGEX
const EMAIL_REGEX = require('config').EMAIL_REGEX

/*
_id (by MongoDB)
email       String      Primary email address of user
name        String      Display name provided by user
hash        String      Password hash (generated by bcrypt and includes the salt)
key2FA      String      Secret key for 2FA token generation
use2FA      Boolean     Indicates if this account has 2FA enabled
creation    Date        Datetime the user account was created
verified    Boolean     If the user has verified their email address
log         Array       Log of (login) activity
*/

const user = new Schema({
    // first two are subject to user input
    email: {
        type: String,
        unique: true,
        required: true,
        trim: true,
        match: EMAIL_REGEX,
        minlength: 5,
        maxlength: 256,
        select: false
    },
    name: {
        type: String,
        required: true,
        trim: true,
        match: NAME_REGEX,
        minlength: 2,
        maxlength: 64
    },
    // below is created ourselves
    creation: {
        type: Date,
        required: true,
        default: Date.now
    },
    hash: {
        type: String,
        required: true,
        select: false
    },
    key2FA: {
        type: String,
        select: false
    },
    use2FA: {
        type: Boolean,
        required: true,
        default: false,
        select: false
    },
    verified: {
        type: Boolean,
        required: true,
        default: false,
        select: false
    },
    // below is used by application specific information
    meta: { type: Object }
})

// user.set('toJSON', { virtuals: true })

module.exports = mongoose.model('User', user)
