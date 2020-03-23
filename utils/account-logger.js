'use strict'

const logger = require('utils/logger').logger

const Users = require('collections/users')

/*
Account event logger middleware

Attach 'accountEvent' property to the response object to log an account related event.

res.accountEvent = {
    userId: user's MongoDB ObjectId,
    type: event type to log
}
*/

const enumEventType = Object.freeze({
    LOGIN_FAIL: 1,
    LOGIN_SUCCESS: 2,
    RESET_REQUEST: 3,
    RESET_SUCCESS: 4,
    INFORMATION_CHANGE_FAIL: 5,
    INFORMATION_CHANGE_SUCCESS: 6,
    EMAIL_VERIFIED: 7,
    _2FA_PREPARED: 8,
    _2FA_ENABLED: 9,
    _2FA_DISABLED: 10,
    _2FA_FAIL: 11,
    _2FA_SUCCESS: 12
})

const accountLogger = (req, res, next) => {
    // Hook on before the request is handled, so we can respond after
    res.on('finish', () => {
        // If an event was passed
        if (res.accountEvent && res.accountEvent.type) {
            const event = res.accountEvent
            // If the event type is one of the predefined ones
            if (Object.values(enumEventType).includes(event.type)) {
                // Log event
                Users.logEvent(event.userId, req.ip, event.type)
                    .then(() => logger.info('Logged event for user ' + event.userId + ': ' + req.ip + ' -- ' + event.type))
                    .catch(err => logger.warn('Error when logging acount event for user ' + event.userId + ':\n\t' + err.message))
            }
        }
    })
    next()
}

module.exports = {
    accountLogger,
    enumEventType
}
