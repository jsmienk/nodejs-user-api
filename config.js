/* GENERAL */
const APP_NAME = 'project'
const API_PREFIX = '/api/v0'
const PORT = 3000

const { level } = require('utils/logger')
const LOG_LEVEL = level.DEBUG

/* SECURITY */
const HTTPS_ENABLED = false
const CORS_DOMAINS = ['http://127.0.0.1:8080', 'http://localhost:8080']

/* MONGODB */
const MONGODB_NAME = 'development'
const MONGODB_PASS = process.env.MONGODB_PASS || 'development'
const MONGODB_HOST = '127.0.0.1'
const MONGODB_PORT = 27017
const MONGODB_DB = 'dinnertime'
const MONGODB_URI = 'mongodb://' + MONGODB_NAME + ':' + MONGODB_PASS + '@' + MONGODB_HOST + ':' + MONGODB_PORT + '/' + MONGODB_DB + '?authSource=' + MONGODB_DB

const NAME_REGEX = /^([\p{L}0-9][',.-]?[ ]?)+$/u
const EMAIL_REGEX = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/

/* JWT */
const JWT_SECRET = process.env.JWT_SECRET || 'development'
const JWT_EXPIRES_IN =     1*60*60  // 1 hour
const JWT_PW_RESET_TIME =  15*60    // 15 minutes
const JWT_PW_VERIFY_TIME = 15*60    // 15 minutes

/* BCRYPT */
const BCRYPT_ROUNDS = 10
const MIN_PASS_LENGTH = 8


/*
Required exports:
- APP_NAME           Name of the client application this API serves
- API_PREFIX         Path prefixed to all routes, E.g. /api/v0/users/1234
- PORT               Port of the server to run on
- HTTPS_ENABLED      If HTTPS is enabled
- MONGODB_URI        URI of the MongoDB to connect to
- JWT_SECRET         Secret for the JWT validation
- JWT_HOURS          Number of hours after which the JWT expires
- JWT_PW_RESET_TIME  Number of seconds after which the password reset token expires
- JWT_PW_VERIFY_TIME Number of seconds after which the account verification token expires
- NAME_REGEX         Regex for username validation
- EMAIL_REGEX        Regex for email validation
- BCRYPT_ROUNDS      Salt rounds for the Bcrypt algorithm
*/
module.exports = {
    APP_NAME,
    API_PREFIX,
    PORT,
    LOG_LEVEL,
    HTTPS_ENABLED,
    CORS_DOMAINS,
    MONGODB_URI,
    JWT_SECRET,
    JWT_EXPIRES_IN,
    JWT_PW_RESET_TIME,
    JWT_PW_VERIFY_TIME,
    NAME_REGEX,
    EMAIL_REGEX,
    BCRYPT_ROUNDS,
    MIN_PASS_LENGTH
}
