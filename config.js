'use strict'

/* GENERAL */
const APP_NAME = 'project'
const API_PREFIX = '/api/v0'
const PORT = 3000

const { level } = require('utils/logger')
const LOG_LEVEL = level.INFO

/* SECURITY */
const HTTPS_ENABLED = true
const HTTPS_KEY_FILE = 'ssl/key.pem'
const HTTPS_CERT_FILE = 'ssl/cert.pem'
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

/* AUTH/JWT */
const JWT_SECRET = process.env.JWT_SECRET || 'development'
const JWT_EXPIRES_IN = 30*60          // (seconds) 30 minutes
const JWT_EMAIL_TIME = 20*60          // (seconds) 20 minutes
const JWT_ALG = 'HS256'
const SESSION_EXPIRES_IN = 7*24*60*60 // (seconds) 1 week

/* BCRYPT */
const BCRYPT_ROUNDS = 10
const MIN_PASS_LENGTH = 8

/* EXTRA */
const GEO_DB_PATH = 'geolite2-city/GeoLite2-City.mmdb'


/*
Required exports:
- APP_NAME           Name of the client application this API serves
- API_PREFIX         Path prefixed to all routes, E.g. /api/v0/users/1234
- PORT               Port of the server to run on
- LOG_LEVEL          Verbosity of the server console output
- HTTPS_ENABLED      If HTTPS is enabled
- HTTPS_KEY_FILE     Path to the HTTPS key file
- HTTPS_CERT_TILE    Path to the HTTPS certificate file
- CORS_DOMAINS       Array of CORS allowed domain strings
- MONGODB_URI        URI of the MongoDB to connect to
- JWT_SECRET         Secret for the JWT validation
- JWT_EXPIRES_IN     Number of seconds after which the token JWT expires
- JWT_EMAIL_TIME     Number of seconds after which the account verification and password reset tokens expires
- JWT_ALG            Algorithms to use for signing/verification
- SESSION_EXPIRES_IN Number of aeconds after which the session JWT expires
- NAME_REGEX         Regex for username validation
- EMAIL_REGEX        Regex for email validation
- BCRYPT_ROUNDS      Salt rounds for the Bcrypt algorithm
- MIN_PASS_LENGTH    Minimal length of a user's password

Optional exports:
- GEO_DB_PATH        Path to a MaxMind geolocation database file to convert IP addresses to cities (.mmdb)
*/
module.exports = {
    // required
    APP_NAME,
    API_PREFIX,
    PORT,
    LOG_LEVEL,
    HTTPS_ENABLED,
    HTTPS_KEY_FILE,
    HTTPS_CERT_FILE,
    CORS_DOMAINS,
    MONGODB_URI,
    JWT_SECRET,
    JWT_EXPIRES_IN,
    JWT_EMAIL_TIME,
    JWT_ALG,
    SESSION_EXPIRES_IN,
    NAME_REGEX,
    EMAIL_REGEX,
    BCRYPT_ROUNDS,
    MIN_PASS_LENGTH,

    // optional
    GEO_DB_PATH
}
