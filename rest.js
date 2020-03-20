// Require relative to project root
require('rootpath')()

const config = require('config')

const { logger } = require('utils/logger')
// Initialize logger
logger.setLevel(config.LOG_LEVEL)
logger.info('Starting server...')

const app = require('express')()
const https = require('https')

// TODO: require('utils/rate-limit')

// Register request middleware (order matters)
app.use(logger.requestLogger)
app.use(require('cors')({
    origin: config.CORS_DOMAINS,
    methods: 'GET,POST,PUT,DELETE',
    credentials: true
}))
app.use(require('helmet')())
app.use(require('cookie-parser')())
app.use(require('utils/jwt')())
app.use(require('body-parser').urlencoded({ extended: false }))
app.use(require('body-parser').json())
app.use(require('utils/account-logger').accountLogger)

// Register API Routes
app.use(config.API_PREFIX + '/users',   require('routes/users'))
app.use(config.API_PREFIX + '/auth',    require('routes/auth'))

// Register error handling middleware
app.use(require('utils/errors').handleError)

// Start server
let server
if (config.HTTPS_ENABLED) {
    // HTTPS server
    const fs = require('fs')
    server = https.createServer({
        key: fs.readFileSync(config.HTTPS_KEY_FILE),
        cert: fs.readFileSync(config.HTTPS_CERT_FILE)
    }, app).listen(config.PORT)
} else {
    // HTTP server
    server = app.listen(config.PORT, () => logger.info('Server listening on port: ' + config.PORT))
}

const db = require('utils/db')()

// Closing server when process is stopped
process.on('SIGINT', () => {
    // Closing MongoDB connection
    logger.info('Closing MongoDB connection...')
    db.close(false, () => logger.info('MongoDB connection closed'))

    // Closing HTTP server
    logger.info('Closing server...')
    server.close(() => {
        logger.info('Server closed')
        process.exit(0)
    })
})