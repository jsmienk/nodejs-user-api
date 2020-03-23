'use strict'

const config = require('config')
const mongoose = require('mongoose')
const logger = require('utils/logger').logger

module.exports = () => {
    logger.info('Starting MongoDB connection...')
    mongoose.connect(config.MONGODB_URI, {
            useUnifiedTopology: true,
            useCreateIndex: true,
            useNewUrlParser: true,
            useFindAndModify: false
        })
        .then(() => logger.info('Mongoose connection success'))
        .catch(err => logger.warn(err.message))

    // Future errors
    mongoose.connection.on('error', err => logger.warn(err.message))
    return mongoose.connection
}