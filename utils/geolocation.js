'use strict'

const logger = require('utils/logger').logger
const config = require('config')
const fs = require('fs')
const maxmind = require('maxmind')

// Load database once
let lookup = null
if (config.GEO_DB_PATH) {
    logger.info('Geolocation database path provided. Loading...')
    try {
        lookup = new maxmind.Reader(fs.readFileSync(config.GEO_DB_PATH))
        logger.info('Geolocation database loaded')
    } catch (err) {
        logger.warn(err)
    }
}

module.exports = async function(ip, pretty=true) {
    return new Promise((resolve, reject) => {
        if (!lookup) return reject('No geolocation database loaded!')
        if (!maxmind.validate(ip)) return reject('Invalid IP address provided: ' + ip + '!')

        const raw = lookup.get(ip)
        if (!raw) return reject('No location found for IP address: ' + ip + '!')
        if (!pretty) return resolve(raw)

        const city = raw.city ? raw.city.names.en : null
        const subd = raw.subdivisions && raw.subdivisions.length !== 0 ? raw.subdivisions[0].names.en : null
        const subd_code = raw.subdivisions && raw.subdivisions.length !== 0 ? raw.subdivisions[0].iso_code : null
        const country = raw.country.names.en
        const country_code = raw.country.iso_code

        return resolve(`${city ? city + ', ' : ''}${subd ? `${subd}, (${subd_code}), ` : ''}${country} (${country_code})`)
    })
}