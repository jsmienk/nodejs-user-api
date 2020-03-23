const mongoose = require('mongoose')
const Schema = mongoose.Schema

/*
_id (by MongoDB)
since       Date    Date since last authentication
ip          String  IP of device that was authenticated with
expires     Number  Expire
location    String  City, Subdivision, Country
platform    String  e.g. MacOS 13.0.1
application String  e.g. Chrome 46
*/
const session = new Schema({
    hash: { type: String, required: true, index: true },
    user: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    since: { type: Date, required: true, default: Date.now },
    ip: { type: String, required: true },
    expires: { type: Number, required: true },
    location: { type: String },
    platform: { type: String },
    application: { type: String }
})

module.exports = mongoose.model('DeviceSession', session)