const mongoose = require('mongoose')
const Schema = mongoose.Schema

/*
_id (by MongoDB)
*/

const login = new Schema({
    // user: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    // date: { type: Date, required: true, default: Date.now },
    // ip: { type: String, required: true },
    // type: { type: Number, required: true }
})

// login.set('toJSON', { virtuals: true })

module.exports = mongoose.model('DeviceSession', login)
