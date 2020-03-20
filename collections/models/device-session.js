const mongoose = require('mongoose')
const Schema = mongoose.Schema

/*
_id (by MongoDB)
*/

const session = new Schema({
    user: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    date: { type: Date, required: true, default: Date.now },
    // TODO
})

// session.set('toJSON', { virtuals: true })

module.exports = mongoose.model('DeviceSession', session)
