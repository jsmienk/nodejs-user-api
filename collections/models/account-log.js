const mongoose = require('mongoose')
const Schema = mongoose.Schema

/*
_id (by MongoDB)
user    ObjectId
date    Date    
ip      String  
type    Number  
*/

const log = new Schema({
    user: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    date: { type: Date, required: true, default: Date.now },
    ip: { type: String, required: true },
    type: { type: Number, required: true }
})

// log.set('toJSON', { virtuals: true })

module.exports = mongoose.model('AccountLog', log)
