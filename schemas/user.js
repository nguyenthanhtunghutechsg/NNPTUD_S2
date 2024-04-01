var mongoose = require("mongoose");
var bcrypt = require('bcrypt');
var jwt = require('jsonwebtoken')
var config = require('../configs/config')

var userSchema = new mongoose.Schema({
    username: {
        type: String,
        unique: true
    },
    password: String,
    role: {
        type: [String]
    },
    status: {
        type: Boolean,
        default: true
    },
    email: String
}, { timestamps: true })

userSchema.pre('save', function () {
    this.password = bcrypt.hashSync(this.password, 10);
})

userSchema.methods.genJWT = function () {
    return jwt.sign({
        id: this._id
    }, config.JWT_SECRET, {
        expiresIn: config.JWT_EXP
    })
}

module.exports = new mongoose.model('user', userSchema);