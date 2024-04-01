var jwt = require('jsonwebtoken')
var config = require('../configs/config');
var responseHandle = require('../helpers/responseHandle');
module.exports = function (req, res, next) {
    if (!req.headers.authorization || !req.headers.authorization.startsWith("Bearer")) {
        responseHandle.renderResponse(res, false, "yeu cau dang nhap");
        return;
    }
    let token = req.headers.authorization.split(" ")[1];
    try {
        var result = jwt.verify(token, config.JWT_SECRET);
        if (result.exp * 1000 > Date.now()) {
            req.userId= result.id;
            next();
        } else {
            responseHandle.renderResponse(res, false, "yeu cau dang nhap");
        }
    } catch (error) {
        responseHandle.renderResponse(res, false, "yeu cau dang nhap");
    }
}