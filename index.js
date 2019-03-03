const bcrypt = require('bcrypt');
const crypto = require('crypto');

var enc = {
    getHashedPassword: function(plain_str, salt) {
        salt =  salt || '';
        const pwdHash = crypto.createHash('sha1').update(plain_str).digest('hex');
        const l1 = crypto.createHash('sha1').update(salt+pwdHash).digest('hex');
        return crypto.createHash('sha1').update(salt+l1).digest('hex');
    },
    getRandomStr: function(len) {
        len = len || 10;
        const str = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        let generated = '';
        for(let i=0; i<len; i++) {
            generated += str[Math.floor(Math.random()*str.length)]
        }
        return generated;
    },
    toMD5: function (plain_str) {
        return crypto.createHash('md5').update(plain_str).digest('hex');
    },
    matchPassword : function(plainPassword, hashedPassword, callback) {
        bcrypt.compare(plainPassword, hashedPassword, function(err, isPasswordMatch) {
            callback(err, isPasswordMatch);
        });
    },
    matchUsingSalt : function(options, callback) {
        var plain = options.password || options.plain;
        var salt = options.salt;
        var hashedPassword = options.hash || options.hashedPassword;

        try {
            // a MD5 hash
            var md5 = this.toMD5(plain);
            //console.log('The MD5 hash is %s', md5);

            //for OpenCart, using following formula:
            //SHA1(salt+SHA1(salt+SHA1(password)))
            var pwdHash = crypto.createHash('sha1').update(plain).digest('hex');
            var l1 = crypto.createHash('sha1').update(salt+pwdHash).digest('hex');
            var sha1 = crypto.createHash('sha1').update(salt+l1).digest('hex');
            //console.log('The SHA1 hash is %s', sha1);

            var match = sha1==hashedPassword || md5==hashedPassword;
            callback(null, match);
        } catch(e) {
            callback(e);
        }
    }
};
module.exports = enc;