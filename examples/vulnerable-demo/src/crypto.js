const crypto = require('crypto');
const ecdh = crypto.createECDH('prime256v1');
const cipher = crypto.createCipheriv('aes-128-gcm', key, iv);
const strong = crypto.createCipheriv('aes-256-gcm', key2, iv2);
const h = crypto.createHash('md5').update(data).digest('hex');
