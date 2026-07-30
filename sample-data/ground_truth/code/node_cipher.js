const crypto = require('crypto');

const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
