const Base64 = require('js-base64').Base64;
const { JwtTypeError, JwtError } = require('./errors');
const strUtil = require('./strUtil');

const util = module.exports = {};

module.exports = {
  decodeJwtString(string) {
    if (!string || !strUtil.isString(string)) {
      throw new JwtTypeError('A jwt must be provided as a string');
    }
  
    const parts = string.split('.');
    if (parts.length !== 3) {
      throw new JwtError('The jwt must have a header, claims set and signature');
    }
  
    const b64uHeader = parts[0];
    const b64uClaimsSet = parts[1];
    const b64uSignature = parts[2];
    
    let header;
    try {
      header = JSON.parse(Base64.decode(b64uHeader));
    } catch (e) {
      throw new JwtError('The jwt header is malformed');
    }

    let claimsSet;
    try {
      claimsSet = JSON.parse(Base64.decode(b64uClaimsSet));
    } catch (e) {
      throw new JwtError('The jwt claims set is malformed');
    }
    
    return {
      header,
      claimsSet,
      b64uSignature,
      b64uHeader,
      b64uClaimsSet
    };
  }
};