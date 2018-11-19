"use strict";


/********* External Imports ********/

var lib = require("./lib");

var KDF = lib.KDF,
    HMAC = lib.HMAC,
    SHA256 = lib.SHA256,
    setupCipher = lib.setupCipher,
    encryptwithGCM = lib.encryptwithGCM,
    decryptWithGCM = lib.decryptWithGCM,
    bitarraySlice = lib.bitarraySlice,
    bitarrayToString = lib.bitarrayToString,
    stringToBitarray = lib.stringToBitarray,
    bitarrayToBase64 = lib.bitarrayToBase64,
    base64ToBitarray = lib.base64ToBitarray,
    stringToPaddedBitarray = lib.stringToPaddedBitarray,
    paddedBitarrayToString = lib.paddedBitarrayToString,
    randomBitarray = lib.randomBitarray,
    bitarrayEqual = lib.bitarrayEqual,
    bitarrayLen = lib.bitarrayLen,
    bitarrayConcat = lib.bitarrayConcat,
    objectHasKey = lib.objectHasKey;


/********* Implementation ********/


var keychainClass = function() {

  // Private instance variables.
    
  // Use this variable to store everything you need to.
  var priv = {
    secrets: { /* Your secrets here */ },
    data: { /* Non-secret data here */ }
  };

  // Maximum length of each record in bytes
  var MAX_PW_LEN_BYTES = 64;
  
  // Flag to indicate whether password manager is "ready" or not
  var ready = false;

  var keychain = {};

  /** 
    * Creates an empty keychain with the given password. Once init is called,
    * the password manager should be in a ready state.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  keychain.init = function(password) {
	  priv.data.version = "CS 255 Password Manager v1.0";
	  
//	  var pass = stringToBitarray(password);
	  var salt = stringToBitarray("salt");
	  var pass = KDF(SHA256(password), salt);
	  priv.secrets.aeskey = bitarraySlice(pass, 0, 128);
	  priv.secrets.hmackey = bitarraySlice(pass, 128, 255);
	  priv.data.cipher = setupCipher(priv.secrets.aeskey);
	  ready = true;
  };

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the save function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object). Returns true if the data is successfully loaded
    * and the provided password is correct. Returns false otherwise.
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: boolean
    */
  keychain.load = function(password, repr, trustedDataCheck) {
	  var calculated = bitarrayToBase64(SHA256(stringToBitarray(repr)));
	  if(calculated != trustedDataCheck)
	  {
		  throw "Hash doesn't match";
	  }
	  keychain.init(password);
	  keychain = JSON.parse(repr);
	  /*try
	  {
		  for(var keys in keychain)
		  {
			  decryptWithGCM(priv.data.cipher, keychain[keys]);
		  }
	  }
	  catch(e)
	  {
		  return false;
	  }*/
	  return true;
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity. If the
    * password manager is not in a ready-state, return null.
    *
    * Return Type: array
    */ 
  keychain.dump = function() {
	  if(!ready)
	  {
		  return null;
	  }
	  return [JSON.stringify(keychain), bitarrayToBase64(SHA256(stringToBitarray(JSON.stringify(keychain))))];
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null. If the password manager is not in a ready state, throw an exception. If
    * tampering has been detected with the records, throw an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: string
    */
  keychain.get = function(name) {
	  if(!ready)
	  {
		  throw "Keychin is not ready";
	  }

	  var keynam = HMAC(priv.secrets.hmackey, name);
	  var keypos = keychain[keynam];
	  if(keypos == undefined)
	  {
		  return null;
	  }
	  else
	  {
		  //decrypt message
		  var msg = decryptWithGCM(priv.data.cipher, keypos);
		  return bitarrayToString(msg);
	  }
  };

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager. If the password manager is
  * not in a ready state, throw an exception.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  keychain.set = function(name, value) {
	  if(!ready)
	  {
		  throw "Keychin is not ready";
	  }
	  var keyname = HMAC(priv.secrets.hmackey, name);
	  var keyval = encryptwithGCM(priv.data.cipher, stringToBitarray(value));
	  keychain[keyname] = keyval;
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise. If
    * the password manager is not in a ready state, throws an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: boolean
  */
  keychain.remove = function(name) {
	  if(!ready)
	  {
		  throw "Keychin is not ready";
	  }
	  var nameindex = HMAC(priv.secrets.hmackey, name);
	  if(keychain[nameindex])
	  {
		  delete keychain[nameindex];
		  return true;
	  }
	  return false;
  };

  return keychain;
};

module.exports.keychain = keychainClass;
