var vows = require('vows'),
    assert = require('assert'),
    events = require('events'),
    OAuth= require('../lib/oauth').OAuth,
    OAuthEcho= require('../lib/oauth').OAuthEcho,
    crypto = require('crypto');

var DummyResponse =function( statusCode ) {
    this.statusCode= statusCode;
    this.headers= {};
}
DummyResponse.prototype= events.EventEmitter.prototype;
DummyResponse.prototype.setEncoding= function() {}

var DummyRequest =function( response ) {
  this.response=  response;
}
DummyRequest.prototype= events.EventEmitter.prototype;
DummyRequest.prototype.end= function(){
  this.emit('response',this.response);
  this.response.emit('end');
}

//Valid RSA keypair used to test RSA-SHA1 signature method
var RsaPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
"MIICXQIBAAKBgQDizE4gQP5nPQhzof/Vp2U2DDY3UY/Gxha2CwKW0URe7McxtnmE\n" +
"CrZnT1n/YtfrrCNxY5KMP4o8hMrxsYEe05+1ZGFT68ztms3puUxilU5E3BQMhz1t\n" +
"JMJEGcTt8nZUlM4utli7fHgDtWbhvqvYjRMGn3AjyLOfY8XZvnFkGjipvQIDAQAB\n" +
"AoGAKgk6FcpWHOZ4EY6eL4iGPt1Gkzw/zNTcUsN5qGCDLqDuTq2Gmk2t/zn68VXt\n" +
"tVXDf/m3qN0CDzOBtghzaTZKLGhnSewQ98obMWgPcvAsb4adEEeW1/xigbMiaW2X\n" +
"cu6GhZxY16edbuQ40LRrPoVK94nXQpj8p7w4IQ301Sm8PSECQQD1ZlOj4ugvfhEt\n" +
"exi4WyAaM45fylmN290UXYqZ8SYPI/VliDytIlMfyq5Rv+l+dud1XDPrWOQ0ImgV\n" +
"HJn7uvoZAkEA7JhHNmHF9dbdF9Koj86K2Cl6c8KUu7U7d2BAuB6pPkt8+D8+y4St\n" +
"PaCmN4oP4X+sf5rqBYoXywHlqEei2BdpRQJBAMYgR4cZu7wcXGIL8HlnmROObHSK\n" +
"OqN9z5CRtUV0nPW8YnQG+nYOMG6KhRMbjri750OpnYF100kEPmRNI0VKQIECQE8R\n" +
"fQsRleTYz768ahTVQ9WF1ySErMwmfx8gDcD6jjkBZVxZVpURXAwyehopi7Eix/VF\n" +
"QlxjkBwKIEQi3Ks297kCQQCL9by1bueKDMJO2YX1Brm767pkDKkWtGfPS+d3xMtC\n" +
"KJHHCqrS1V+D5Q89x5wIRHKxE5UMTc0JNa554OxwFORX\n" +
"-----END RSA PRIVATE KEY-----";

var RsaPublicKey = "-----BEGIN PUBLIC KEY-----\n" +
"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDizE4gQP5nPQhzof/Vp2U2DDY3\n" +
"UY/Gxha2CwKW0URe7McxtnmECrZnT1n/YtfrrCNxY5KMP4o8hMrxsYEe05+1ZGFT\n" +
"68ztms3puUxilU5E3BQMhz1tJMJEGcTt8nZUlM4utli7fHgDtWbhvqvYjRMGn3Aj\n" +
"yLOfY8XZvnFkGjipvQIDAQAB\n" +
"-----END PUBLIC KEY-----";

vows.describe('OAuth').addBatch({
    'When newing OAuth': {
      topic: new OAuth(null, null, null, null, null, null, "PLAINTEXT"),
      'followRedirects is enabled by default': function (oa) {
        assert.equal(oa._clientOptions.followRedirects, true)
      }
    },
    'When generating the signature base string described in http://oauth.net/core/1.0/#sig_base_example': {
        topic: new OAuth(null, null, null, null, null, null, "HMAC-SHA1"),
        'we get the expected result string': function (oa) {
          var result= oa._createSignatureBase("GET", "http://photos.example.net/photos",
                                              "file=vacation.jpg&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_nonce=kllo9940pd9333jh&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1191242096&oauth_token=nnch734d00sl2jdk&oauth_version=1.0&size=original")
          assert.equal( result, "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal");
        }
    },
    'When generating the signature with RSA-SHA1': {
        topic: new OAuth(null, null, null, RsaPrivateKey, null, null, "RSA-SHA1"),
        'we get a valid oauth signature': function (oa) {
            var signatureBase = "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DRSA-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal";
            var oauthSignature = oa._createSignature(signatureBase, "xyz4992k83j47x0b");

            assert.equal( oauthSignature, "qS4rhWog7GPgo4ZCJvUdC/1ZAax/Q4Ab9yOBvgxSopvmKUKp5rso+Zda46GbyN2hnYDTiA/g3P/d/YiPWa454BEBb/KWFV83HpLDIoqUUhJnlXX9MqRQQac0oeope4fWbGlfTdL2PXjSFJmvfrzybERD/ZufsFtVrQKS3QBpYiw=");

            //now check that given the public key we can verify this signature
            var verifier = crypto.createVerify("RSA-SHA1").update(signatureBase);
            var valid = verifier.verify(RsaPublicKey, oauthSignature, 'base64');
            assert.ok( valid, "Signature could not be verified with RSA public key");
        }
    },
    'When generating the signature base string with PLAINTEXT': {
        topic: new OAuth(null, null, null, null, null, null, "PLAINTEXT"),
        'we get the expected result string': function (oa) {
          var result= oa._getSignature("GET", "http://photos.example.net/photos",
                                              "file=vacation.jpg&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_nonce=kllo9940pd9333jh&oauth_signature_method=PLAINTEXT&oauth_timestamp=1191242096&oauth_token=nnch734d00sl2jdk&oauth_version=1.0&size=original",
                                              "test");
          assert.equal( result, "&test");
        }
    },
    'When normalising a url': {
      topic: new OAuth(null, null, null, null, null, null, "HMAC-SHA1"),
      'default ports should be stripped': function(oa) {
        assert.equal( oa._normalizeUrl("https://somehost.com:443/foo/bar"), "https://somehost.com/foo/bar" );
      },
      'should leave in non-default ports from urls for use in signature generation': function(oa) {
        assert.equal( oa._normalizeUrl("https://somehost.com:446/foo/bar"), "https://somehost.com:446/foo/bar" );
        assert.equal( oa._normalizeUrl("http://somehost.com:81/foo/bar"), "http://somehost.com:81/foo/bar" );
      },
      'should add a trailing slash when no path at all is present': function(oa) {
        assert.equal( oa._normalizeUrl("http://somehost.com"),  "http://somehost.com/")
      }
    },
    'When making an array out of the arguments hash' : {
      topic: new OAuth(null, null, null, null, null, null, "HMAC-SHA1"),
      'flatten out arguments that are arrays' : function(oa) {
        var parameters= {"z": "a",
                      "a": ["1", "2"],
                      "1": "c" };
        var parameterResults= oa._makeArrayOfArgumentsHash(parameters);
        assert.equal(parameterResults.length, 4);
        assert.equal(parameterResults[0][0], "1");
        assert.equal(parameterResults[1][0], "z");
        assert.equal(parameterResults[2][0], "a");
        assert.equal(parameterResults[3][0], "a");
      }
    },
    'When ordering the request parameters'  : {
      topic: new OAuth(null, null, null, null, null, null, "HMAC-SHA1"),
      'Order them by name' : function(oa) {
        var parameters= {"z": "a",
                      "a": "b",
                      "1": "c" };
        var parameterResults= oa._sortRequestParams(oa._makeArrayOfArgumentsHash(parameters))
        assert.equal(parameterResults[0][0], "1");
        assert.equal(parameterResults[1][0], "a");
        assert.equal(parameterResults[2][0], "z");
      },
      'If two parameter names are the same then order by the value': function(oa) {
        var parameters= {"z": "a",
                      "a": ["z", "b", "b", "a", "y"],
                      "1": "c" };
        var parameterResults= oa._sortRequestParams(oa._makeArrayOfArgumentsHash(parameters))
        assert.equal(parameterResults[0][0], "1");
        assert.equal(parameterResults[1][0], "a");
        assert.equal(parameterResults[1][1], "a");
        assert.equal(parameterResults[2][0], "a");
        assert.equal(parameterResults[2][1], "b");
        assert.equal(parameterResults[3][0], "a");
        assert.equal(parameterResults[3][1], "b");
        assert.equal(parameterResults[4][0], "a");
        assert.equal(parameterResults[4][1], "y");
        assert.equal(parameterResults[5][0], "a");
        assert.equal(parameterResults[5][1], "z");
        assert.equal(parameterResults[6][0], "z");
      }
    },
    'When normalising the request parameters': {
      topic: new OAuth(null, null, null, null, null, null, "HMAC-SHA1"),
      'the resulting parameters should be encoded and ordered as per http://tools.ietf.org/html/rfc5849#section-3.1 (3.4.1.3.2)' : function(oa) {
        var parameters= {"b5" : "=%3D",
          "a3": ["a", "2 q"],
          "c@": "",
          "a2": "r b",
          "oauth_consumer_key": "9djdj82h48djs9d2",
          "oauth_token":"kkk9d7dh3k39sjv7",
          "oauth_signature_method": "HMAC-SHA1",
          "oauth_timestamp": "137131201",
          "oauth_nonce": "7d8f3e4a",
          "c2" :  ""};
        var normalisedParameterString= oa._normaliseRequestParams(parameters);
        assert.equal(normalisedParameterString, "a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9djdj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7");
      }
    },
    'When preparing the parameters for use in signing': {
      topic: new OAuth(null, null, null, null, null, null, "HMAC-SHA1"),
      'We need to be wary of node\'s auto object creation from foo[bar] style url parameters' : function(oa) {
        var result= oa._prepareParameters( "", "", "", "http://foo.com?foo[bar]=xxx&bar[foo]=yyy", {} );
        assert.equal( result[0][0], "bar[foo]")
        assert.equal( result[0][1], "yyy")
        assert.equal( result[1][0], "foo[bar]")
        assert.equal( result[1][1], "xxx")
      }
    },
    'When signing a url': {
      topic: function() {
        var oa= new OAuth(null, null, "consumerkey", "consumersecret", "1.0", null, "HMAC-SHA1");
        oa._getTimestamp= function(){ return "1272399856"; }
        oa._getNonce= function(){ return "ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp"; }
        return oa;
      },
      'Provide a valid signature when no token present': function(oa) {
        assert.equal( oa.signUrl("http://somehost.com:3323/foo/poop?bar=foo"), "http://somehost.com:3323/foo/poop?bar=foo&oauth_consumer_key=consumerkey&oauth_nonce=ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1272399856&oauth_version=1.0&oauth_signature=7ytO8vPSLut2GzHjU9pn1SV9xjc%3D");
      },
      'Provide a valid signature when a token is present': function(oa) {
        assert.equal( oa.signUrl("http://somehost.com:3323/foo/poop?bar=foo", "token"), "http://somehost.com:3323/foo/poop?bar=foo&oauth_consumer_key=consumerkey&oauth_nonce=ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1272399856&oauth_token=token&oauth_version=1.0&oauth_signature=9LwCuCWw5sURtpMroIolU3YwsdI%3D");
      },
      'Provide a valid signature when a token and a token secret is present': function(oa) {
        assert.equal( oa.signUrl("http://somehost.com:3323/foo/poop?bar=foo", "token", "tokensecret"), "http://somehost.com:3323/foo/poop?bar=foo&oauth_consumer_key=consumerkey&oauth_nonce=ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1272399856&oauth_token=token&oauth_version=1.0&oauth_signature=zeOR0Wsm6EG6XSg0Vw%2FsbpoSib8%3D");
      }
    },
    'When getting a request token': {
        topic: function() {
          var oa= new OAuth(null, null, "consumerkey", "consumersecret", "1.0", null, "HMAC-SHA1");
          oa._getTimestamp= function(){ return "1272399856"; }
          oa._getNonce= function(){ return "ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp"; }
          oa._performSecureRequest= function(){ return this.requestArguments = arguments; }
          return oa;
        },
        'Use the HTTP method in the client options': function(oa) {
          oa.setClientOptions({ requestTokenHttpMethod: "GET" });
          oa.getOAuthRequestToken(function() {});
          assert.equal(oa.requestArguments[2], "GET");
        },
        'Use a POST by default': function(oa) {
          oa.setClientOptions({});
          oa.getOAuthRequestToken(function() {});
          assert.equal(oa.requestArguments[2], "POST");
        }
    },
    'When getting an access token': {
        topic: function() {
          var oa= new OAuth(null, null, "consumerkey", "consumersecret", "1.0", null, "HMAC-SHA1");
          oa._getTimestamp= function(){ return "1272399856"; }
          oa._getNonce= function(){ return "ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp"; }
          oa._performSecureRequest= function(){ return this.requestArguments = arguments; }
          return oa;
        },
        'Use the HTTP method in the client options': function(oa) {
          oa.setClientOptions({ accessTokenHttpMethod: "GET" });
          oa.getOAuthAccessToken(function() {});
          assert.equal(oa.requestArguments[2], "GET");
        },
        'Use a POST by default': function(oa) {
          oa.setClientOptions({});
          oa.getOAuthAccessToken(function() {});
          assert.equal(oa.requestArguments[2], "POST");
        }
    },
    'When get authorization header' : {
        topic: function() {
          var oa= new OAuth(null, null, "consumerkey", "consumersecret", "1.0", null, "HMAC-SHA1");
          oa._getTimestamp= function(){ return "1272399856"; }
          oa._getNonce= function(){ return "ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp"; }
          return oa;
        },
        'Provide a valid signature when a token and a token secret is present': function(oa) {
          assert.equal( oa.authHeader("http://somehost.com:3323/foo/poop?bar=foo", "token", "tokensecret"), 'OAuth oauth_consumer_key="consumerkey",oauth_nonce="ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1272399856",oauth_token="token",oauth_version="1.0",oauth_signature="zeOR0Wsm6EG6XSg0Vw%2FsbpoSib8%3D"');
        },
        'Support variable whitespace separating the arguments': function(oa) {
            oa._oauthParameterSeperator= ", ";
            assert.equal( oa.authHeader("http://somehost.com:3323/foo/poop?bar=foo", "token", "tokensecret"), 'OAuth oauth_consumer_key="consumerkey", oauth_nonce="ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1272399856", oauth_token="token", oauth_version="1.0", oauth_signature="zeOR0Wsm6EG6XSg0Vw%2FsbpoSib8%3D"');
        }
    },
    'When get the OAuth Echo authorization header': {
      topic: function () {
        var realm = "http://foobar.com/";
        var verifyCredentials = "http://api.foobar.com/verify.json";
        var oa = new OAuthEcho(realm, verifyCredentials, "consumerkey", "consumersecret", "1.0A", "HMAC-SHA1");
        oa._getTimestamp= function(){ return "1272399856"; }
        oa._getNonce= function(){ return "ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp"; }
        return oa;
      },
      'Provide a valid signature when a token and token secret is present': function (oa) {
        assert.equal( oa.authHeader("http://somehost.com:3323/foo/poop?bar=foo", "token", "tokensecret"), 'OAuth realm="http://foobar.com/",oauth_consumer_key="consumerkey",oauth_nonce="ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1272399856",oauth_token="token",oauth_version="1.0A",oauth_signature="0rr1LhSxACX2IEWRq3uCb4IwtOs%3D"');
      }
    },
    'When non standard ports are used': {
        topic: function() {
          var oa= new OAuth(null, null, null, null, null, null, "HMAC-SHA1"),
          mockProvider= {};

          oa._createClient= function( parsedUrl, method, headers, post_body ) {
            assert.equal(headers.Host, "somehost.com:8080");
            assert.equal(parsedUrl.hostname, "somehost.com");
            assert.equal(parsedUrl.port, "8080");
            return {
              on: function() {},
              end: function() {}
            };
          }
          return oa;
        },
        'getProtectedResource should correctly define the host headers': function(oa) {
          oa.getProtectedResource("http://somehost.com:8080", "GET", "oauth_token", null, function(){})
        }
    },
    'When building the OAuth Authorization header': {
      topic: new OAuth(null, null, null, null, null, null, "HMAC-SHA1"),
      'All provided oauth arguments should be concatentated correctly' : function(oa) {
       var parameters= [
          ["oauth_timestamp",         "1234567"],
          ["oauth_nonce",             "ABCDEF"],
          ["oauth_version",           "1.0"],
          ["oauth_signature_method",  "HMAC-SHA1"],
          ["oauth_consumer_key",      "asdasdnm2321b3"]];
        assert.equal(oa._buildAuthorizationHeaders(parameters), 'OAuth oauth_timestamp="1234567",oauth_nonce="ABCDEF",oauth_version="1.0",oauth_signature_method="HMAC-SHA1",oauth_consumer_key="asdasdnm2321b3"');
      },
      '*Only* Oauth arguments should be concatentated, others should be disregarded' : function(oa) {
       var parameters= [
          ["foo",         "2343"],
          ["oauth_timestamp",         "1234567"],
          ["oauth_nonce",             "ABCDEF"],
          ["bar",             "dfsdfd"],
          ["oauth_version",           "1.0"],
          ["oauth_signature_method",  "HMAC-SHA1"],
          ["oauth_consumer_key",      "asdasdnm2321b3"],
          ["foobar",      "asdasdnm2321b3"]];
        assert.equal(oa._buildAuthorizationHeaders(parameters), 'OAuth oauth_timestamp="1234567",oauth_nonce="ABCDEF",oauth_version="1.0",oauth_signature_method="HMAC-SHA1",oauth_consumer_key="asdasdnm2321b3"');
      },
      '_buildAuthorizationHeaders should not depends on Array.prototype.toString' : function(oa) {
       var _toString = Array.prototype.toString;
       Array.prototype.toString = function(){ return '[Array] ' + this.length; }; // toString overwrite example used in jsdom.
       var parameters= [
          ["foo",         "2343"],
          ["oauth_timestamp",         "1234567"],
          ["oauth_nonce",             "ABCDEF"],
          ["bar",             "dfsdfd"],
          ["oauth_version",           "1.0"],
          ["oauth_signature_method",  "HMAC-SHA1"],
          ["oauth_consumer_key",      "asdasdnm2321b3"],
          ["foobar",      "asdasdnm2321b3"]];
        assert.equal(oa._buildAuthorizationHeaders(parameters), 'OAuth oauth_timestamp="1234567",oauth_nonce="ABCDEF",oauth_version="1.0",oauth_signature_method="HMAC-SHA1",oauth_consumer_key="asdasdnm2321b3"');
       Array.prototype.toString = _toString;
      }
    },
    'When performing a secure' : {
      topic: new OAuth("http://foo.com/RequestToken",
                       "http://foo.com/AccessToken",
                       "anonymous",  "anonymous",
                       "1.0A", "http://foo.com/callback", "HMAC-SHA1"),
      'POST' : {
        'if no callback is passed' : {
          'it should return a request object': function(oa) {
            var request= oa.post("http://foo.com/blah", "token", "token_secret", "BLAH", "text/plain")
            assert.isObject(request);
            assert.equal(request.method, "POST");
            request.end();
          }
        },
        'if a callback is passed' : {
          "it should call the internal request's end method and return nothing": function(oa) {
            var callbackCalled= false;
            var op= oa._createClient;
            try {
              oa._createClient= function( parsedUrl, method, headers, post_body ) {
                return {
                  write: function(){},
                  on: function() {},
                  end: function() {
                    callbackCalled= true;
                  }
                };
              }
              var request= oa.post("http://foo.com/blah", "token", "token_secret", "BLAH", "text/plain", function(e,d){})
              assert.equal(callbackCalled, true);
              assert.isUndefined(request);
            }
            finally {
              oa._createClient= op;
            }
          }
        }
       },
       'GET' : {
         'if no callback is passed' : {
           'it should return a request object': function(oa) {
             var request= oa.get("http://foo.com/blah", "token", "token_secret")
             assert.isObject(request);
             assert.equal(request.method, "GET");
             request.end();
           }
         },
         'if a callback is passed' : {
           "it should call the internal request's end method and return nothing": function(oa) {
             var callbackCalled= false;
             var op= oa._createClient;
             try {
               oa._createClient= function( parsedUrl, method, headers, post_body ) {
                 return {
                   on: function() {},
                   end: function() {
                     callbackCalled= true;
                   }
                 };
               }
               var request= oa.get("http://foo.com/blah", "token", "token_secret", function(e,d) {})
               assert.equal(callbackCalled, true);
               assert.isUndefined(request);
             }
             finally {
               oa._createClient= op;
             }
           }
         },
       },
       'PUT' : {
         'if no callback is passed' : {
           'it should return a request object': function(oa) {
             var request= oa.put("http://foo.com/blah", "token", "token_secret", "BLAH", "text/plain")
             assert.isObject(request);
             assert.equal(request.method, "PUT");
             request.end();
           }
         },
         'if a callback is passed' : {
           "it should call the internal request's end method and return nothing": function(oa) {
             var callbackCalled= 0;
             var op= oa._createClient;
             try {
               oa._createClient= function( parsedUrl, method, headers, post_body ) {
                 return {
                   on: function() {},
                   end: function() {
                     callbackCalled++;
                   }
                 };
               }
               var request= oa.put("http://foo.com/blah", "token", "token_secret", "BLAH", "text/plain", function(e,d){})
               assert.equal(callbackCalled, 1);
               assert.isUndefined(request);
             }
             finally {
               oa._createClient= op;
             }
           }
         },
        },
       'DELETE' : {
         'if no callback is passed' : {
           'it should return a request object': function(oa) {
             var request= oa.delete("http://foo.com/blah", "token", "token_secret")
             assert.isObject(request);
             assert.equal(request.method, "DELETE");
             request.end();
           }
         },
         'if a callback is passed' : {
           "it should call the internal request's end method and return nothing": function(oa) {
             var callbackCalled= false;
             var op= oa._createClient;
             try {
               oa._createClient= function( parsedUrl, method, headers, post_body ) {
                 return {
                   on: function() {},
                   end: function() {
                     callbackCalled= true;
                   }
                 };
               }
               var request= oa.delete("http://foo.com/blah", "token", "token_secret", function(e,d) {})
               assert.equal(callbackCalled, true);
               assert.isUndefined(request);
             }
             finally {
               oa._createClient= op;
             }
           }
         }
       },
       'Request With a Callback' : {
          'and a 200 response code is received' : {
            'it should callback successfully' : function(oa) {
              var op= oa._createClient;
              var callbackCalled = false;
              try {
                oa._createClient= function( parsedUrl, method, headers, post_body ) {
                  return new DummyRequest( new DummyResponse(200) );
                }
                oa._performSecureRequest("token", "token_secret", 'POST', 'http://originalurl.com', {"scope": "foobar,1,2"}, null, null, function(error) {
                  // callback
                  callbackCalled= true;
                  assert.equal(error, undefined);
                });
                assert.equal(callbackCalled, true)
              }
              finally {
                oa._createClient= op;
              }
            }
          },
          'and a 210 response code is received' : {
            'it should callback successfully' : function(oa) {
              var op= oa._createClient;
              var callbackCalled = false;
              try {
                oa._createClient= function( parsedUrl, method, headers, post_body ) {
                  return new DummyRequest( new DummyResponse(210) );
                }
                oa._performSecureRequest("token", "token_secret", 'POST', 'http://originalurl.com', {"scope": "foobar,1,2"}, null, null, function(error) {
                  // callback
                  callbackCalled= true;
                  assert.equal(error, undefined);
                });
                assert.equal(callbackCalled, true)
              }
              finally {
                oa._createClient= op;
              }
            }
          },
       }
     }
}).export(module);
