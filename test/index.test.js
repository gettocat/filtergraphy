function importTest(name, path) {
    describe(name, function () {
        require(path);
    });
}

process.on('unhandledRejection', (reason, p) => {
    console.log('Unhandled Rejection at: Promise', p, 'reason:', reason);
    // application specific logging, throwing an error, or other logic here
});

//let common = require("./common");

describe("top", function () {
    beforeEach(function () {
        //console.log("running something before each test");
    });

    //@personal
    importTest("crypto/createKeyPair", './crypto/createkeypair.test.js');
    importTest("cannot-decrypt", './crypto/cannot-decrypt.test.js');

    //tempkey
    importTest("tempkey-crypto/decrypt", './crypto/temp-key.test');

    //hellopublickey
    importTest("hellopublickey", './crypto/hellopublickey.test.js');

    //filter-filter
    importTest("filterfrom-filterto", './crypto/filterfrom-filterto.test.js');
    //filterfrom
    importTest("filterfrom", './crypto/filterfrom-keyto.test.js');
    //key-to
    importTest("filterto", './crypto/keyfrom-filterto.test.js');
    //key-key
    importTest("keyfrom-keyto", './crypto/keyfrom-keyto.test.js');

    //errors
    //dialog not found (if have valid key)

    //@media
    //open media:
    //creation
    importTest("openmedia create", './media/creation.test.js');
    //follow
    importTest("openmedia follow", './media/follow_public.test.js');
    //unfollow
    importTest("openmedia unfollow", './media/unfollow_public.test.js');
    //message from media
    importTest("openmedia broadcast", './media/broadcast_public.test.js');

    //closed media:
    //follow
    importTest("closed media follow", './media/follow_private.test.js');
    //unfollow
    importTest("closed media unfollow", './media/unfollow_private.test.js');
    //message from media
    importTest("closed media broadcast", './media/broadcast_private.test.js');


    after(function () {
        console.log("after all tests");
    });
});