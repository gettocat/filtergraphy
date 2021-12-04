const assert = require('assert');

it('should be equal', function (done) {
    this.timeout(5000);

    const APP = require('../../index')
    let app = new APP();
    let k = 2;

    let dialogs = [];

    let storage = [{
        publicKey: '02178d4517d71b8ed15544e377000f832725b6ebd1dfda72e2a01af2467d30395e',
        privateKey: '68d2c63da5a448e8e65a27bf60d4e85b83eec11a73ef006b0e7b7e77efc06f22',
        path: "0'/0'/1",
        index: 1,
        keyType: 'private_dialog'
    },
    {
        publicKey: '03e27cfa304366c849be09cac09c0e03baf3f371291eb4adc2a36a2a9a002ae83c',
        privateKey: '30068c1e860fac3e3aa16083310d3e6b1d061e53da16b08b100621c4f11796ec',
        path: "0'/0'/2",
        index: 2,
        keyType: 'private_dialog'
    },
    {
        publicKey: '02ff3efab1d0916490814cf03bc6e4d4b6125e14a2a41b2f04766a202209ba4bdb',
        privateKey: 'b4606ac312891ad667bc307d0a0e55a5381248836f8cc1bee066034efcfd4ef1',
        path: "0'/0'/3",
        index: 3,
        keyType: 'private_dialog'
    }
    ];

    app.on('NET:sendmempool', () => { });
    app.on('msg', () => { });

    /*decrypt events*/
    app.on('addDialog', (localkey, externalkey, callback) => {
        for (let i in dialogs) {
            if (dialogs[i].localkey == localkey && dialogs[i].externalkey == externalkey)
                return callback();
        }

        dialogs.push({
            localkey,
            externalkey
        });

        callback();
    })

    app.on('removeDialog', (localkey, externalkey, callback) => {
        for (let i in dialogs) {
            if (dialogs[i].localkey == localkey && dialogs[i].externalkey == externalkey) {
                dialogs.splice(i, 1);
                break;
            }
        }

        callback();
    })

    app.on('getAllLocalPublicKeysList', (callback) => {
        let list = [];
        for (let i in storage) {
            list.push(storage[i].publicKey)
        }

        callback(list);
    })

    app.on('getMediaKeys', (callback) => {
        callback([])
    })

    app.on('getKeyInfo', (key, callback) => {
        let keystore, dialog;
        for (let i in storage) {
            if (storage[i].publicKey == key)
                keystore = storage[i];
        }

        for (let i in dialogs) {
            if (dialogs[i].localkey == key)
                dialog = dialogs[i]
        }

        callback(dialog, keystore);
    })

    /*encrypt events*/

    app.on('getKeystoreByMeta', (context, version, callback) => {
        for (let i in storage) {
            if (storage[i].publicKey == context.localkey) {
                callback(storage[i]);
                return;
            }
        }
    });

    /*keys events*/
    app.on('seedAccess', (callback) => {
        callback(new app.seed('skull fan flight acid grunt adjust steak process flight drastic hope silly'));
    })

    app.on('getLastIndex', (callback) => {
        callback(k++);
    })

    app.on('saveNewKey', (type, keystore, callback) => {
        //save key to database
        storage.push(keystore);
        callback(keystore);
    })

    app.addDialog(storage[0].publicKey, storage[1].publicKey);
    app.addDialog(storage[1].publicKey, storage[0].publicKey);


    let data = Buffer.from('hello');
    app.encrypt({ localkey: storage[0].publicKey, externalkey: storage[1].publicKey }, data, APP.Crypto.TEMPKEY)
        .then((encryptedData) => {
            console.log('encrypted:', encryptedData.toString('hex'));
            return encryptedData
        })
        .then((enc) => {
            return app.decrypt(enc);
        })
        .then((res) => {
            console.log(res);
            console.log('decrypted', data.equals(res.content), res.content.toString(), res.meta.switch)
            assert(data.equals(res.content) && res.dialog.externalkey != storage[0].publicKey && res.dialog.externalkey == res.meta.from);
            done();
        })
        .catch(e => {
            console.log(e)
            done(e);
        })

});
