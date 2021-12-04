const assert = require('assert');



it('should create new media, follow and then unfollow', function (done) {
    const APP = require('../../index')
    let app = new APP();

    let k = 0;
    let pk = 0;

    let dialogs = [];
    let mediaNetInfo = {};
    let mediaLocalInfo = {};
    let mediaNetFollowStateInfo = {};
    let dialogsWithMedia = {};

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

    app.on('NET:sendmempool', (data, callback) => { callback() });
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

    app.on('getAllMediaNames', (callback) => {
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

    app.on('getLastPublicIndex', (callback) => {
        callback(pk++)
    })

    app.on('saveNewKey', (type, keystore, callback) => {
        //save key to database
        storage.push(keystore);
        callback(keystore);
    })

    app.addDialog(storage[0].publicKey, storage[1].publicKey);
    app.addDialog(storage[1].publicKey, storage[0].publicKey);


    //media:
    app.on('NET:getMediaInfo', (name, callback) => {
        callback(mediaNetInfo[name])
    })

    app.on('NET:saveMediaInfo', (name, data, callback) => {
        mediaNetInfo[name] = data;
        callback(mediaNetInfo[name]);
    })

    app.on('saveMediaInfo', (data, callback) => {
        mediaLocalInfo[data.name] = data;
        callback(mediaLocalInfo[data.name])
    })


    app.on('NET:setFollowState', (mediaName, followerState, callback) => {
        if (!mediaNetFollowStateInfo[mediaName])
            mediaNetFollowStateInfo[mediaName] = {};


        mediaNetFollowStateInfo[mediaName][followerState.publicKey] = followerState;

        callback();
    })

    app.on('NET:getFollowState', (mediaName, followerKey, callback) => {
        if (!mediaNetFollowStateInfo[mediaName])
            mediaNetFollowStateInfo[mediaName] = {};

        callback(mediaNetFollowStateInfo[mediaName][followerKey]);
    })

    /**
     * another events
     */

    app.on('NET:getMempoolHistory', (callback) => {
        callback([]);
    });

    app.on('addMediaDialog', (localkey, mediaName, callback) => {
        dialogsWithMedia[mediaName] = { localkey, externalKey: mediaName };
        callback({ localkey, externalKey: mediaName });
    })

    app.on('removeMediaDialog', (localkey, mediaName, callback) => {
        delete dialogsWithMedia[mediaName];
        callback();
    })

    app.on('getDialogWithMedia', (mediaName, callback) => {
        callback(dialogsWithMedia[mediaName])
    })

    app.on('getDialogByExternalKey', (externalkey, callback) => {
        callback();
    })

    app.on('getMediaFollowers', (mediaPublicKey, callback) => {
        callback();
    })


    app.on('getAllFollowedMediaKeys', (callback) => {
        callback()
    })

    app.on('getMediaFollowers', (mediaPublicKey, callback) => {
        callback()
    })

    app.on('getMediaInfo', (nameOrKey, callback) => {
        if (mediaLocalInfo[nameOrKey])
            callback(mediaLocalInfo[nameOrKey])
        else {
            for (let i in mediaLocalInfo) {
                if (mediaLocalInfo[i].publicKey == nameOrKey) {
                    callback(mediaLocalInfo[i]);
                    return;
                }
            }
        }
    })

    app.on('saveMessage', (dialog, content, options, callback) => {
        callback({ hash: options.hash });
    })

    app.on('addFollower', (localkey, followerkey, callback) => {
        callback()
    })

    app.on('removeFollower', (localkey, followerkey, callback) => {
        callback()
    })

    app.on('follower', (pubkey) => {
        console.log('new follower', pubkey)
    })

    app.on('notfollower', () => {

    })
    /**
     * another events
     */

    let _tempkey;
    app.createMedia('followtest', 'MEDIA_PUBLIC')
        .then(() => {
            return app.getMedia('followtest')
        })
        .then(media => {

            return app.follow('followtest')

        })
        .then((e) => {
            //todo, can check sign and hash.
            _tempkey = dialogsWithMedia['followtest'].localkey;
            assert(dialogsWithMedia['followtest'] && mediaNetFollowStateInfo['followtest'][dialogsWithMedia['followtest'].localkey]);
            return app.unfollow('followtest')
        })
        .then(e => {
            assert(!dialogsWithMedia['followtest'] && !mediaNetFollowStateInfo['followtest'][_tempkey].follow);
            done()
        })
        .catch(done)

});