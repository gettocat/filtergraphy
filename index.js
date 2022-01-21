const EventEmitter = require('events');
const bitPony = require('bitpony');
const EC = require('elliptic').ec;
const cr = require('crypto');

const SECRET = '5c4d018cdceb47b7051045c29d3130203b999f03d3c4200b7fe957ea9915125';

class Crypto { }
Crypto.FILTERTO = 1;
Crypto.FILTERFROMFILTERTO = 2;
Crypto.KEYTO = 3;
Crypto.KEYFROMKEYTO = 4;
Crypto.MEDIA = 5;
//
Crypto.HELLOPUBLICKEY = 10;
Crypto.TEMPKEY = 11;

class App extends EventEmitter {
    constructor(options) {
        if (!options)
            options = {};
        super();

        this.secret = SECRET + (options.secret || "");
        this.seed = require('./lib/seed')(this);
        this.bloom = require('./lib/filter')(this);
        this.schema = require('./lib/schema')(this);
        this.messageSchema = require('./lib/schema/message')(this);
        let CLS = require('./lib/pow')
        this.pow = new CLS(this);

        this.config = {
            proof:
            {
                period: 3600,
                target: 10,
                capacity: 100
            }
        }


        /**
        this.on('getKeystoreByMeta', ({ localkey, externalkey }, version, callback) => {
            callback(keystore);
        })

        this.on('addDialog', (localkey, externalkey, callback) => {

        })

        this.on('removeDialog', (localkey, externalkey, callback) => {

        })

        this.on('getAllExternalPublicKeysList', (callback)=>{
            callback(list) //list = [externalPublicKey1, externalPublicKey2,...]
        })

        this.on('getAllLocalPublicKeysList', (callback)=>{
            callback(list) //list = [localPublicKey1, localPublicKey2,...]
        })

        this.on('getMediaKeys', (callback)=>{
            callback(list) //list = [myMediaPublicKey1, myMediaPublicKey2,...]
        })

        this.on('getKeyInfo', (key, callback)=>{
            callback(dialog, keystore)
        })

        this.on('seedAccess', (callback)=>{
            callback(new this.seed(mnemonic));
        })
        
        this.on('getLastIndex', (callback)=>{
            callback(lastusedkeyindex);
        })

        this.on('getLastPublicIndex', (callback)=>{
            callback(lastusedpublickey)
        })

        this.on('saveNewKey', (typeofkey, keystore, callback)=>{
            //save key to database
            callback();
        })

        this.on('createProof', (payload, callback)=>{
            callback(proof);
        })
        
        this.on('NET:getMempoolHistory', (callback) => {//for proof calculating
            //app.network.document.get('mempool').history();
            callback(history)
        })

        this.on('NET:getMediaInfo', (mediaName, callback)=>{
            callback(mediaInfo);
        })

        this.on('NET:saveMediaInfo', (mediaName, mediaInfo, callback)=>{
            //save media to network
            callback();
        })

        this.on('saveMediaInfo', (mediaInfo, callback) => {
            //save media to local db
            callback(mediaData)
        })

        this.on('addMediaDialog', (localkey, mediaName, callback) => {
            //create new dialog with media
            callback();
        })

        this.on('removeMediaDialog', (localkey, mediaName, callback) => {
            //remove dialog with media and localkey
            callback();
        })

        this.on('getDialogWithMedia', (mediaName, callback)=>{
            //find dialog {media_name, localkey}
            callback({media_name, localkey});
        })

        this.on('NET:setFollowState', mediaName, followerState, callback){
            //set follower state
            callback();
        })

        this.on('NET:getFollowState', mediaName, followerKey, callback, ()=>{
            //get follower state
            callback(state);
        })

        this.on('getDialogByExternalKey', externalkey, callback, ()=>{
            callback();
        })

        this.on('NET:sendmempool', data, callback, ()=>{
            callback(hash)
        })

        this.on('NET:getMempoolHistory', (callback)=>{
            callback([
                time1,
                time2,...
                ...
            ])
        })

        this.on('getMediaFollowers', mediaPubKey, callback, ()=>{
            callback([followerPubkey1, followerPubkey2,....,followerPubKeyN])
        })

        this.on('addFollower', localkey, followerkey, callback, ()=>{
            callback();
        })

        this.on('removeFollower', localkey, followerkey, callback, ()=>{
            callback();
        })

        this.on('getMediaInfo', mediaPublicKey, callback, ()=>{
            callback(mediaName)
        })

        this.on('getAllFollowedMediaKeys', callback, ()=>{
            callback([mediaPublicName1, mediaPublicName2,...,])
        });

        this.on('saveMessage', dialog, content, options, callback, () => {
            callback(message);
        });
         */


        this.on('createProof', ({ time, payload }, callback) => {
            this.pow.createProof(payload, time)
                .then(proof => { callback(proof) })
        });
    }
    incomingmessagehandle({ hash, message }) {
        return this.decrypt(message.message)
            .then((res) => {
                if (!res) return;

                if (res.meta.version == Crypto.MEDIA) {
                    //message from media
                    //get media dialog
                    //read message
                    //save message
                    //emit msg

                    return new Promise((resolve, reject) => {

                        let finalName = res.meta.from;

                        this.emit('getDialogWithMedia', finalName, (dialog) => {
                            let promise = Promise.resolve();

                            if (dialog && this.config.confidentiality == 'high') {
                                promise = promise.then(() => {
                                    return this.getMedia(finalName)
                                        .catch(e => { return { type: 'nomedia' }; })
                                        .then((media) => {
                                            if (media.type == 'MEDIA_OPEN') {
                                                return this.getFollowState(finalName, dialog.localkey)
                                                    .then((state) => {
                                                        if (!state)
                                                            resolve(null);
                                                        else
                                                            return Promise.resolve();
                                                    })
                                            }

                                            return Promise.resolve();
                                        })
                                });
                            } else if (!dialog && this.config.confidentiality == 'high') {
                                return resolve(null);
                            }

                            if (!dialog) {
                                promise
                                    .then(() => {
                                        return this.createKeyPair()
                                    })
                                    .then(keypair => {
                                        return this.addMediaDialog(keypair.publicKey, finalName, "@" + finalName)
                                    })
                                    .then(dialog => {
                                        resolve(dialog);
                                    })
                            } else
                                resolve(dialog);
                        })

                    })
                        .then(dialog => {

                            if (!dialog)
                                return Promise.resolve();

                            return new Promise(resolve => {
                                this.emit('saveMessage', dialog, res.content.toString('hex'), {
                                    self: false, //self
                                    nonce: message.nonce,
                                    time: message.time,
                                    hash: hash,
                                    message_id: message.hash
                                }, () => {
                                    this.emit("msg", { dialog, meta: res.meta, content: res.content, self: false, hash })
                                    resolve();
                                });
                            })

                        })

                }

                if (!!res.dialog && !!res.content) {

                    let self = res.meta.from == res.dialog.localkey;
                    let msg;
                    try {
                        msg = this.messageSchema.read(res.meta.additionData ? res.meta.additionData.getContent() : res.content);
                    } catch (e) {
                        //just buffer
                        msg = res.meta.additionData ? res.meta.additionData.getContent() : res.content;
                    }

                    if (msg instanceof this.messageSchema.FollowMessage) {
                        let followernewkey = msg.getContent().publicKey;
                        if (res.meta.switch) {
                            //new key to follower only
                            followernewkey = res.meta.switch.getContent().new.getContent();
                        }


                        return this.addMediaFollower(res.dialog.localkey, followernewkey)
                            .then(() => {
                                return new Promise(resolve => {
                                    this.emit('getMediaInfo', res.dialog.localkey, (mediaData) => {
                                        resolve(mediaData);
                                    })
                                })
                            })
                            .then(mediaData => {
                                this.emit('follower', mediaData, followernewkey);
                                this.emit(mediaData.name + ':follower', followernewkey);
                            })
                        //only for private media.
                        //handle event, add follower to local db
                        //send event 'follower'
                    }

                    if (msg instanceof this.messageSchema.UnfollowMessage) {
                        //only for private media.
                        //handle event, remove follower to local db
                        //send event 'notfollower'
                        let followerkey = res.dialog.externalkey;//he can send 0 in followerkey field

                        if (res.meta.switch) {
                            followerkey = res.meta.switch.getContent().old.getContent();//im think its not need
                        }


                        return this.removeMediaFollower(res.dialog.localkey, followerkey)
                            .then(() => {
                                return new Promise(resolve => {
                                    this.emit('getMediaInfo', res.dialog.localkey, (mediaData) => {
                                        resolve(mediaData);
                                    })
                                })
                            })
                            .then((mediaData) => {
                                this.emit('notfollower', mediaData, followerkey);
                                this.emit(mediaData.name + ':notfollower', followerkey);
                            })
                    }

                    //save message
                    return new Promise(resolve => {
                        this.emit('saveMessage', res.dialog, res.content.toString('hex'), {
                            self,
                            nonce: message.nonce,
                            time: message.time,
                            hash,
                            message_id: hash
                        }, () => {
                            this.emit("msg", { dialog: res.dialog, meta: res.meta, content: res.content, self, hash })
                            resolve();
                        });
                    })
                }


            })
    }
    _checkEvents(type) {
        let required = ['addDialog', 'removeDialog', 'NET:sendmempool', 'msg'];
        if (type == 'encrypt') {
            required.push('getKeystoreByMeta');
        }

        if (type == 'decrypt') {
            required.push('getAllLocalPublicKeysList');
            required.push('getMediaKeys');
            required.push('getKeyInfo');
        }

        if (type == 'keys' || type == 'hellopublickey') {
            required.push('getLastIndex');
            required.push('seedAccess');
            required.push('saveNewKey');
            if (type == 'hellopublickey')
                required.push('getLastPublicIndex');
        }

        if (type == 'media') {
            //TODO MEDIA
            required.push('createProof');
            required.push('getMediaInfo');
            required.push('saveMediaInfo');
            required.push('NET:saveMediaInfo');
            required.push('NET:setFollowState');
            required.push('NET:getFollowState');
            required.push('NET:getMediaInfo');
            required.push('NET:getMempoolHistory');
            required.push('addMediaDialog');
            required.push('getDialogWithMedia');
            required.push('removeMediaDialog');
            required.push('getDialogByExternalKey');
            required.push('getAllFollowedMediaKeys');
            required.push('getMediaFollowers')
            required.push('saveMessage');
            required.push('addFollower');
            required.push('removeFollower');
            required.push('getLastPublicIndex');

            //may be not required
            required.push('follower');
            required.push('notfollower');
        }

        let res = [];
        for (let i in required) {
            if (this.listenerCount(required[i]) < 1)
                res.push(required[i]);
        }

        if (res.length == 0)
            return true;

        throw new Error('Must be defined next events: ' + res.join(', '));
    }
    createKeyPair(type) {
        this._checkEvents('keys');

        if (!type)
            type = 'private_dialog';

        return new Promise(resolve => {
            this.emit('getLastIndex', (index) => {
                this.emit("seedAccess", (seed) => {
                    let key = seed.createKey(index + 1);
                    key.index = index + 1;

                    this.emit("saveNewKey", type, {
                        publicKey: key.publicKey.toString('hex'),
                        privateKey: key.privateKey.toString('hex'),
                        path: key.path,
                        index: key.index,
                        keyType: type,
                    }, (keystore) => {
                        resolve(keystore);
                    });
                })
            })
        })
    }
    createPublicKeyPair() {
        this._checkEvents('hellopublickey');

        let type = 'public_keypair';

        return new Promise(resolve => {
            this.emit('getLastPublicIndex', (index) => {
                this.emit("seedAccess", (seed) => {
                    let key = seed.createPublicKeypair(index + 1);
                    key.index = index + 1;

                    this.emit("saveNewKey", type, {
                        publicKey: key.publicKey.toString('hex'),
                        privateKey: key.privateKey.toString('hex'),
                        path: key.path,
                        index: key.index,
                        keyType: type,
                        xpub: key.publicExtendedKey
                    }, (keystore) => {
                        resolve(keystore);
                    });
                })
            })
        })
    }
    createFromDerive(xpub, path) {
        this._checkEvents('hellopublickey');

        let type = 'public_outcome';

        return new Promise(resolve => {
            this.emit("seedAccess", (seed) => {
                let key = seed.createPublicKeypair(xpub.index);
                let child = key.derive("m/44/9999/" + path, true);
                this.emit("saveNewKey", type, child, () => {
                    resolve({
                        publicKey: child.publicKey.toString('hex'),
                        privateKey: child.privateKey.toString('hex'),
                        path: path,
                        index: -999,
                        keyType: type
                    });
                });
            })
        })
    }
    addDialog(localkey, externalkey) {
        return new Promise(resolve => {
            this.emit("addDialog", localkey, externalkey, resolve);
        });
    }
    removeDialog(localkey, externalkey) {
        return new Promise(resolve => {
            this.emit("removeDialog", localkey, externalkey, resolve);
        })
    }
    addMediaDialog(localkey, mediaName) {
        return new Promise(resolve => {
            this.emit("addMediaDialog", localkey, mediaName, resolve);
        });
    }
    removeMediaDialog(localkey, mediaName) {
        return new Promise(resolve => {
            this.emit("removeMediaDialog", localkey, mediaName, resolve);
        });
    }
    addMediaFollower(localKey, followerKey) {
        return new Promise(resolve => {
            this.emit("addFollower", localKey, followerKey, resolve);
        });
    }
    removeMediaFollower(localKey, followerKey) {
        return new Promise(resolve => {
            this.emit("removeFollower", localKey, followerKey, resolve);
        });
    }
    /**
     * media section
     */
    createMedia(name, type) {
        this._checkEvents('media');
        //type can be:
        //MEDIA_PUBLIC - list of followers with publickeys of followers open in network
        //MEDIA_PRIVATE - list of followers in localstore of media node
        if (type != 'MEDIA_PUBLIC' && type != 'MEDIA_PRIVATE')
            throw new Error('Invalid media type');

        if (!name)
            throw new Error('Invalid name');

        let _key;
        //check name in media db for double
        return new Promise((resolve, reject) => {
            this.emit('NET:getMediaInfo', name, (mediaInfo) => {
                if (mediaInfo) {
                    return reject('Name ' + name + ' already exist');
                }

                resolve();
            })
        })
            .then(() => {
                return this.createPublicKeyPair()
            })
            .then(key => {
                _key = key;
                //save media to localdb
                return new Promise((resolve, reject) => {
                    this.emit('saveMediaInfo', { type, name, xpub: key.xpub, publicKey: key.publicKey }, (mediaData) => {
                        if (!mediaData)
                            reject('Error while saving mediaInfo');
                        else
                            resolve(mediaData);
                    });
                })
            })
            .then(mediaData => {

                let payload = this.pow.payloadMediaCreate(name, mediaData.xpub, mediaData.publicKey);

                return new Promise(resolve => {
                    const time = Math.floor(Date.now() / 1000);
                    this.emit('createProof', { time, payload }, ({ hash, time, nonce, diff }) => {

                        this.emit("seedAccess", (seed) => {
                            let key = seed.createPublicKeypair(_key.index);
                            let sign = key.sign(Buffer.from(hash, 'hex')).toString('hex');

                            this.emit('NET:saveMediaInfo', name, {
                                hash,
                                type,
                                nonce,
                                time,
                                sign,
                                xpub: mediaData.xpub,
                                publicKey: mediaData.publicKey,
                            }, () => {
                                resolve();
                            })

                        });

                    });
                })
            });

    }
    getMedia(media_name) {
        return new Promise((resolve, reject) => {

            this.emit('NET:getMediaInfo', media_name, (mediaInfo) => {
                if (!mediaInfo) {
                    return reject('Media ' + media_name + ' do not exist');
                }

                resolve(mediaInfo);
            })

        })
    }
    getFollowState(mediaName, followerKey) {
        return new Promise(resolve => {
            this.emit('NET:getFollowState', mediaName, followerKey, (state) => {
                resolve(state)
            })
        })
    }
    //edit media
    //follow
    follow(mediaName) {
        let media_publicKey;
        let media_xpub;
        let my_media_key;
        let sign = ''; //sign 'follow(1)'
        let buffer;
        let promise = Promise.resolve();
        let _k;

        return this.getMedia(mediaName)
            .then(media_data => {

                media_xpub = media_data.xpub;
                media_publicKey = media_data.publicKey;

                if (!mediaName || !media_data || !media_xpub || !media_publicKey)
                    throw new Error('Invalid media id');

                return Promise.resolve(media_data);
            })
            .then((media_data) => {


                if (media_data.type == 'MEDIA_PRIVATE') {

                    promise = promise
                        .then(() => {
                            return new Promise((resolve, reject) => {
                                this.emit('getDialogWithMedia', mediaName, (dialog) => {

                                    if (dialog)
                                        return reject('You are already followed to @' + mediaName);

                                    resolve()
                                })


                            })
                        })
                        .then(() => {
                            return this.createKeyPair()
                        })
                        .then(media_sub_key => {
                            return new Promise(resolve => {
                                this.emit("seedAccess", (seed) => {
                                    my_media_key = media_sub_key;
                                    let key = seed.createKey(media_sub_key.index);
                                    key.index = media_sub_key.index;
                                    resolve(key);
                                });
                            })
                        })
                        .then(key => {
                            _k = key;
                            sign = key.sign((this.sha256(Buffer.from('follow(1)')))).toString('hex');
                            return Promise.resolve(sign);
                        })
                        .then(sign => {
                            buffer = this.messageSchema.create(this.messageSchema.FollowMessage, my_media_key.publicKey, sign).pack();
                            return this.encrypt({ localkey: my_media_key.publicKey, externalkey: media_publicKey, media: mediaName }, buffer, Crypto.TEMPKEY, "@" + mediaName);
                        })
                        .then((payload) => {
                            //maybe here need change sign to dialog.localkey, but im not sure
                            const sign = _k.sign(Buffer.from(this.sha256(payload), 'hex')).toString('hex');
                            return this._broadcastMessage(payload, sign)
                            /*.then((res) => { in encrypt now.
                                return this.addMediaDialog(my_media_key.publicKey, mediaName, "@" + mediaName)
                                    .then(() => {
                                        return Promise.resolve(res);
                                    })
                            })*/
                        })

                }

                if (media_data.type == 'MEDIA_PUBLIC') {
                    //TODO: check follow state first.
                    promise = promise
                        .then(() => {
                            return new Promise((resolve, reject) => {
                                this.emit('getDialogWithMedia', mediaName, (dialog) => {

                                    if (dialog)
                                        return reject('You are already followed to @' + mediaName);

                                    resolve(dialog)
                                })


                            })
                        })
                        .then(() => {
                            return this.createKeyPair()
                        })
                        .then((media_sub_key) => {
                            return new Promise(resolve => {
                                this.emit("seedAccess", (seed) => {
                                    my_media_key = media_sub_key;
                                    let key = seed.createKey(media_sub_key.index);
                                    key.index = media_sub_key.index;
                                    resolve(key);
                                });
                            })
                        })
                        .then(_key => {
                            //by the way we can check followState using only public key of sub and sign from state, because another data can be created
                            let payload = this.pow.payloadMediaFollow(my_media_key.publicKey, this.sha256(Buffer.from('follow(1)')).toString('hex'));

                            return new Promise(resolve => {
                                const time = Math.floor(Date.now() / 1000);
                                this.emit('createProof', { time, payload }, ({ hash, time, nonce, diff }) => {

                                    let sign = _key.sign(Buffer.from(hash, 'hex')).toString('hex');

                                    this.emit('NET:setFollowState', mediaName, {
                                        hash,
                                        nonce,
                                        time,
                                        sign,
                                        publicKey: my_media_key.publicKey,
                                        follow: 1,
                                    }, () => {
                                        resolve(hash);
                                    })

                                });
                            })
                        })
                        .then((hash) => {
                            return this.addMediaDialog(my_media_key.publicKey, mediaName, "@" + mediaName)
                                .then(() => {
                                    return Promise.resolve(hash);
                                })
                        })

                }

                return promise;
            })
    }
    //unfollow
    unfollow(mediaName) {
        let media_publicKey;
        let media_xpub;
        let my_media_key;
        let sign = ''; //sign 'follow(1)'
        let buffer;
        let _dialog;
        let promise = Promise.resolve();

        let _k;

        return this.getMedia(mediaName)
            .then(media_data => {

                media_xpub = media_data.xpub;
                media_publicKey = media_data.publicKey;

                if (!mediaName || !media_data || !media_xpub || !media_publicKey)
                    throw new Error('Invalid media id');

                return Promise.resolve(media_data);
            })
            .then(media_data => {

                if (media_data.type == 'MEDIA_PRIVATE') {
                    promise = promise
                        .then(() => {
                            return new Promise((resolve, reject) => {
                                this.emit('getDialogWithMedia', mediaName, (dialog) => {

                                    if (!dialog)
                                        return reject('You are not followed to @' + mediaName);
                                    dialog.externalkey = media_data.publicKey;
                                    resolve(dialog)
                                })


                            })
                        })
                        .then((dialog) => {
                            return new Promise((resolve, reject) => {
                                this.emit('getKeyInfo', dialog.localkey, (dialog, keystore) => {
                                    _dialog = dialog;
                                    if (!keystore)
                                        return reject('You are not followed to @' + mediaName + ", can not find keystore");

                                    resolve(keystore);
                                })
                            })
                        })
                        .then(keystore => {
                            my_media_key = keystore;

                            return new Promise(resolve => {
                                this.emit("seedAccess", (seed) => {
                                    let key = seed.createKey(my_media_key.index);
                                    key.index = my_media_key.index;
                                    resolve(key);
                                });
                            })

                        })
                        .then(key => {
                            _k = key;
                            sign = key.sign((this.sha256(Buffer.from('follow(0)')))).toString('hex');
                            return Promise.resolve(sign);
                        })
                        .then(sign => {
                            buffer = this.messageSchema.create(this.messageSchema.UnfollowMessage, my_media_key.publicKey, sign).pack();
                            return this.encrypt(_dialog, buffer, Crypto.FILTERFROMFILTERTO);
                        })
                        .then((payload) => {
                            //maybe here need change sign to dialog.localkey, but im not sure
                            const sign = _k.sign(Buffer.from(this.sha256(payload), 'hex')).toString('hex');
                            return this._broadcastMessage(payload, sign);
                        })
                }

                if (media_data.type == 'MEDIA_PUBLIC') {

                    promise = promise
                        .then(() => {
                            return new Promise((resolve, reject) => {
                                this.emit('getDialogWithMedia', mediaName, (dialog) => {
                                    if (!dialog) {
                                        return reject('You are not followed to @' + mediaName);
                                    }

                                    this.emit('getKeyInfo', dialog.localkey, (_dialog, keystore) => {
                                        resolve(keystore);
                                    })
                                })
                            })
                        })
                        .then(keystore => {
                            my_media_key = keystore;

                            if (!my_media_key)
                                return Promise.reject('You are not followed to @' + mediaName + ", can not find keystore");

                            return new Promise(resolve => {
                                this.emit("seedAccess", (seed) => {
                                    let key = seed.createKey(my_media_key.index);
                                    key.index = my_media_key.index;
                                    resolve(key);
                                });
                            })
                        })
                        .then(_key => {
                            let payload = this.pow.payloadMediaFollow(my_media_key.publicKey, this.sha256(Buffer.from('follow(0)')).toString('hex'));

                            return new Promise(resolve => {
                                const time = Math.floor(Date.now() / 1000);
                                this.emit('createProof', { time, payload }, ({ hash, time, nonce, diff }) => {

                                    let sign = _key.sign(Buffer.from(hash, 'hex')).toString('hex');

                                    this.emit('NET:setFollowState', mediaName, {
                                        hash,
                                        nonce,
                                        time,
                                        sign,
                                        publicKey: my_media_key.publicKey,
                                        follow: 0,
                                    }, () => {
                                        resolve(hash);
                                    })

                                });
                            })
                        })
                        .then((hash) => {
                            return this.removeMediaDialog(my_media_key.publicKey, mediaName)
                                .then(() => {
                                    return Promise.resolve(hash);
                                })
                        })

                }

                return promise;

            })

    }
    //broadcastMediaMessage 
    mediaBroadcast(mediaName, buffer) {
        let media_publicKey;
        let media_xpub;
        let media_key;
        let sign = ''; //sign 'follow(1)'
        let _dialog;
        let promise = Promise.resolve();
        let _k;

        return this.getMedia(mediaName)
            .then(media_data => {

                if (!mediaName || !media_data || !media_data.xpub || !media_data.publicKey)
                    throw new Error('Invalid media id');

                media_xpub = media_data.xpub;
                media_publicKey = media_data.publicKey;

                return Promise.resolve(media_data);
            })
            .then(media_data => {

                if (media_data.type == 'MEDIA_PRIVATE') {
                    //enumerate all followers from db and send f2f message to each
                    promise = promise
                        .then(() => {
                            return new Promise(resolve => {

                                this.emit("getMediaFollowers", media_publicKey, (followers_pubkeys) => {
                                    resolve(followers_pubkeys);
                                })

                            })
                        })
                        .then(followers => {
                            let promises = [];
                            for (let followerKey of followers) {
                                //todo, add some entropy
                                promises.push(this.encrypt({ localkey: media_publicKey, externalkey: followerKey }, buffer, Crypto.FILTERFROMFILTERTO)
                                    .then(buff => {
                                        return this._broadcastMessage(buff);
                                    }))
                            }

                            return Promise.all(promises);
                        })
                }

                if (media_data.type == 'MEDIA_PUBLIC') {
                    //get key
                    //send message to mempool
                    //encryptMediaMessage
                    let _key;
                    promise = promise
                        .then(() => {
                            return new Promise((resolve, reject) => {
                                this.emit('getDialogWithMedia', mediaName, (dialog) => {
                                    if (!dialog) {
                                        return reject('You are not followed to @' + mediaName);
                                    }

                                    this.emit('getKeyInfo', dialog.localkey, (_dialog, keystore) => {
                                        resolve(keystore);
                                    })
                                })
                            })
                        })
                        .then(keystore => {
                            media_key = keystore;

                            return new Promise(resolve => {
                                this.emit("seedAccess", (seed) => {
                                    let key = seed.createKey(media_key.index);
                                    key.index = media_key.index;
                                    resolve(key);
                                });
                            })

                        })
                        .then(key => {
                            _key = key;
                            return this.encryptMediaMessage(mediaName, media_data.hash, buffer);
                        })
                        .then(encryptedMessage => {
                            let payload_hash = this.sha256(encryptedMessage);
                            let sign = _key.sign(Buffer.from(payload_hash, 'hex')).toString('hex');

                            return this._broadcastMessage(encryptedMessage, sign);
                        })

                }

                return promise;
            })

    }
    /**
     * 
     * end of media section
     */

    _broadcastMessage(payload, sign) {
        //sign is for public-media messages only.
        //todo;
        //create proof, send to mempool (emit NET:sendmempool)
        return new Promise((resolve, reject) => {
            const t = Math.floor(Date.now() / 1000);
            this.emit('createProof', { time: t, payload }, ({ hash, time, nonce, diff }) => {
                this.emit('NET:sendmempool', {
                    hash, time, nonce, payload, sign
                }, (hash) => {
                    resolve(hash)
                })
            });
        })

    }
    encryptMediaMessage(media_name, media_secret, payload) {
        //simple encryption, not p2p, it is only for MEDIA_PUBLIC type. For MEDIA_PRIVATE we will use p2p encryption 
        let encryptedPayload = this.encryptECDH(payload, media_secret);
        //create filter
        let meta = this.createMeta(Crypto.MEDIA, { localkey: Buffer.from(media_name).toString('hex') });
        //check version and make result message base on version number.
        let buffer = this.writeEncrypted(meta, encryptedPayload);

        //return buffer
        return Promise.resolve(buffer);
    }
    decryptMediaMessage(meta, payload) {
        let _mediaName;
        return new Promise((resolve, reject) => {
            this.emit('getAllFollowedMediaKeys', (keys) => {

                let res = false;
                let filter = this.bloom.load(meta.filter_from.getContent());
                for (let mediaName of keys) {
                    if (filter.contain(Buffer.from(mediaName).toString('hex'))) {
                        res = mediaName;
                        break;
                    }
                }

                if (!res) {
                    return reject('Have not medias in db');
                }

                resolve(res);

            });
        })
            .then(mediaName => {
                _mediaName = mediaName;
                return this.getMedia(mediaName)
            })
            .then(media_data => {

                if (!media_data || !media_data.xpub || !media_data.publicKey || !media_data.hash)
                    throw new Error('Invalid media id');

                return Promise.resolve(media_data);
            })
            .then(media_data => {
                let content = this.decryptECDH(payload.getContent(), media_data.hash);
                return Promise.resolve({
                    meta: {
                        from: _mediaName,
                        version: meta.version,
                    },
                    content
                })
            })
    }
    encrypt(context, data, version, dialogName) {//TODO: dialogName
        this._checkEvents('encrypt');

        if (version != Crypto.HELLOPUBLICKEY) {
            if (!context.localkey)
                return Promise.reject('For sending we need localkey');

            if (!context.externalkey) {
                return Promise.reject('For sending we need externalkey');
            }
        }

        if (!data)
            return Promise.reject('For sending we need content of message');

        if (version == Crypto.HELLOPUBLICKEY) {
            if (!context.externalkeyWithDerive)
                return Promise.reject('For encrypting HELLOPUBLICKEY message you must use externalkeyWithDerive');
        }

        let promise = Promise.resolve(data);
        let tempkey;
        let securekey;
        if (version == Crypto.TEMPKEY) {
            promise = this.createKeyPair()
                .then((key) => {
                    securekey = key.publicKey;
                    let buff = Buffer.from('');
                    let oldkey_schema = this.schema.create(this.schema.PublicKey, context.localkey);
                    let newkey_schema = this.schema.create(this.schema.PublicKey, securekey);
                    buff = this.schema.concat(buff, this.schema.SwitchKey, oldkey_schema, newkey_schema);

                    if (data)
                        buff = this.schema.concat(buff, this.schema.SwitchKeyAdditionalData, data);
                    return Promise.resolve(buff);
                })
        }

        if (version == Crypto.HELLOPUBLICKEY) {
            //any person can create publicKey B from A and send public with temp public key T (filterA-keyT) 'hello' message 
            //A catch this message, decrypt 'hello' message, get HelloPublicKey(B). 
            //now you have private channel A(B)<-->B, now you can use private channel filter-filter for messaging

            let xpub = new this.seed(context.externalkeyWithDerive); //xpub
            let A = xpub.getMaster();
            let hpath = this.seed.getRandomPath(12);
            let B = xpub.derive(hpath, true);

            promise = this.createKeyPair()
                .then((tk) => {
                    tempkey = tk;
                    return this.createKeyPair();
                })
                .then((secureKey) => {
                    let buff = Buffer.from('');
                    securekey = secureKey;

                    let oldkey_schema = this.schema.create(this.schema.PublicKey, tempkey.publicKey);
                    let newkey_schema = this.schema.create(this.schema.PublicKey, secureKey.publicKey);
                    let path_schema = this.schema.create(this.schema.HelloPublicKeyPath, hpath);

                    buff = this.schema.concat(buff, this.schema.SwitchHelloPublicKey, oldkey_schema, newkey_schema, path_schema);

                    context = {
                        localkey: tempkey.publicKey,
                        externalkey: A.publicKey.toString('hex'),
                        external: {
                            path: hpath,
                            key: B.publicKey.toString('hex'),
                            parent: context.externalkeyWithDerive,
                        }
                    }

                    if (data)
                        buff = this.schema.concat(buff, this.schema.SwitchKeyAdditionalData, data);

                    return Promise.resolve(buff);
                });
        }

        return promise
            .then((buff) => {
                return new Promise((resolve, reject) => {
                    this.emit('getKeystoreByMeta', context, version, (keystore) => {
                        resolve({ keystore, buff })
                    })
                })
            })
            .then(({ keystore, buff }) => {
                return this.encryptPayload(context.externalkey, keystore, buff);
            })
            .then(encryptedPayload => {
                let meta = this.createMeta(version, context);
                //check version and make result message base on version number.
                let buffer = this.writeEncrypted(meta, encryptedPayload);

                //return buffer
                return Promise.resolve(buffer);
            })
            .then((buffer) => {
                if (version != Crypto.TEMPKEY && version != Crypto.HELLOPUBLICKEY)
                    return Promise.resolve(buffer);

                if (version == Crypto.HELLOPUBLICKEY)
                    return Promise.all([
                        this.removeDialog(tempkey.publicKey, context.externalkey),
                        this.addDialog(securekey.publicKey, context.externalkey)//, dialog_name)
                    ])
                        .then(() => {
                            return Promise.resolve(buffer);
                        })

                //now we must remove old dialog keys.
                if (version == Crypto.TEMPKEY)
                    return Promise.all([
                        context.media ? this.removeMediaDialog(context.localkey, context.media) : Promise.resolve(),
                        this.removeDialog(context.localkey, context.externalkey),
                        this.addDialog(securekey, context.externalkey),
                        context.media ? this.addMediaDialog(securekey, context.media, "@" + context.media) : Promise.resolve()
                    ])
                        .then(() => {
                            return Promise.resolve(buffer);
                        })
            })
    }
    decrypt(buffer) {
        this._checkEvents('decrypt');

        let { meta, payload } = this.readEncrypted(buffer);
        if (meta.version == Crypto.MEDIA) {
            return this.decryptMediaMessage(meta, payload);
        }

        if ([Crypto.FILTERTO, Crypto.FILTERFROMFILTERTO, Crypto.KEYTO, Crypto.KEYFROMKEYTO, Crypto.TEMPKEY, Crypto.HELLOPUBLICKEY].indexOf(meta.version) == -1)
            return Promise.reject('invalid message type = ' + meta.version); //another type

        //todo
        //meta:
        //get pubkey list by meta, filter list => slice(list) with filtered keys
        //get dialogs & keystore list by keys
        //check every keystore for decryption.
        //get one.
        //shift encryptedData mod 32, if data length <32
        let localkeys = [];
        let mediakeys = []
        let localMatch = [];

        return new Promise((resolve, reject) => {
            this.emit('getAllLocalPublicKeysList', (list) => {
                if (!list || !(typeof list != 'array'))
                    reject('invalid result for getAllLocalPublicKeysList');

                resolve(list)
            })
        })
            .then((list) => {
                localkeys = list;
                return new Promise((resolve, reject) => {
                    this.emit('getMediaKeys', (list) => {
                        if (!list || !(typeof list != 'array'))
                            reject('invalid result for getMediaKeys');

                        resolve(list)
                    })
                })
            })
            .then((list) => {
                mediakeys = list;
                if (meta.version == Crypto.FILTERTO || meta.version == Crypto.FILTERFROMFILTERTO) {
                    //meta.filter_to instanceof Schema.Filter
                    let filter = this.bloom.load(meta.filter_to.getContent());
                    for (let key of localkeys) {
                        if (filter.contain(key))
                            localMatch.push(key);
                    }

                }

                if (meta.version == Crypto.KEYTO || meta.version == Crypto.KEYFROMKEYTO) {
                    //meta.publickey_to instanceof Schema.PublicKey
                    let exkey = meta.publickey_to.getContent();
                    for (let key of localkeys) {
                        if (key == exkey)
                            localMatch.push(key);
                    }

                }

                if (meta.version == Crypto.TEMPKEY || meta.version == Crypto.HELLOPUBLICKEY) {

                    let filter = this.bloom.load(meta.filter_to.getContent());

                    for (let key of localkeys) {
                        if (filter.contain(key))
                            localMatch.push(key);
                    }

                    for (let key of mediakeys) {
                        if (filter.contain(key))
                            localMatch.push(key);
                    }

                }

                return Promise.resolve(localMatch);
            })
            .then((res) => {
                if (res.length > 0) //it is really need?
                    return Promise.resolve(res);

                //it can be outgoing message
                if (meta.filter_from) {
                    let filter = this.bloom.load(meta.filter_from.getContent());
                    for (let key of localkeys) {
                        if (filter.contain(key))
                            localMatch.push(key);
                    }
                } else if (meta.publickey_from) {
                    let exkey = meta.publickey_from.getContent();
                    for (let key of localkeys) {
                        if (exkey == key)
                            localMatch.push(key);
                    }
                }

                return Promise.resolve(localMatch);
            })
            .then(keys => {
                //for each selected key get dialogs and keypair
                //check every dialog for decyption
                let promises = [];
                for (let key of keys) {
                    promises.push(new Promise((resolve, reject) => {
                        this.emit('getKeyInfo', key, (dialog, keystore) => {
                            resolve({ dialog, keystore })
                        })
                    })
                        .then(({ dialog, keystore }) => {

                            //it can be message to media here. ?

                            if (meta.version != Crypto.HELLOPUBLICKEY && meta.version != Crypto.TEMPKEY)
                                if (!dialog || !keystore)
                                    return Promise.reject('nulldialog/keystore');
                                else
                                    if (!keystore)
                                        return Promise.reject('nulldialog/keystore');

                            if ((meta.version == Crypto.HELLOPUBLICKEY || meta.version == Crypto.TEMPKEY) && !dialog) {
                                dialog = {
                                    externalkey: meta.publickey_from.getContent(),
                                    localkey: keystore.publicKey
                                };
                            }

                            //todo, check by checksum
                            let local = this.createMetaChecksum({ localkey: dialog.externalkey, externalkey: dialog.localkey }, meta.time);
                            if (local.checksum == meta.checksum) {
                                //its our candidate
                                let content = this.decryptPayload(dialog.externalkey, keystore, payload.getContent());
                                return Promise.resolve({ key, dialog, keystore, content });
                            } else
                                return Promise.reject('invalidchecksum');

                        })
                        .catch(e => {
                            return Promise.resolve(false);
                        }))
                }

                return Promise.all(promises);
            })
            .then(keys => {
                let length = 0;
                let res = [];
                for (let i in keys) {
                    let key = keys[i];

                    if (!key)
                        continue;

                    keys[i].meta = {
                        from: key.dialog.externalkey,
                        to: key.keystore.publicKey,
                        version: meta.version,
                    };

                    if (meta.version == Crypto.TEMPKEY) {
                        try {
                            let read = this.schema.read(key.content, 0);
                            keys[i].meta.switch = read.result;

                            if (key.content.length > read.offset)
                                try {
                                    keys[i].raw = key.content;
                                    keys[i].content = this.schema.read(key.content, read.offset).result.getContent();
                                } catch (e) {
                                    console.log('tempkey additionData decrypt error', e)
                                }

                        } catch (e) {
                            console.log('tempkey decrypt error', e)
                        }
                    }

                    if (meta.version == Crypto.HELLOPUBLICKEY) {
                        keys[i].meta.switchHelloPublicKey = this.schema.read(key.content, 0).result;

                        let switchHelloPublicKey = this.schema.read(key.content, 0);
                        let additionData;

                        if (key.content.length > switchHelloPublicKey.offset)
                            try {
                                additionData = this.schema.read(key.content, switchHelloPublicKey.offset);
                                keys[i].content = additionData.result.getContent();
                            } catch (e) {

                            }
                    }

                    length++;
                    res.push(keys[i]);
                }


                if (!length)
                    return Promise.reject('can not decrypt message');

                if (length == 1) {
                    return Promise.resolve(res[0]);
                }

                if (length > 1) {
                    //?????
                    return Promise.resolve(res[0]);
                }
            })
            .then(context => {

                if (context.meta.version == Crypto.TEMPKEY) {
                    return Promise.all([
                        //todo: change localkey too
                        this.removeDialog(context.meta.to, context.meta.from),
                        this.addDialog(context.meta.to, context.meta.switch.getContent().new.getContent()) //,dialog_name)
                    ])
                        .then(() => {
                            //context.dialog.localkey = context.meta.to;
                            context.dialog.externalkey = context.meta.switch.getContent().new.getContent();
                            context.meta.from = context.meta.switch.getContent().new.getContent();

                            return Promise.resolve(context);
                        })
                }

                if (context.meta.version == Crypto.HELLOPUBLICKEY) {
                    let keys = context.meta.switchHelloPublicKey.getContent();
                    let newkeystore;

                    return this.removeDialog(context.meta.to, context.meta.from)
                        .then(() => {
                            return this.createFromDerive(context.keystore, keys.path.getContent())
                        })
                        .then((_newkeystore) => {
                            newkeystore = _newkeystore;
                            return this.addDialog(newkeystore.publicKey, keys.new.getContent()); //,dialog_name)
                        })
                        .then(() => {
                            return Promise.resolve(context);
                        })
                }

                return Promise.resolve(context);
            })
    }
    createMetaChecksum(meta, time) {
        if (!time)
            time = parseInt(Date.now() / 1000);

        let timeuint32 = new bitPony.writer(Buffer.from('')).uint32(time, false).result;
        let checksum = this.sha256(Buffer.concat([
            Buffer.from(meta.localkey || "", 'hex'),
            this.sha256(timeuint32),
            Buffer.from(meta.externalkey || "", 'hex')
        ])).slice(0, 4).toString('hex');

        return { time, checksum };
    }
    createMeta(version, context) {
        const NOISE = 12;
        const { time, checksum } = this.createMetaChecksum(context);


        let filter_from, filter_to, publickey_from, publickey_to;
        if (version == Crypto.FILTERTO || version == Crypto.FILTERFROMFILTERTO) {
            let s = this.bloom.noise(NOISE);
            s.push(context.externalkey);
            filter_to = this.bloom.create(s);

            if (version == Crypto.FILTERFROMFILTERTO) {
                s = this.bloom.noise(NOISE);
                s.push(context.localkey);
                filter_from = this.bloom.create(s);
            }
        }

        if (version == Crypto.KEYTO || version == Crypto.KEYFROMKEYTO) {
            publickey_to = context.externalkey;
            if (version == Crypto.KEYFROMKEYTO) {
                publickey_from = context.localkey;
            }
        }

        if (version == Crypto.TEMPKEY || version == Crypto.HELLOPUBLICKEY) {
            publickey_from = context.localkey;
            let s = this.bloom.noise(NOISE);
            s.push(context.externalkey);
            filter_to = this.bloom.create(s);
        }

        if (version == Crypto.MEDIA) {
            let s = this.bloom.noise(NOISE);
            s.push(context.localkey ? context.localkey : context.externalkey);
            filter_from = this.bloom.create(s);

            filter_to = '';
        }

        return { version, checksum, time, filter_from, filter_to, publickey_from, publickey_to };
    }
    readEncrypted(payload) {
        //todo - add to schema uint32
        //also add checksum for quick check of payload without decryption
        let stream = new bitPony.reader(payload);
        let res = stream.uint32(0);
        let version = res.result;
        res = stream.uint32(res.offset);
        let time = res.result;
        res = stream.uint32(res.offset);
        let checksum = parseInt(res.result).toString(16);

        //version 1 - version|checksum|filter_to|encrypteddata
        //version 2 - version|checksum|filter_from|filter_to|encrypteddata
        //version 3 - version|checksum|pubkey_to|encrypteddata //unsafe
        //version 4 - version|checksum|pubkey_from|pubkey_to|encrypteddata // unsafe!
        //version 5 - media_name_hex_filter|encrypteddata
        //tempkey
        //hellopublickey

        let offset = res.offset,
            params = [],
            meta = {},
            pl;
        while (offset < payload.length) {
            res = this.schema.read(payload, offset);
            offset = res.offset;
            params.push(res.result);
        }

        if (version == Crypto.FILTERTO) {
            //params[0];//filter_to
            //params[1];//encrypteddata
            pl = params[1];
            meta = {
                filter_to: params[0]
            };
        }

        if (version == Crypto.FILTERFROMFILTERTO) {
            //params[0];//filter_from
            //params[1];//filter_to
            //params[2];//encrypteddata
            pl = params[2];
            meta = {
                filter_from: params[0],
                filter_to: params[1]
            };
        }

        if (version == Crypto.KEYTO) {
            //params[0];//pubkey_to
            //params[1];//encrypteddata
            pl = params[1];
            meta = {
                publickey_to: params[0],
            };
        }

        if (version == Crypto.KEYFROMKEYTO) {
            //params[0];//pubkey_from
            //params[1];//pubkey_to
            //params[2];//encrypteddata
            pl = params[2];
            meta = {
                publickey_to: params[1],
                publickey_from: params[0],
            };
        }

        if (version == Crypto.TEMPKEY) {
            //params[0];//pubkey_from
            //params[1];//filter_to
            //params[2];//switchkey
            pl = params[2];
            meta = {
                filter_to: params[1],
                publickey_from: params[0],
                switch: params[2]
            };
        }

        if (version == Crypto.HELLOPUBLICKEY) {
            //params[0];//pubkey_from
            //params[1];//filter_to
            //params[2];//switchHelloPublicKey
            pl = params[2];
            meta = {
                filter_to: params[1],
                publickey_from: params[0],
                switchHelloPublicKey: params[2]
            };
        }

        if (version == Crypto.MEDIA) {
            //params[0];//filter_from
            //params[1];//encrypteddata
            pl = params[1];
            meta = {
                filter_from: params[0]
            };
        }

        meta.version = version;
        meta.time = time;
        meta.checksum = checksum;

        return {
            payload: pl,
            meta,
        }
    }
    writeEncrypted(meta, payload) {

        let wr = new bitPony.writer(Buffer.from(""));
        wr.uint32(meta.version, true);
        wr.uint32(meta.time, true);
        wr.uint32(parseInt(meta.checksum, 16), true);
        let temp = Buffer.from(wr.getBuffer());

        if (meta.version == Crypto.FILTERTO) {
            //params[0];//filter_to
            //params[1];//encrypteddata
            temp = this.schema.concat(temp, this.schema.Filter, meta.filter_to);
            temp = this.schema.concat(temp, this.schema.EncryptedData, payload);
        }

        if (meta.version == Crypto.FILTERFROMFILTERTO) {
            //params[0];//filter_from
            //params[1];//filter_to
            //params[2];//encrypteddata

            temp = this.schema.concat(temp, this.schema.Filter, meta.filter_from);
            temp = this.schema.concat(temp, this.schema.Filter, meta.filter_to);
            temp = this.schema.concat(temp, this.schema.EncryptedData, payload);
        }

        if (meta.version == Crypto.KEYTO) {
            //params[0];//pubkey_to
            //params[1];//encrypteddata
            temp = this.schema.concat(temp, this.schema.PublicKey, meta.publickey_to);
            temp = this.schema.concat(temp, this.schema.EncryptedData, payload);
        }

        if (meta.version == Crypto.KEYFROMKEYTO) {
            //params[0];//pubkey_from
            //params[1];//pubkey_to
            //params[2];//encrypteddata

            temp = this.schema.concat(temp, this.schema.PublicKey, meta.publickey_from);
            temp = this.schema.concat(temp, this.schema.PublicKey, meta.publickey_to);
            temp = this.schema.concat(temp, this.schema.EncryptedData, payload);
        }

        if (meta.version == Crypto.TEMPKEY) {
            //params[0];//pubkey_from
            //params[1];//filter_to
            //params[2];//encrypteddata

            temp = this.schema.concat(temp, this.schema.PublicKey, meta.publickey_from);
            temp = this.schema.concat(temp, this.schema.Filter, meta.filter_to);
            temp = this.schema.concat(temp, this.schema.EncryptedData, payload);
        }

        if (meta.version == Crypto.HELLOPUBLICKEY) {
            //params[0]publickey_from
            //params[1]filter_to
            //params[2]//encrypteddata

            temp = this.schema.concat(temp, this.schema.PublicKey, meta.publickey_from);
            temp = this.schema.concat(temp, this.schema.Filter, meta.filter_to);
            temp = this.schema.concat(temp, this.schema.EncryptedData, payload);
        }

        if (meta.version == Crypto.MEDIA) {
            temp = this.schema.concat(temp, this.schema.Filter, meta.filter_from);
            temp = this.schema.concat(temp, this.schema.EncryptedData, payload);
        }

        return temp;
    }
    encryptPayload(externalkey, keystore, data) {
        let X = this.createECDHsecret(externalkey, keystore);
        //encrypt value with | X, value -> encvalue
        return this.encryptECDH(data, X);
    }
    decryptPayload(externalkey, keystore, payload) {
        let X = this.createECDHsecret(externalkey, keystore);
        return this.decryptECDH(payload, X);
    }
    createECDHsecret(receiver_pk, keystore) {
        let ec = new EC('secp256k1');
        let key = ec.keyFromPrivate(keystore.privateKey, 16);
        let key2 = ec.keyFromPublic(receiver_pk, 'hex');

        return key.derive(key2.getPublic()).toString(16);
    }
    encryptECDH(buffer, secret, algorithm) {
        if (!algorithm)
            algorithm = 'aes-256-ctr';

        secret = Buffer.from(secret, 'hex');
        let key = cr.scryptSync(secret, SECRET, secret.length);
        const iv = cr.randomBytes(16);
        if (key.length < 32) {
            let leads = 32 - key.length;
            let leads_buff = Buffer.alloc(leads, '0');
            key = Buffer.concat([
                leads_buff,
                key
            ]);
        }

        const hash = this.sha256(buffer).slice(0, 8);
        const cipher = cr.createCipheriv(algorithm, Buffer.from(key, 'hex'), iv);
        const res = Buffer.concat([hash, iv, cipher.update(Buffer.from(buffer, 'hex')), cipher.final()]);
        /*console.log('encrypt', {
            iv,
            secret,
            secret_length: secret.length,
            key
        });*/
        return res;
    }
    decryptECDH(buffer, secret, algorithm) {
        if (!algorithm)
            algorithm = 'aes-256-ctr';
        const hash = buffer.slice(0, 8);
        const iv = buffer.slice(8, 24);
        const payload = buffer.slice(24);

        secret = Buffer.from(secret, 'hex');
        let key = cr.scryptSync(secret, SECRET, secret.length);
        if (key.length != 32) {
            let leads = 32 - key.length;
            let leads_buff = Buffer.alloc(leads, '0');
            key = Buffer.concat([
                leads_buff,
                key
            ]);
        }

        let decipher = cr.createDecipheriv(algorithm, key, iv);
        let buff = Buffer.concat([decipher.update(payload), decipher.final()]);
        /*console.log('decrypt', {
            iv,
            secret,
            secret_length: secret.length,
            key
        });*/

        const local_hash = this.sha256(buff).slice(0, 8);
        if (!hash.equals(local_hash))
            throw new Error('invalid payload digest sum');

        return buff;
    }
    sha256(message, output) {
        if (!output)
            output = '';
        return cr.createHash('sha256').update(message).digest(output);
    }
    sha256d(message, output) {
        if (!output)
            output = '';
        return cr.createHash('sha256').update(cr.createHash('sha256').update(message).digest()).digest(output);
    }
}

App.Crypto = Crypto;

module.exports = App;