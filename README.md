# FilterCryptography

## Intro

This package implements the functionality of secure chat without transferring information about the sender and recipients.

### Algorithm

Algorithm assumes asymmetric encryption with the ability to hide the sender and recipient of the message. The algorithm has the ability to exchange messages between users, as well as organize a media channel that allows you to broadcast messages to channel subscribers without revealing the recipients and the sender. 

Media channels can be of two types - public and private. Public media assumes an open list of subscribers stored in the cloud, and private - a closed one, in which only the media stores the list of subscribers. 

Аlgorithm has several options for interaction, described below.

## p2p (person to person)

For all examples have:
Alice (A) with private and public key
Bob (B) with private and public key

X = secret key, created by diffi-hellman algorithm:
Pseudocode:

`X1 = (publicKeyAlice, privateKeyBob), X2 = (publicKeyBob, privateKeyAlice), X1 == X2 == X`

`EncryptedMessage = encrypt(X, message);`

`bloomFilterAliceWithSalt = bloomFilter(randomBytes + publicKeyAlice)`
`bloomFilterBobWithSalt = bloomFilter(randomBytes + publicKeyBob)`


### keyfrom-keyto

`Payload = publicKeyAlice|publicKeyBob|EncryptedMessage`

### filterfrom-keyto

`Payload = bloomFilterAliceWithSalt|publicKeyBob|EncryptedMessage`


### keyfrom-filterto

`Payload = publicKeyAlice|bloomFilterBobWithSalt|EncryptedMessage`

### filterfrom-filterto (f2f)

`Payload = bloomFilterAliceWithSalt|bloomFilterBobWithSalt|EncryptedMessage`

### tempkey

Used for secretly change the public key of the opposite side. Alice sending message with oldkey and Bob after receive this message change dialog externalkey (PublicKeyAlice) to newkey.

`Payload = publicKeyAlice|bloomFilterBobWithSalt|SwitchMessage|SwitchKeyAdditionalData`
`SwitchMessage = encrypt(X,oldkey|newkey)`
`SwitchKeyAdditionalData = EncryptedData`

### hellopublickey

Used for media channels. Bob create extendedPublicKey with xpub. Alice use this xpub for create new dialog.
Alice makes temp key, and create externalkey by derive from xpub. Then send to xpub key message with new key (like in tempkey) and path of derived key. Bob received this message, create derived publicKey from path and xpub, and create dialog with tempkey, derivedkey 

`Payload = publicKeyAlice|bloomFilterBobWithSalt|SwitchHelloPublicKeyMessage`
`SwitchHelloPublicKeyMessage = encrypt(X,oldkey|newkey|path)`
`SwitchKeyAdditionalData = EncryptedData`

## Media (media to group of persons)

All info about media save in cloud db. Information contains media type, it can me public and private.

### public media

Public media uses a cloud db to store a list of subscribers, which is stored openly and each network member can count the number of subscribers and their public keys. Messages are sent openly without encryption

### private media

Private media store the list of subscribers locally, the subscription is done via encrypted messages. The number of subscribers and their list cannot be read. Messages are sent in encrypted form.

## Events

All necessary methods are implemented as events that need to be overridden. Below is a list of events with parameters and the necessary functionality.

```js

/*decrypt events*/
app.on('addDialog', (localkey, externalkey, callback, dialogName) => {
    //add dialog to local db
    callback();
})

app.on('removeDialog', (localkey, externalkey, callback) => {
    //remove existing dialog to local db
    callback();
})

app.on('getAllLocalPublicKeysList', (callback) => {
    //get all public keys from keystore
    callback(list);
})

app.on('getMediaKeys', (callback) => {
    //get all my media public keys 
    callback([])
})

app.on('getKeyInfo', (key, callback) => {
    //get dialog by localkey==key, and keystore of key
    callback(dialog, keystore);
})

app.on('getDialogByExternalKey', (externalkey, callback) => {
    //find dialog by externalkey
    callback();
})

/*encrypt events*/
app.on('getKeystoreByMeta', (context, version, callback) => {
    //fild keystore by context.localkey
});

/*keys events*/
app.on('seedAccess', (callback) => {
    //get access to seed phrase, use new app.seed("mnemonic")
    callback(new app.seed(mnemonic));
})

app.on('getLastIndex', (callback) => {
    //get last used key index
    callback(k++);
})

app.on('getLastPublicIndex', (callback) => {
    //get last used public key index
    callback(pk++)
})

app.on('saveNewKey', (type, keystore, callback) => {
    //save key to database, return keystore to callback
    callback(keystore);
})

//media:
app.on('getMediaInfo', (nameOrKey, callback) => {
    
    //find media by nameOrKey and return info
    callback(mediaLocalInfo);
})

app.on('saveMediaInfo', (data, callback) => {
    //save data to localdb
    callback(data)
})

app.on('getAllFollowedMediaKeys', (callback) => {
    //get add my media dialogs localkey
    callback([myMediaKey1, myMediaKey2])
})

app.on('addMediaDialog', (localkey, mediaName, callback) => {
    //add new dialog with media
    callback({ localkey, externalKey: mediaName });
})

app.on('removeMediaDialog', (localkey, mediaName, callback) => {
    //remove dialog with media
    callback();
})

app.on('getDialogWithMedia', (mediaName, callback) => {
    //find dialog by media name
    callback(dialogsWithMedia[mediaName])
})

app.on('getMediaFollowers', (mediaPubKey, callback) => {
    //get all followers from my private media
    callback(followers[mediaPubKey]);
})

app.on('addFollower', (localkey, followerkey, callback) => {
    //add follower to localtable of private media
    if (!followers[localkey])
        followers[localkey] = [];
    followers[localkey].push(followerkey);
    callback()
})

app.on('removeFollower', (localkey, followerkey, callback) => {
    //remove follower key from private media db
    followers[localkey].splice(followers[localkey].indexOf(followerkey), 1);
    callback()
})

//net
app.on('NET:getMediaInfo', (name, callback) => {
    //get media info from network
    callback(mediaNetInfo[name])
})

app.on('NET:saveMediaInfo', (name, data, callback) => {
    //save media info to network
    mediaNetInfo[name] = data;
    callback(mediaNetInfo[name]);
})

app.on('NET:setFollowState', (mediaName, followerState, callback) => {
    //set follower to follower table of public media
    callback();
})

app.on('NET:getFollowState', (mediaName, followerKey, callback) => {
    //get follower from follower table of public media
    callback(mediaNetFollowStateInfo[mediaName][followerKey]);
})

app.on('NET:getMempoolHistory', (callback) => {
    //get last N tx times from mempool
    callback([]);
});


app.on('NET:sendmempool', (data, callback) => {
    //send data to mempool
    callback()
});

/**
 * another events
 */

app.on('saveMessage', (dialog, content, options, callback) => {
    //save message to localdb
    callback({ hash: options.hash });
})

app.on('follower', (pubkey, followerKey) => {
    //info about new follower to private media (without callback)
})

app.on('notfollower', () => {
    //info about unfollow of follower to private media (without callback)
})

app.on('msg', (msg) => {
    //info about new message from network (without callback)
});
```



## Initialization

```js
    const APP = require('filtergraphy')
    let app = new APP();
```

## Methods

```js
app.createKeyPair(type)
    .then(keystore=>{
        
    })
```

```js
app.createPublicKeyPair()
    .then(keystore=>{
        //creates keystore with keystore.xpub key (for hellopublickey and medias)
    })
```

```js
app.addDialog(localkey, externalkey)
    .then(dialog=>{
        //creates new private dialog
    })
```

```js
app.removeDialog(localkey, externalkey)
    .then(()=>{
        //remove private dialog
    })
```

```js
app.addMediaDialog(localkey, mediaName)
    .then(()=>{
        //add dialog with media dialog 
    })
```

```js
app.removeMediaDialog(localkey, mediaName)
    .then(()=>{
        //remove dialog with media dialog
    })
```

```js
app.addMediaFollower(localKey, followerKey)
    .then(()=>{
        //add followers to PRIVATE_MEDIA media
    })
```

```js
app.removeMediaFollower(localKey, followerKey)
    .then(()=>{
        //remove followers to PRIVATE_MEDIA media
    })
```

```js
//creates new media and add it to media table.
//name is a `username` of media
//type can me 'MEDIA_PUBLIC' or 'MEDIA_PRIVATE'
app.createMedia(name, type)
    .then(()=>{
        //remove followers to PRIVATE_MEDIA media
    })
```

```js
//get info about media
app.getMedia(media_name)
    .then(media=>{
        
    })
```

```js
//only for media.type == MEDIA_PUBLIC
app.getFollowState(mediaName, followerKey)
    .then(followState=>{
        //returns info about follower of media  
    })
```

```js
//create new keystore and follow to media
app.follow(mediaName)
```

```js
//get follow keystore and unfollow from media
app.unfollow(mediaName)
```

```js
//broadcast buffer to all followers of media
app.mediaBroadcast(mediaName, buffer)
```


```js
/**
 * version types:
 * App.Crypto.FILTERTO
 * App.Crypto.FILTERFROMFILTERTO
 * App.Crypto.KEYTO
 * App.Crypto.KEYFROMKEYTO
 * App.Crypto.MEDIA
 * App.Crypto.HELLOPUBLICKEY
 * App.Crypto.TEMPKEY
 * 
 * 
 * context = {localkey, externalkey}
 * 
 * For version App.Crypto.HELLOPUBLICKEY
 * context = { externalkeyWithDerive: xpub }
 */
app.encrypt(context, buffer, version)
    .then(encryptedBuffer=>{
        
    })
```

```js
app.decrypt(encryptedBuffer)
    .then(result=>{

        //filter from-to, key from-to etc..
        result = {
            key: '03e27cfa304366c849be09cac09c0e03baf3f371291eb4adc2a36a2a9a002ae83c',
            dialog: {
                localkey: '03e27cfa304366c849be09cac09c0e03baf3f371291eb4adc2a36a2a9a002ae83c',
                externalkey: '02178d4517d71b8ed15544e377000f832725b6ebd1dfda72e2a01af2467d30395e'
            },
            keystore: {
                publicKey: '03e27cfa304366c849be09cac09c0e03baf3f371291eb4adc2a36a2a9a002ae83c',
                privateKey: '30068c1e860fac3e3aa16083310d3e6b1d061e53da16b08b100621c4f11796ec',
                path: "0'/0'/2",
                index: 2,
                keyType: 'private_dialog'
            },
            content: Buffer,
            meta: {
                from: '02178d4517d71b8ed15544e377000f832725b6ebd1dfda72e2a01af2467d30395e',
                to: '03e27cfa304366c849be09cac09c0e03baf3f371291eb4adc2a36a2a9a002ae83c',
                version: 2
            }
        }
        
        //tempkey result:
        result = {
            key: '03e27cfa304366c849be09cac09c0e03baf3f371291eb4adc2a36a2a9a002ae83c',
            dialog: {
                localkey: '03e27cfa304366c849be09cac09c0e03baf3f371291eb4adc2a36a2a9a002ae83c',
                externalkey: '02ff3efab1d0916490814cf03bc6e4d4b6125e14a2a41b2f04766a202209ba4bdb'
            },
            keystore: {
                publicKey: '03e27cfa304366c849be09cac09c0e03baf3f371291eb4adc2a36a2a9a002ae83c',
                privateKey: 'xxxx',
                path: "0'/0'/2",
                index: 2,
                keyType: 'private_dialog'
            },
            content: Buffer,
            meta: {
                from: '02ff3efab1d0916490814cf03bc6e4d4b6125e14a2a41b2f04766a202209ba4bdb',
                to: '03e27cfa304366c849be09cac09c0e03baf3f371291eb4adc2a36a2a9a002ae83c',
                version: 11,
                switch: SwitchKey {
                typename: 'SwitchKey',
                oldkey: [PublicKey],
                newkey: [PublicKey]
                }
            },
            raw: Buffer
        }

        //hellopublickey result:
        result = {
            dialog: {
                externalkey: '02ff3efab1d0916490814cf03bc6e4d4b6125e14a2a41b2f04766a202209ba4bdb',
                localkey: '02da762b0cf81bb366bb6d83349cdc631626f1457bf61c7ab1080c8d4163ec885c'
            },
            keystore: {
                publicKey: '02da762b0cf81bb366bb6d83349cdc631626f1457bf61c7ab1080c8d4163ec885c',
                privateKey: 'xxxxx',
                path: '0/0/1',
                index: 1,
                keyType: 'public_keypair',
                xpub: 'xpub6H3ZCjPj4Dsam3gx8VA29NRMqfujTXM8Wefuoa7T2o4fmRsPTmURiiCF2RXvM2g3nMMyFZRgab3JheQnAay7g1NkAP8JasxATGy7hjYBA5z'
            },
            content: Buffer,
            meta: {
                from: '02ff3efab1d0916490814cf03bc6e4d4b6125e14a2a41b2f04766a202209ba4bdb',
                to: '02da762b0cf81bb366bb6d83349cdc631626f1457bf61c7ab1080c8d4163ec885c',
                version: 10,
                switchHelloPublicKey: SwitchHelloPublicKey {
                    typename: 'SwitchHelloPublicKey',
                    oldkey: [PublicKey],
                    newkey: [PublicKey],
                    path: [HelloPublicKeyPath]
                }
            }
        }



    })  
    .catch(message=>{
        //can not decrypt message
    })
```