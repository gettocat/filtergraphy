const bitPony = require('bitpony');

module.exports = (app) => {
    //TODO:
    //uint32 schema
    //add checksum of key1+key2.
    class Schema {
        //actual versions
        //all types
        constructor() {
            this.Filter = Filter;
            this.PublicKey = PublicKey;
            this.HelloPublicKeyPath = HelloPublicKeyPath;
            this.EncryptedData = EncryptedData;
            this.SwitchKey = SwitchKey;
            this.SwitchHelloPublicKey = SwitchHelloPublicKey;
            this.SwitchKeyAdditionalData = SwitchKeyAdditionalData;
        }
        static read(buffer, offset) {
            let stream = new bitPony.reader(buffer);
            let res = stream.uint16(offset);
            offset = res.offset;

            let cls = this.Types[res.result];
            let cls_ = this[cls];
            if (!cls_)
                throw new Error('invalid schema object in read');
            let f = new cls_(-1);
            let off = f.fromStream(buffer, offset);

            return {
                offset: off,
                result: f
            }
        }
        static concat(buff, type, ...others) {
            let a = new type(...others);
            return Buffer.concat([buff, a.pack()]);
        }
        static create(type, ...others) {
            let a = new type(...others);
            return a;
        }
    }

    class Type {
        constructor(typename, schema_version) {
            this.typename = typename;
            this.version = schema_version || app.SCHEMA;
        }
        pack() {
            return Buffer.from("");
        }
        unpack(buffer) {

        }
        fromStream(buffer, offset) {
            let buff = Buffer.from(buffer, 'hex').subarray(offset);
            let off = this.unpack(buff);
            return offset + off;
        }
        toStream(buffer) {
            return Buffer.concat([buffer, this.pack()]);
        }
        getContent() {
            return "";
        }
    }

    class SwitchHelloPublicKey extends Type {
        //SwitchKey is encrypted local sender PublicKey and external path of public key.
        constructor(oldkey, newkey, path, version) {
            super('SwitchHelloPublicKey', version);

            if (oldkey != -1) {
                if (!(oldkey instanceof PublicKey))
                    throw new Error('keys must be instance of Schema.PublicKey');

                if (!(newkey instanceof PublicKey))
                    throw new Error('keys must be instance of Schema.PublicKey');

                if (!(path instanceof HelloPublicKeyPath))
                    throw new Error('keys must be instance of Schema.HelloPublicKeyPath');

                this.oldkey = oldkey;
                this.newkey = newkey;
                this.path = path;
            }
        }
        pack() {
            let stream = new bitPony.writer(Buffer.from(''));
            stream.uint16(Schema.Names['SwitchHelloPublicKey'], true);
            stream.string(Buffer.from(this.oldkey.pack(), 'hex'), true);
            stream.string(Buffer.from(this.newkey.pack(), 'hex'), true);
            stream.string(Buffer.from(this.path.pack(), 'hex'), true);
            return stream.getBuffer();
        }
        unpack(buffer) {
            let stream = new bitPony.reader(buffer);
            let res = stream.string(0);
            this.oldkey = Schema.read(res.result, 0).result;

            res = stream.string(res.offset);
            this.newkey = Schema.read(res.result, 0).result;

            res = stream.string(res.offset);
            this.path = Schema.read(res.result, 0).result;

            return res.offset;
        }
        getContent() {
            return {
                old: this.oldkey,
                new: this.newkey,
                path: this.path,
            }
        }
    }

    class SwitchKey extends Type {
        //SwitchKey is encrypted PublicKey
        constructor(oldkey, newkey, version) {
            super('SwitchKey', version);

            if (oldkey != -1) {
                if (!(oldkey instanceof PublicKey))
                    throw new Error('keys must be instance of Schema.PublicKey');

                if (!(newkey instanceof PublicKey))
                    throw new Error('keys must be instance of Schema.PublicKey');

                this.oldkey = oldkey;
                this.newkey = newkey;
            }
        }
        pack() {
            let stream = new bitPony.writer(Buffer.from(''));
            stream.uint16(Schema.Names['SwitchKey'], true);
            stream.string(this.oldkey.pack(), true);
            stream.string(this.newkey.pack(), true);
            return stream.getBuffer();
        }
        unpack(buffer) {
            let stream = new bitPony.reader(buffer);
            let res = stream.string(0);
            this.oldkey = Schema.read(res.result, 0).result;

            res = stream.string(res.offset);
            this.newkey = Schema.read(res.result, 0).result;

            return res.offset;
        }
        getContent() {
            return {
                old: this.oldkey,
                new: this.newkey
            }
        }
    }

    class EncryptedData extends Type {
        constructor(payload, payloadtype, version) {
            super('EncryptedData', version);
            if (payload != -1) {
                this.payload = payload;
                this.payloadtype = payloadtype || 1; //encryption type
            }
        }
        pack() {
            let stream = new bitPony.writer(Buffer.from(''));
            stream.uint16(Schema.Names['EncryptedData'], true);
            stream.uint16(this.payloadtype, true);
            stream.string(Buffer.from(this.payload, 'hex'), true);
            return stream.getBuffer();
        }
        unpack(buffer) {
            let stream = new bitPony.reader(buffer);
            let res = stream.uint16(0);
            this.payloadtype = res.result;
            res = stream.string(res.offset);
            this.payload = res.result;
            return res.offset;
        }
        getContent() {
            return this.payload;
        }
    }

    class SwitchKeyAdditionalData extends Type {
        constructor(payload, payloadtype, version) {
            super('SwitchKeyAdditionalData', version);
            if (payload != -1) {
                this.payload = payload;
                this.payloadtype = payloadtype || 1; //encryption type
            }
        }
        pack() {
            let stream = new bitPony.writer(Buffer.from(''));
            stream.uint16(Schema.Names['SwitchKeyAdditionalData'], true);
            stream.uint16(this.payloadtype, true);
            stream.string(Buffer.from(this.payload, 'hex'), true);
            return stream.getBuffer();
        }
        unpack(buffer) {
            let stream = new bitPony.reader(buffer);
            let res = stream.uint16(0);
            this.payloadtype = res.result;
            res = stream.string(res.offset);
            this.payload = res.result;
            return res.offset;
        }
        getContent() {
            return this.payload;
        }
    }

    class HelloPublicKeyPath extends Type {
        constructor(path, pathtype, version) {
            super('HelloPublicKeyPath', version);
            if (path != -1) {
                this.pathtype = pathtype || 0;
                this.path = path;
            }
        }
        pack() {
            let stream = new bitPony.writer(Buffer.from(''));
            stream.uint16(Schema.Names['HelloPublicKeyPath'], true);
            stream.uint16(this.pathtype, true);

            let arr = this.path.split("/");
            stream.uint8(arr.length, true);

            for (let el of arr) {
                stream.uint32(el, true);
            }

            return stream.getBuffer();
        }
        unpack(buffer) {
            let stream = new bitPony.reader(buffer);
            let res = stream.uint16(0);
            this.pathtype = res.result;

            let arr = [];
            res = stream.uint8(res.offset);
            let size = res.result;

            for (let i = 0; i < size; i++) {
                res = stream.uint32(res.offset);
                arr.push(res.result);
            }

            this.path = arr.join('/');

            return res.offset;
        }
        getContent() {
            return this.path;
        }
    }

    class PublicKey extends Type {
        constructor(key, keytype, version) {
            super('PublicKey', version);
            if (key != -1) {
                this.keytype = keytype || 0;
                this.key = key;
            }
        }
        pack() {
            let stream = new bitPony.writer(Buffer.from(''));
            stream.uint16(Schema.Names['PublicKey'], true);
            stream.uint16(this.keytype, true);
            stream.string(Buffer.from(this.key, 'hex'), true);
            return stream.getBuffer();
        }
        unpack(buffer) {
            let stream = new bitPony.reader(buffer);
            let res = stream.uint16(0);
            this.keytype = res.result;
            res = stream.string(res.offset);
            this.key = res.result.toString('hex');
            return res.offset;
        }
        getContent() {
            return this.key;
        }
    }

    class Filter extends Type {
        constructor(filter, filtertype, version) {
            super('Filter', version);
            if (filter != -1) {
                this.filtertype = filtertype || 0;
                this.filter = filter;
            }
        }
        pack() {
            let stream = new bitPony.writer(Buffer.from(''));
            stream.uint16(Schema.Names['Filter'], true);
            stream.uint16(this.filtertype, true);
            stream.string(Buffer.from(this.filter, 'hex'), true);
            return stream.getBuffer();
        }
        unpack(buffer) {
            let stream = new bitPony.reader(buffer);
            let res = stream.uint16(0);
            this.filtertype = res.result;
            res = stream.string(res.offset);
            this.filter = res.result;
            return res.offset;
        }
        getContent() {
            return this.filter;
        }
    }

    Schema.Filter = Filter;
    Schema.EncryptedData = EncryptedData;
    Schema.PublicKey = PublicKey;
    Schema.HelloPublicKeyPath = HelloPublicKeyPath;
    Schema.SwitchKey = SwitchKey;
    Schema.SwitchHelloPublicKey = SwitchHelloPublicKey;
    Schema.SwitchKeyAdditionalData = SwitchKeyAdditionalData;

    Schema.Types = {
        100: 'Filter',
        200: 'PublicKey',
        1000: 'EncryptedData',
        1001: 'SwitchKeyAdditionalData',
        1002: 'SwitchKey',
        1003: 'SwitchHelloPublicKey',
        2001: 'HelloPublicKeyPath',
    };

    Schema.Names = {
        'Filter': 100,
        'PublicKey': 200,
        'EncryptedData': 1000,
        'SwitchKeyAdditionalData': 1001,
        'SwitchKey': 1002,
        'SwitchHelloPublicKey': 1003,
        'HelloPublicKeyPath': 2001,
    };

    return Schema;

}