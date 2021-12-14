'use strict';

const BSON = require('bson');
const { EventEmitter, once } = require('events');
const net = require('net');
const tls = require('tls');
const expect = require('chai').expect;
const sinon = require('sinon');
const mongodb = require('mongodb');
const StateMachine = require('../lib/stateMachine')({ mongodb }).StateMachine;

describe('StateMachine', function() {
  class MockRequest {
    constructor(message, bytesNeeded) {
      this._bytesNeeded = typeof bytesNeeded === 'number' ? bytesNeeded : 1024;
      this._message = message;
      this.endpoint = 'some.fake.host.com';
      this._kmsProvider = 'aws';
    }

    get message() {
      return this._message;
    }

    get bytesNeeded() {
      return this._bytesNeeded;
    }

    get kmsProvider() {
      return this._kmsProvider;
    }

    addResponse(buffer) {
      this._bytesNeeded -= buffer.length;
    }
  }

  describe('kmsRequest', function() {
    class MockSocket extends EventEmitter {
      constructor(callback) {
        super();
        this.on('connect', callback);
      }
      write() {}
      destroy() {}
      end(callback) {
        Promise.resolve().then(callback);
      }
    }

    before(function() {
      this.sinon = sinon.createSandbox();
    });

    beforeEach(function() {
      this.fakeSocket = undefined;
      this.sinon.stub(tls, 'connect').callsFake((options, callback) => {
        this.fakeSocket = new MockSocket(callback);
        return this.fakeSocket;
      });
    });

    it('should only resolve once bytesNeeded drops to zero', function(done) {
      const stateMachine = new StateMachine({ bson: BSON });
      const request = new MockRequest(Buffer.from('foobar'), 500);
      let status = 'pending';
      stateMachine
        .kmsRequest(request)
        .then(
          () => (status = 'resolved'),
          () => (status = 'rejected')
        )
        .catch(() => {});

      this.fakeSocket.emit('connect');
      setTimeout(() => {
        expect(status).to.equal('pending');
        expect(request.bytesNeeded).to.equal(500);
        expect(request.kmsProvider).to.equal('aws');
        this.fakeSocket.emit('data', Buffer.alloc(300));
        setTimeout(() => {
          expect(status).to.equal('pending');
          expect(request.bytesNeeded).to.equal(200);
          this.fakeSocket.emit('data', Buffer.alloc(200));
          setTimeout(() => {
            expect(status).to.equal('resolved');
            expect(request.bytesNeeded).to.equal(0);
            done();
          });
        });
      });
    });

    afterEach(function() {
      this.sinon.restore();
    });
  });

  describe('Socks5 support', function() {
    let socks5srv;
    let hasTlsConnection;

    beforeEach(async () => {
      hasTlsConnection = false;
      socks5srv = net.createServer(async(socket) => {
        expect(await once(socket, 'data')).to.deep.equal([Buffer.from('05020002', 'hex')]);
        socket.write(Buffer.from('0500', 'hex'));
        expect(await once(socket, 'data')).to.deep.equal([Buffer.concat([
          Buffer.from('0501000312', 'hex'),
          Buffer.from('some.fake.host.com'),
          Buffer.from('01bb', 'hex')
        ])]);
        socket.write(Buffer.from('0500007f0000010100', 'hex'));
        expect((await once(socket, 'data'))[0][1]).to.equal(3); // TLS handshake version byte
        hasTlsConnection = true;
        socket.end();
      });
      socks5srv.listen(0);
      await once(socks5srv, 'listening');
    });

    afterEach(() => {
      socks5srv.close();
    });

    it('should create HTTPS connections through a Socks5 proxy', async function() {
      const stateMachine = new StateMachine({
        bson: BSON,
        proxyOptions: {
          host: 'localhost',
          port: socks5srv.address().port,
          username: 'foo',
          password: 'bar'
        }
      });

      const request = new MockRequest(Buffer.from('foobar'), 500);
      try {
        await stateMachine.kmsRequest(request);
      } catch (err) {
        expect(err.name).to.equal('MongoCryptError');
        expect(err.originalError.code).to.equal('ECONNRESET');
        expect(hasTlsConnection).to.equal(true);
        return;
      }
      expect.fail('missed exception');
    });
  });
});
