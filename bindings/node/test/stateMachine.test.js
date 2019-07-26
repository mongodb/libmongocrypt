'use strict';

const EventEmitter = require('events').EventEmitter;
const tls = require('tls');
const expect = require('chai').expect;
const sinon = require('sinon');
const mongodb = require('mongodb');
const common = require('../lib/common')({ mongodb });
const StateMachine = require('../lib/stateMachine')({ mongodb, common }).StateMachine;

describe('StateMachine', function() {
  describe('kmsRequest', function() {
    class MockRequest {
      constructor(message, bytesNeeded) {
        this._bytesNeeded = typeof bytesNeeded === 'number' ? bytesNeeded : 1024;
        this._message = message;
        this.endPoint = 'some.fake.host.com';
      }
      get message() {
        return this._message;
      }

      get bytesNeeded() {
        return this._bytesNeeded;
      }

      addResponse(buffer) {
        this._bytesNeeded -= buffer.length;
      }
    }

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
      const stateMachine = new StateMachine();
      const request = new MockRequest(Buffer.from('foobar'), 500);
      let status = 'pending';
      stateMachine
        .kmsRequest(request)
        .then(() => (status = 'resolved'), () => (status = 'rejected'))
        .catch(() => {});

      this.fakeSocket.emit('connect');
      setTimeout(() => {
        expect(status).to.equal('pending');
        expect(request.bytesNeeded).to.equal(500);
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
});
