@0xcd997b20d7d0a48c;

interface CdmWorker {
  createCdmInstance @0 (cdmInterfaceVersion: Int8, keySystem: Text, hostProxy: HostProxy) -> (cdmProxy: CdmProxy);
  getCdmVersion     @1 () -> (version: Text);
}

struct VideoFrameSize {
  width  @0: Int32;
  height @1: Int32;
}

struct VideoDecoderConfig2 {
  codec            @0: UInt32;
  profile          @1: UInt32;
  format           @2: UInt32;
  codedSize        @3: VideoFrameSize;
  extraData        @4: Data;
  encryptionScheme @5: UInt32;
}

struct Buffer {
  offset @0: UInt32;
  size   @1: UInt32;
}

struct VideoFrame {
  format        @0: UInt32;
  size          @1: VideoFrameSize;
  frameBuffer   @2: Buffer;
  kYPlaneOffset @3: UInt32;
  kUPlaneOffset @4: UInt32;
  kVPlaneOffset @5: UInt32;
  kYPlaneStride @6: UInt32;
  kUPlaneStride @7: UInt32;
  kVPlaneStride @8: UInt32;
  timestamp     @9: Int64;
}

struct KeyInformation {
  keyId      @0: Data;
  status     @1: UInt32;
  systemCode @2: UInt32;
}

struct DecryptedBlock {
  buffer    @0: Buffer;
  timestamp @1: Int64;
}

struct Policy {
  minHdcpVersion @0: UInt32;
}

interface CdmProxy {
  initialize                      @  0 (allowDistinctiveIdentifier: Bool, allowPersistentState: Bool, useHwSecureCodecs: Bool);
  getStatusForPolicy              @  1 (promiseId: UInt32, policy: Policy);
  setServerCertificate            @  2 (promiseId: UInt32, serverCertificateData: Data);
  createSessionAndGenerateRequest @  3 (promiseId: UInt32, sessionType: UInt32, initDataType: UInt32, initData: Data);
  loadSession                     @  4 (); # TODO
  updateSession                   @  5 (promiseId: UInt32, sessionId: Text, response: Data);
  closeSession                    @  6 (promiseId: UInt32, sessionId: Text);
  removeSession                   @  7 (); # TODO
  timerExpired                    @  8 (context: UInt64);
  decrypt                         @  9 (encryptedBufferOffset: UInt32) -> (status: UInt32, decryptedBuffer: DecryptedBlock);
  initializeAudioDecoder          @ 10 (); # TODO
  initializeVideoDecoder          @ 11 (videoDecoderConfig: VideoDecoderConfig2) -> (status: UInt32);
  deinitializeDecoder             @ 12 (decoderType: UInt32);
  resetDecoder                    @ 13 (decoderType: UInt32);
  decryptAndDecodeFrame           @ 14 (encryptedBufferOffset: UInt32) -> (status: UInt32, videoFrame: VideoFrame);
  decryptAndDecodeSamples         @ 15 (); # TODO
  onPlatformChallengeResponse     @ 16 (); # TODO
  onQueryOutputProtectionStatus   @ 17 (result: UInt32, linkMask: UInt32, outputProtectionMask: UInt32);
  onStorageId                     @ 18 (version: UInt32, storageId: Data);
}

interface FileIOProxy {
  open  @0 (fileName: Text);
  read  @1 ();
  write @2 (data: Data);
  close @3 ();
}

interface FileIOClientProxy {
  onOpenComplete  @0 (status: UInt32);
  onReadComplete  @1 (status: UInt32, data: Data);
  onWriteComplete @2 (status: UInt32);
}

interface HostProxy {
  setTimer                     @  0 (delayMs: Int64, context: UInt64);
  onInitialized                @  1 (success: Bool);
  onResolveKeyStatusPromise    @  2 (promiseId: UInt32, keyStatus: UInt32);
  onResolveNewSessionPromise   @  3 (promiseId: UInt32, sessionId: Text);
  onResolvePromise             @  4 (promiseId: UInt32);
  onRejectPromise              @  5 (promiseId: UInt32, exception: UInt32, systemCode: UInt32, errorMessage: Text);
  onSessionMessage             @  6 (sessionId: Text, messageType: UInt32, message: Text);
  onSessionKeysChange          @  7 (sessionId: Text, hasAdditionalUsableKey: Bool, keysInfo: List(KeyInformation));
  onExpirationChange           @  8 (sessionId: Text, newExpiryTime: Float64);
  onSessionClosed              @  9 (sessionId: Text);
  sendPlatformChallenge        @ 10 (); # TODO
  enableOutputProtection       @ 11 (); # TODO
  queryOutputProtectionStatus  @ 12 ();
  onDeferredInitializationDone @ 13 (); # TODO
  createFileIO                 @ 14 (client: FileIOClientProxy) -> (fileIO: FileIOProxy);
  requestStorageId             @ 15 (version: UInt32);
  reportMetrics                @ 16 (metricName: UInt32, value: UInt64);
}
