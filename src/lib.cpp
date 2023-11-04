#include <cerrno>
#include <cstdlib>
#include <cstdio>
#include <fcntl.h>
#include <dlfcn.h>
#include <spawn.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <kj/main.h>
#include <capnp/rpc-twoparty.h>
#include <cdm/content_decryption_module.h>
#include "cdm.capnp.h"
#include "config.h"
#include "util.h"

static uint32_t write_input_buffer(const cdm::InputBuffer_2& source, XAlloc& allocator) {

  auto data = allocator.allocate(source.data_size);
  memcpy(data, source.data, source.data_size);

  auto key_id = allocator.allocate(source.key_id_size);
  memcpy(key_id, source.key_id, source.key_id_size);

  auto iv = allocator.allocate(source.iv_size);
  memcpy(iv, source.iv, source.iv_size);

  auto subsamples = allocator.allocate(sizeof(cdm::SubsampleEntry) * source.num_subsamples);
  memcpy(subsamples, source.subsamples, sizeof(cdm::SubsampleEntry) * source.num_subsamples);

  auto input_buffer = reinterpret_cast<cdm::InputBuffer_2*>(allocator.allocate(sizeof(cdm::InputBuffer_2)));
  memcpy(input_buffer, &source, sizeof(cdm::InputBuffer_2));

  input_buffer->data       = reinterpret_cast<uint8_t*>(allocator.getOffset(data));
  input_buffer->key_id     = reinterpret_cast<uint8_t*>(allocator.getOffset(key_id));
  input_buffer->iv         = reinterpret_cast<uint8_t*>(allocator.getOffset(iv));
  input_buffer->subsamples = reinterpret_cast<cdm::SubsampleEntry*>(allocator.getOffset(subsamples));

  return allocator.getOffset(reinterpret_cast<uint8_t*>(input_buffer));
}

class CdmWrapper: public cdm::ContentDecryptionModule_10 {

  pid_t                              m_worker_pid;
  kj::AsyncIoContext&                m_io;
  kj::Own<kj::AsyncCapabilityStream> m_stream;
  kj::Own<capnp::TwoPartyClient>     m_client;
  CdmProxy::Client                   m_cdm;
  cdm::Host_10*                      m_host;
  XAlloc                             m_allocator;
  void*                              m_decrypted_buffers;

public:

  void Initialize(bool allow_distinctive_identifier, bool allow_persistent_state, bool use_hw_secure_codecs) override {
    KJ_DLOG(INFO, "Initialize", allow_distinctive_identifier, allow_persistent_state, use_hw_secure_codecs);
    auto request = m_cdm.initializeRequest();
    request.setAllowDistinctiveIdentifier(allow_distinctive_identifier);
    request.setAllowPersistentState(allow_persistent_state);
    request.setUseHwSecureCodecs(use_hw_secure_codecs);
    request.send().wait(m_io.waitScope);
    KJ_DLOG(INFO, "exiting Initialize");
  }

  void GetStatusForPolicy(uint32_t promise_id, const cdm::Policy& policy) override {
    KJ_DLOG(INFO, "GetStatusForPolicy", promise_id, policy.min_hdcp_version);
    auto request = m_cdm.getStatusForPolicyRequest();
    request.setPromiseId(promise_id);
    request.getPolicy().setMinHdcpVersion(policy.min_hdcp_version);
    request.send().wait(m_io.waitScope);
    KJ_DLOG(INFO, "exiting GetStatusForPolicy");
  }

  void SetServerCertificate(uint32_t promise_id, const uint8_t* server_certificate_data, uint32_t server_certificate_data_size) override {
    KJ_DLOG(INFO, "SetServerCertificate", promise_id, server_certificate_data, server_certificate_data_size);
    auto request = m_cdm.setServerCertificateRequest();
    request.setPromiseId(promise_id);
    request.setServerCertificateData(kj::arrayPtr(server_certificate_data, server_certificate_data_size));
    request.send().wait(m_io.waitScope);
    KJ_DLOG(INFO, "exiting SetServerCertificate");
  }

  void CreateSessionAndGenerateRequest(
    uint32_t promise_id, cdm::SessionType session_type, cdm::InitDataType init_data_type, const uint8_t* init_data, uint32_t init_data_size) override {
    KJ_DLOG(INFO, "CreateSessionAndGenerateRequest", promise_id, session_type, init_data_type, init_data, init_data_size);
    auto request = m_cdm.createSessionAndGenerateRequestRequest();
    request.setPromiseId(promise_id);
    request.setSessionType(session_type);
    request.setInitDataType(init_data_type);
    request.setInitData(kj::arrayPtr(init_data, init_data_size));
    request.send().wait(m_io.waitScope);
    KJ_DLOG(INFO, "exiting CreateSessionAndGenerateRequest");
  }

  void LoadSession(uint32_t promise_id, cdm::SessionType session_type, const char* session_id, uint32_t session_id_size) override {
    KJ_UNIMPLEMENTED("LoadSession");
  }

  void UpdateSession(uint32_t promise_id, const char* session_id, uint32_t session_id_size, const uint8_t* response, uint32_t response_size) override {
    KJ_DLOG(INFO, "UpdateSession", promise_id, session_id, session_id_size, response, response_size);
    auto request = m_cdm.updateSessionRequest();
    request.setPromiseId(promise_id);
    request.setSessionId(kj::StringPtr(session_id, session_id_size));
    request.setResponse(kj::arrayPtr(response, response_size));
    request.send().wait(m_io.waitScope);
    KJ_DLOG(INFO, "exiting UpdateSession");
  }

  void CloseSession(uint32_t promise_id, const char* session_id, uint32_t session_id_size) override {
    KJ_DLOG(INFO, "CloseSession", promise_id, session_id, session_id_size);
    auto request = m_cdm.closeSessionRequest();
    request.setPromiseId(promise_id);
    request.setSessionId(kj::StringPtr(session_id, session_id_size));
    request.send().wait(m_io.waitScope);
    KJ_DLOG(INFO, "exiting CloseSession");
  }

  void RemoveSession(uint32_t promise_id, const char* session_id, uint32_t session_id_size) override {
    KJ_UNIMPLEMENTED("RemoveSession");
  }

  void TimerExpired(void* context) override {
    KJ_DLOG(INFO, "TimerExpired", context);
    auto request = m_cdm.timerExpiredRequest();
    request.setContext(reinterpret_cast<uint64_t>(context));
    request.send().wait(m_io.waitScope);
    KJ_DLOG(INFO, "exiting TimerExpired");
  }

  cdm::Status Decrypt(const cdm::InputBuffer_2& encrypted_buffer, cdm::DecryptedBlock* decrypted_buffer) override {
    KJ_DLOG(INFO, "Decrypt");
    KJ_ASSERT(decrypted_buffer->DecryptedBuffer() == nullptr);

    auto request = m_cdm.decryptRequest();

    uint32_t offset = write_input_buffer(encrypted_buffer, m_allocator);
    request.setEncryptedBufferOffset(offset);

    auto response = request.send().wait(m_io.waitScope);
    auto status   = static_cast<cdm::Status>(response.getStatus());

    m_allocator.forget();

    if (status == cdm::kSuccess) {

      auto source = response.getDecryptedBuffer();

      auto buffer = m_host->Allocate(source.getBuffer().getSize());
      buffer->SetSize(source.getBuffer().getSize());
      memcpy(buffer->Data(), reinterpret_cast<uint8_t*>(m_decrypted_buffers) + source.getBuffer().getOffset(), source.getBuffer().getSize());
      decrypted_buffer->SetDecryptedBuffer(buffer);

      decrypted_buffer->SetTimestamp(source.getTimestamp());
    }

    KJ_DLOG(INFO, "exiting Decrypt", status);
    return status;
  }

  cdm::Status InitializeAudioDecoder(const cdm::AudioDecoderConfig_2& audio_decoder_config) override {
    KJ_UNIMPLEMENTED("InitializeAudioDecoder");
  }

  cdm::Status InitializeVideoDecoder(const cdm::VideoDecoderConfig_2& video_decoder_config) override {
    KJ_DLOG(INFO, "InitializeVideoDecoder");

    auto request = m_cdm.initializeVideoDecoderRequest();
    {
      auto req_video_decoder_config = request.getVideoDecoderConfig();
      req_video_decoder_config.setCodec  (video_decoder_config.codec);
      req_video_decoder_config.setProfile(video_decoder_config.profile);
      req_video_decoder_config.setFormat (video_decoder_config.format);
      {
        auto req_coded_size = req_video_decoder_config.getCodedSize();
        req_coded_size.setWidth (video_decoder_config.coded_size.width);
        req_coded_size.setHeight(video_decoder_config.coded_size.height);
      }
      req_video_decoder_config.setExtraData(kj::arrayPtr(video_decoder_config.extra_data, video_decoder_config.extra_data_size));
      req_video_decoder_config.setEncryptionScheme(static_cast<uint32_t>(video_decoder_config.encryption_scheme));
    }
    auto response = request.send().wait(m_io.waitScope);
    auto status   = static_cast<cdm::Status>(response.getStatus());

    KJ_DLOG(INFO, "exiting InitializeVideoDecoder", status);
    return status;
  }

  void DeinitializeDecoder(cdm::StreamType decoder_type) override {
    KJ_DLOG(INFO, "DeinitializeDecoder", decoder_type);
    auto request = m_cdm.deinitializeDecoderRequest();
    request.setDecoderType(decoder_type);
    request.send().wait(m_io.waitScope);
    KJ_DLOG(INFO, "exiting DeinitializeDecoder");
  }

  void ResetDecoder(cdm::StreamType decoder_type) override {
    KJ_DLOG(INFO, "ResetDecoder", decoder_type);
    auto request = m_cdm.resetDecoderRequest();
    request.setDecoderType(decoder_type);
    request.send().wait(m_io.waitScope);
    KJ_DLOG(INFO, "exiting ResetDecoder");
  }

  cdm::Status DecryptAndDecodeFrame(const cdm::InputBuffer_2& encrypted_buffer, cdm::VideoFrame* video_frame) override {
    KJ_DLOG(INFO, "DecryptAndDecodeFrame");
    KJ_ASSERT(video_frame->FrameBuffer() == nullptr);

    auto request = m_cdm.decryptAndDecodeFrameRequest();

    uint32_t offset = write_input_buffer(encrypted_buffer, m_allocator);
    request.setEncryptedBufferOffset(offset);

    auto response = request.send().wait(m_io.waitScope);
    auto status   = static_cast<cdm::Status>(response.getStatus());

    m_allocator.forget();

    if (status == cdm::kSuccess) {

      auto source = response.getVideoFrame();

      video_frame->SetFormat(static_cast<cdm::VideoFormat>(source.getFormat()));
      video_frame->SetSize(cdm::Size { .width = source.getSize().getWidth(), .height = source.getSize().getHeight() });

      auto framebuffer = m_host->Allocate(source.getFrameBuffer().getSize());
      framebuffer->SetSize(source.getFrameBuffer().getSize());
      memcpy(framebuffer->Data(), reinterpret_cast<uint8_t*>(m_decrypted_buffers) + source.getFrameBuffer().getOffset(), source.getFrameBuffer().getSize());
      video_frame->SetFrameBuffer(framebuffer);

      video_frame->SetPlaneOffset(cdm::kYPlane, source.getKYPlaneOffset());
      video_frame->SetPlaneOffset(cdm::kUPlane, source.getKUPlaneOffset());
      video_frame->SetPlaneOffset(cdm::kVPlane, source.getKVPlaneOffset());

      video_frame->SetStride(cdm::kYPlane, source.getKYPlaneStride());
      video_frame->SetStride(cdm::kUPlane, source.getKUPlaneStride());
      video_frame->SetStride(cdm::kVPlane, source.getKVPlaneStride());

      video_frame->SetTimestamp(source.getTimestamp());
    }

    KJ_DLOG(INFO, "exiting DecryptAndDecodeFrame", status);
    return status;
  }

  cdm::Status DecryptAndDecodeSamples(const cdm::InputBuffer_2& encrypted_buffer, cdm::AudioFrames* audio_frames) override {
    KJ_UNIMPLEMENTED("DecryptAndDecodeSamples");
  }

  void OnPlatformChallengeResponse(const cdm::PlatformChallengeResponse& response) override {
    KJ_UNIMPLEMENTED("OnPlatformChallengeResponse");
  }

  void OnQueryOutputProtectionStatus(cdm::QueryResult result, uint32_t link_mask, uint32_t output_protection_mask) override {
    KJ_DLOG(INFO, "OnQueryOutputProtectionStatus", result, link_mask, output_protection_mask);
    auto request = m_cdm.onQueryOutputProtectionStatusRequest();
    request.setResult(result);
    request.setLinkMask(link_mask);
    request.setOutputProtectionMask(output_protection_mask);
    request.send().wait(m_io.waitScope);
    KJ_DLOG(INFO, "exiting OnQueryOutputProtectionStatus");
  }

  void OnStorageId(uint32_t version, const uint8_t* storage_id, uint32_t storage_id_size) override {
    KJ_DLOG(INFO, "OnStorageId", version, storage_id, storage_id_size);
    auto request = m_cdm.onStorageIdRequest();
    request.setVersion(version);
    request.setStorageId(kj::arrayPtr(storage_id, storage_id_size));
    request.send().wait(m_io.waitScope);
    KJ_DLOG(INFO, "exiting OnStorageId");
  }

  void Destroy() override {
    KJ_DLOG(INFO, "Destroy");
    //TODO: we can't just use `delete this` because m_cdm.~Client() apparently gives us
    // "Fatal uncaught kj::Exception: kj/io.c++:331: failed: close: Bad file descriptor"
    KJ_SYSCALL(munmap(m_decrypted_buffers, SHMEM_ARENA_SIZE));
    m_client.~Own();
    m_stream.~Own();
    int status;
    KJ_SYSCALL(waitpid(m_worker_pid, &status, 0));
  }

  CdmWrapper(pid_t worker_pid, kj::AsyncIoContext& io, kj::Own<kj::AsyncCapabilityStream> stream, kj::Own<capnp::TwoPartyClient> client,
    CdmProxy::Client cdm, cdm::Host_10* host, XAlloc allocator, void* decrypted_buffers) :
      m_worker_pid(worker_pid), m_io(io), m_stream(kj::mv(stream)), m_client(kj::mv(client)),
        m_cdm(kj::mv(cdm)), m_host(host), m_allocator(kj::mv(allocator)), m_decrypted_buffers(decrypted_buffers) {}

  ~CdmWrapper() noexcept {
    //KJ_SYSCALL(munmap(m_decrypted_buffers, SHMEM_ARENA_SIZE));
  }
};

static thread_local kj::AsyncIoContext io = kj::setupAsyncIo();

class FileIOProxyImpl final: public FileIOProxy::Server {

  cdm::FileIO* m_file_io;

public:

  kj::Promise<void> open(OpenContext context) override {
    KJ_DLOG(INFO, "open");
    auto file_name = context.getParams().getFileName();
    m_file_io->Open(file_name.begin(), file_name.size());
    KJ_DLOG(INFO, "exiting open");
    return kj::READY_NOW;
  }

  kj::Promise<void> read(ReadContext context) override {
    KJ_DLOG(INFO, "read");
    m_file_io->Read();
    KJ_DLOG(INFO, "exiting read");
    return kj::READY_NOW;
  }

  kj::Promise<void> write(WriteContext context) override {
    KJ_DLOG(INFO, "write");
    auto data = context.getParams().getData();
    m_file_io->Write(data.begin(), data.size());
    KJ_DLOG(INFO, "exiting write");
    return kj::READY_NOW;
  }

  kj::Promise<void> close(CloseContext context) override {
    KJ_DLOG(INFO, "close");
    m_file_io->Close();
    KJ_DLOG(INFO, "exiting close");
    return kj::READY_NOW;
  }

  FileIOProxyImpl(cdm::FileIO* io) : m_file_io(io) {}
};

class FileIOClientWrapper: public cdm::FileIOClient {

  FileIOClientProxy::Client m_client;

public:

  void OnOpenComplete(cdm::FileIOClient::Status status) override {
    KJ_DLOG(INFO, "OnOpenComplete", static_cast<uint32_t>(status));
    auto request = m_client.onOpenCompleteRequest();
    request.setStatus(static_cast<uint32_t>(status));
    request.send().wait(io.waitScope);
    KJ_DLOG(INFO, "exiting OnOpenComplete");
  }

  void OnReadComplete(cdm::FileIOClient::Status status, const uint8_t* data, uint32_t data_size) override {
    KJ_DLOG(INFO, "OnReadComplete", static_cast<uint32_t>(status));
    auto request = m_client.onReadCompleteRequest();
    request.setStatus(static_cast<uint32_t>(status));
    request.setData(kj::arrayPtr(data, data_size));
    request.send().wait(io.waitScope);
    KJ_DLOG(INFO, "exiting OnReadComplete");
  }

  void OnWriteComplete(cdm::FileIOClient::Status status) override {
    KJ_DLOG(INFO, "OnWriteComplete", static_cast<uint32_t>(status));
    auto request = m_client.onWriteCompleteRequest();
    request.setStatus(static_cast<uint32_t>(status));
    request.send().wait(io.waitScope);
    KJ_DLOG(INFO, "exiting OnWriteComplete");
  }

  FileIOClientWrapper(FileIOClientProxy::Client&& client) : m_client(client) {}

  ~FileIOClientWrapper() noexcept {
    KJ_ASSERT(0);
  }
};

class HostProxyImpl final: public HostProxy::Server {

  cdm::Host_10* m_host;

public:

  kj::Promise<void> setTimer(SetTimerContext context) override {
    KJ_DLOG(INFO, "setTimer");
    auto delay_ms = context.getParams().getDelayMs();
    auto context_ = reinterpret_cast<void*>(context.getParams().getContext());
    m_host->SetTimer(delay_ms, context_);
    KJ_DLOG(INFO, "exiting setTimer");
    return kj::READY_NOW;
  }

  kj::Promise<void> onInitialized(OnInitializedContext context) override {
    KJ_DLOG(INFO, "onInitialized");
    auto success = context.getParams().getSuccess();
    m_host->OnInitialized(success);
    KJ_DLOG(INFO, "exiting onInitialized");
    return kj::READY_NOW;
  }

  kj::Promise<void> onResolveKeyStatusPromise(OnResolveKeyStatusPromiseContext context) override {
    KJ_DLOG(INFO, "onResolveKeyStatusPromise");
    auto promise_id = context.getParams().getPromiseId();
    auto key_status = context.getParams().getKeyStatus();
    m_host->OnResolveKeyStatusPromise(promise_id, static_cast<cdm::KeyStatus>(key_status));
    KJ_DLOG(INFO, "exiting onResolveKeyStatusPromise");
    return kj::READY_NOW;
  }

  kj::Promise<void> onResolveNewSessionPromise(OnResolveNewSessionPromiseContext context) override {
    KJ_DLOG(INFO, "onResolveNewSessionPromise");
    auto promise_id = context.getParams().getPromiseId();
    auto session_id = context.getParams().getSessionId();
    m_host->OnResolveNewSessionPromise(promise_id, session_id.begin(), session_id.size());
    KJ_DLOG(INFO, "exiting onResolveNewSessionPromise");
    return kj::READY_NOW;
  }

  kj::Promise<void> onResolvePromise(OnResolvePromiseContext context) override {
    KJ_DLOG(INFO, "onResolvePromise");
    auto promise_id = context.getParams().getPromiseId();
    m_host->OnResolvePromise(promise_id);
    KJ_DLOG(INFO, "exiting onResolvePromise");
    return kj::READY_NOW;
  }

  kj::Promise<void> onRejectPromise(OnRejectPromiseContext context) override {
    KJ_DLOG(INFO, "onRejectPromise");
    auto promise_id    = context.getParams().getPromiseId();
    auto exception     = context.getParams().getException();
    auto system_code   = context.getParams().getSystemCode();
    auto error_message = context.getParams().getErrorMessage();
    m_host->OnRejectPromise(promise_id, static_cast<cdm::Exception>(exception), system_code, error_message.begin(), error_message.size());
    KJ_DLOG(INFO, "exiting onRejectPromise");
    return kj::READY_NOW;
  }

  kj::Promise<void> onSessionMessage(OnSessionMessageContext context) override {
    KJ_DLOG(INFO, "onSessionMessage");
    auto session_id   = context.getParams().getSessionId();
    auto message_type = context.getParams().getMessageType();
    auto message      = context.getParams().getMessage();
    m_host->OnSessionMessage(session_id.begin(), session_id.size(), static_cast<cdm::MessageType>(message_type), message.begin(), message.size());
    KJ_DLOG(INFO, "exiting onSessionMessage");
    return kj::READY_NOW;
  }

  kj::Promise<void> onSessionKeysChange(OnSessionKeysChangeContext context) override {
    KJ_DLOG(INFO, "onSessionKeysChange");

    auto session_id                = context.getParams().getSessionId();
    auto has_additional_usable_key = context.getParams().getHasAdditionalUsableKey();

    auto keys_info = kj::heapArray<cdm::KeyInformation>(context.getParams().getKeysInfo().size());
    for (uint32_t i = 0; i < keys_info.size(); i++) {
      keys_info[i].key_id      = context.getParams().getKeysInfo()[i].getKeyId().begin();
      keys_info[i].key_id_size = context.getParams().getKeysInfo()[i].getKeyId().size();
      keys_info[i].status      = static_cast<cdm::KeyStatus>(context.getParams().getKeysInfo()[i].getStatus());
      keys_info[i].system_code = context.getParams().getKeysInfo()[i].getSystemCode();
    }

    m_host->OnSessionKeysChange(session_id.begin(), session_id.size(), has_additional_usable_key, keys_info.begin(), keys_info.size());

    KJ_DLOG(INFO, "exiting onSessionKeysChange");
    return kj::READY_NOW;
  }

  kj::Promise<void> onExpirationChange(OnExpirationChangeContext context) override {
    KJ_DLOG(INFO, "onExpirationChange");
    auto session_id      = context.getParams().getSessionId();
    auto new_expiry_time = context.getParams().getNewExpiryTime();
    m_host->OnExpirationChange(session_id.begin(), session_id.size(), new_expiry_time);
    KJ_DLOG(INFO, "exiting onExpirationChange");
    return kj::READY_NOW;
  }

  kj::Promise<void> onSessionClosed(OnSessionClosedContext context) override {
    KJ_DLOG(INFO, "onSessionClosed");
    auto session_id = context.getParams().getSessionId();
    m_host->OnSessionClosed(session_id.begin(), session_id.size());
    KJ_DLOG(INFO, "exiting onSessionClosed");
    return kj::READY_NOW;
  }

  kj::Promise<void> queryOutputProtectionStatus(QueryOutputProtectionStatusContext context) override {
    KJ_DLOG(INFO, "queryOutputProtectionStatus");
    m_host->QueryOutputProtectionStatus();
    KJ_DLOG(INFO, "exiting queryOutputProtectionStatus");
    return kj::READY_NOW;
  }

  //TODO: who is supposed to dispose of the FileIO object?
  kj::Promise<void> createFileIO(CreateFileIOContext context) override {
    KJ_DLOG(INFO, "createFileIO");
    auto file_io_client = context.getParams().getClient();
    auto file_io = m_host->CreateFileIO(new FileIOClientWrapper(kj::mv(file_io_client)));
    if (file_io != nullptr) {
      context.getResults().setFileIO(kj::heap<FileIOProxyImpl>(file_io));
    }
    KJ_DLOG(INFO, "exiting createFileIO");
    return kj::READY_NOW;
  }

  kj::Promise<void> requestStorageId(RequestStorageIdContext context) override {
    KJ_DLOG(INFO, "requestStorageId");
    auto version = context.getParams().getVersion();
    m_host->RequestStorageId(version);
    KJ_DLOG(INFO, "exiting requestStorageId");
    return kj::READY_NOW;
  }

  HostProxyImpl(cdm::Host_10* host) : m_host(host) {}
};

__attribute__((constructor))
static void init() {
  kj::TopLevelProcessContext context("");
  context.increaseLoggingVerbosity();
}

CDM_API void INITIALIZE_CDM_MODULE() {
  // do nothing
}

CDM_API void DeinitializeCdmModule() {
  // do nothing
}

static pid_t spawn_worker(int sockets[2]) {

  char* bindir_path = getenv("FCDM_BINDIR_PATH");
  if (bindir_path == nullptr) {
    KJ_LOG(FATAL, "FCDM_BINDIR_PATH is not set");
    return -1;
  }

  KJ_SYSCALL(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sockets));
  KJ_SYSCALL(fcntl(sockets[0], F_SETFD, FD_CLOEXEC));

  char socket_fd_str[11];
  snprintf(socket_fd_str, sizeof(socket_fd_str), "%d", sockets[1]);

  extern char** environ;

  pid_t pid = 0;

#ifndef DISABLE_FCDM_JAIL
  auto jail_wrapper_path = kj::str(bindir_path, "/fcdm-jail");
  auto worker_path       = kj::str(bindir_path, "/fcdm-worker");

  const char* const args[] = {
    "fcdm-jail",
    socket_fd_str,
    nullptr
  };

  KJ_SYSCALL(setenv("FCDM_WORKER_PATH", worker_path.cStr(), 1));

  int err = posix_spawn(&pid, jail_wrapper_path.cStr(), nullptr, nullptr, const_cast<char* const*>(args), environ);
  if (err == 0) {
    KJ_LOG(INFO, "started worker process", pid);
    return pid;
  } else {
    KJ_LOG(FATAL, "unable to start worker jail process", jail_wrapper_path, strerror(errno));
    KJ_SYSCALL(close(sockets[0]));
    KJ_SYSCALL(close(sockets[1]));
    return -1;
  }
#else
  auto worker_path = kj::str(bindir_path, "/fcdm-worker");

  const char* const args[] = {
    "fcdm-worker",
    socket_fd_str,
    nullptr
  };

  int err = posix_spawn(&pid, worker_path.cStr(), nullptr, nullptr, const_cast<char* const*>(args), environ);
  if (err == 0) {
    KJ_LOG(INFO, "started worker process", pid);
    return pid;
  } else {
    KJ_LOG(FATAL, "unable to start worker process", worker_path, strerror(errno));
    KJ_SYSCALL(close(sockets[0]));
    KJ_SYSCALL(close(sockets[1]));
    return -1;
  }
#endif
}

//TODO: is it safe to throw exceptions here?
CDM_API void* CreateCdmInstance(int cdm_interface_version, const char* key_system, uint32_t key_system_size, GetCdmHostFunc get_cdm_host_func, void* user_data) {

  KJ_DLOG(INFO, "CreateCdmInstance", cdm_interface_version, key_system, key_system_size, reinterpret_cast<void*>(get_cdm_host_func), user_data);

  int sockets[2];
  pid_t pid = spawn_worker(sockets);
  if (pid == -1) {
    return nullptr;
  }

  //TODO: who is supposed to close sockets[0]?
  KJ_SYSCALL(close(sockets[1]));

  auto stream = io.lowLevelProvider->wrapUnixSocketFd(sockets[0]);
  auto client = kj::heap<capnp::TwoPartyClient>(*stream, 1 /* maxFdsPerMessage */);
  auto worker = client.get()->bootstrap().castAs<CdmWorker>();

  auto host = reinterpret_cast<cdm::Host_10*>(get_cdm_host_func(cdm_interface_version, user_data));
  KJ_ASSERT(host != nullptr);

  auto request = worker.createCdmInstanceRequest();
  request.setCdmInterfaceVersion(cdm_interface_version);
  request.setKeySystem(kj::StringPtr(key_system, key_system_size));
  request.setHostProxy(kj::heap<HostProxyImpl>(host));

  auto response = request.send().wait(io.waitScope);

  auto cdm = response.getCdmProxy();

  int memfd = KJ_ASSERT_NONNULL(cdm.getFd().wait(io.waitScope));
  KJ_DEFER(KJ_SYSCALL(close(memfd)));

  XAlloc allocator(memfd, SHMEM_ARENA_SIZE, 0);

  long page_size;
  KJ_SYSCALL(page_size = sysconf(_SC_PAGESIZE));

  void* decrypted_buffers = mmap(nullptr, SHMEM_ARENA_SIZE, PROT_READ, MAP_SHARED, memfd, SHMEM_ARENA_SIZE + page_size);
  if (decrypted_buffers == MAP_FAILED) {
    KJ_FAIL_SYSCALL("mmap", errno);
  }

  return reinterpret_cast<void*>(new CdmWrapper(pid, io, kj::mv(stream), kj::mv(client), kj::mv(cdm), host, kj::mv(allocator), decrypted_buffers));
}

CDM_API const char* GetCdmVersion() {

  KJ_DLOG(INFO, "GetCdmVersion");

  static thread_local char* version = nullptr;
  if (version == nullptr) {

    int sockets[2];
    pid_t pid = spawn_worker(sockets);
    if (pid == -1) {
      return nullptr;
    }

    {
      KJ_DEFER(KJ_SYSCALL(close(sockets[0])));
      KJ_DEFER(KJ_SYSCALL(close(sockets[1])));

      auto stream = io.lowLevelProvider->wrapUnixSocketFd(sockets[0]);
      capnp::TwoPartyClient client(*stream, 1 /* maxFdsPerMessage */);

      auto worker   = client.bootstrap().castAs<CdmWorker>();
      auto request  = worker.getCdmVersionRequest();
      auto response = request.send().wait(io.waitScope);

      version = strdup(response.getVersion().cStr());
    }

    int status;
    KJ_SYSCALL(waitpid(pid, &status, 0));
  }

  KJ_LOG(INFO, version);

  return version;
}
