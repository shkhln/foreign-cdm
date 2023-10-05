#include <cerrno>
#include <cstdlib>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <kj/main.h>
#include <capnp/rpc-twoparty.h>
#include <cdm/content_decryption_module.h>
#include "cdm.capnp.h"
#include "config.h"
#include "util.h"

class XBuffer: public cdm::Buffer {

  uint8_t* m_data;
  uint32_t m_capacity;
  uint32_t m_size;

 public:

  void Destroy() override {
    delete this;
  }

  uint32_t Capacity() const override {
    return m_capacity;
  }

  uint8_t* Data() override {
    return m_data;
  }

  void SetSize(uint32_t size) override {
    KJ_ASSERT(size <= m_capacity);
    m_size = size;
  }

  uint32_t Size() const override {
    return m_size;
  }

  XBuffer(uint32_t capacity, void* data) :
    m_data(static_cast<uint8_t*>(data)), m_capacity(capacity), m_size(capacity) {}

  ~XBuffer() {}
};

class XDecryptedBlock: public cdm::DecryptedBlock {

  cdm::Buffer* m_buffer    = nullptr;
  int64_t      m_timestamp = 0;

public:
  void SetDecryptedBuffer(cdm::Buffer* buffer) override {
    m_buffer = buffer;
  }

  cdm::Buffer* DecryptedBuffer() override {
    return m_buffer;
  }

  void SetTimestamp(int64_t timestamp) override {
    m_timestamp = timestamp;
  }

  int64_t Timestamp() const override {
    return m_timestamp;
  }

  XDecryptedBlock() {}
  ~XDecryptedBlock() {}
};

class XVideoFrame: public cdm::VideoFrame {

  cdm::VideoFormat m_format         = cdm::kUnknownVideoFormat;
  cdm::Size        m_size           = cdm::Size { .width = 0, .height = 0 };
  cdm::Buffer*     m_frame_buffer   = nullptr;
  uint32_t         m_kYPlane_offset = 0;
  uint32_t         m_kUPlane_offset = 0;
  uint32_t         m_kVPlane_offset = 0;
  uint32_t         m_kYPlane_stride = 0;
  uint32_t         m_kUPlane_stride = 0;
  uint32_t         m_kVPlane_stride = 0;
  int64_t          m_timestamp      = 0;

public:
  void SetFormat(cdm::VideoFormat format) override {
    m_format = format;
  }

  cdm::VideoFormat Format() const override {
    return m_format;
  }

  void SetSize(cdm::Size size) override {
    m_size = size;
  }

  cdm::Size Size() const override {
    return m_size;
  }

  void SetFrameBuffer(cdm::Buffer* frame_buffer) override {
    m_frame_buffer = frame_buffer;
  }

  cdm::Buffer* FrameBuffer() override {
    return m_frame_buffer;
  }

  void SetPlaneOffset(cdm::VideoPlane plane, uint32_t offset) override {
    switch (plane) {
      case cdm::kYPlane: m_kYPlane_offset = offset; break;
      case cdm::kUPlane: m_kUPlane_offset = offset; break;
      case cdm::kVPlane: m_kVPlane_offset = offset; break;
      default:
        KJ_UNREACHABLE;
    }
  }

  uint32_t PlaneOffset(cdm::VideoPlane plane) override {
    switch (plane) {
      case cdm::kYPlane: return m_kYPlane_offset;
      case cdm::kUPlane: return m_kUPlane_offset;
      case cdm::kVPlane: return m_kVPlane_offset;
      default:
        KJ_UNREACHABLE;
    }
  }

  void SetStride(cdm::VideoPlane plane, uint32_t stride) override {
    switch (plane) {
      case cdm::kYPlane: m_kYPlane_stride = stride; break;
      case cdm::kUPlane: m_kUPlane_stride = stride; break;
      case cdm::kVPlane: m_kVPlane_stride = stride; break;
      default:
        KJ_UNREACHABLE;
    }
  };

  uint32_t Stride(cdm::VideoPlane plane) override {
    switch (plane) {
      case cdm::kYPlane: return m_kYPlane_stride;
      case cdm::kUPlane: return m_kUPlane_stride;
      case cdm::kVPlane: return m_kVPlane_stride;
      default:
        KJ_UNREACHABLE;
    }
  }

  void SetTimestamp(int64_t timestamp) override {
    m_timestamp = timestamp;
  }

  int64_t Timestamp() const {
    return m_timestamp;
  }

  XVideoFrame() {}
  ~XVideoFrame() {}
};

static cdm::InputBuffer_2* get_input_buffer_and_fix_pointers(uint8_t* shared_mem_start, uint32_t offset) {

  auto buffer = reinterpret_cast<cdm::InputBuffer_2*>(reinterpret_cast<uint8_t*>(shared_mem_start) + offset);

  buffer->data       = shared_mem_start + reinterpret_cast<uintptr_t>(buffer->data);
  buffer->key_id     = shared_mem_start + reinterpret_cast<uintptr_t>(buffer->key_id);
  buffer->iv         = shared_mem_start + reinterpret_cast<uintptr_t>(buffer->iv);
  buffer->subsamples = reinterpret_cast<cdm::SubsampleEntry*>(
    shared_mem_start + reinterpret_cast<uintptr_t>(buffer->subsamples));

  return buffer;
}

struct HostContext {
  kj::WaitScope* scope;
  XAlloc*        arena;
};

static thread_local struct HostContext host_ctx = HostContext { .scope = nullptr, .arena = nullptr };

static void set_host_context(kj::WaitScope* scope, XAlloc* arena) {
  KJ_ASSERT(host_ctx.scope == nullptr);
  KJ_ASSERT(host_ctx.arena == nullptr);
  host_ctx.scope = scope;
  host_ctx.arena = arena;
}

static void clear_host_context() {
  KJ_ASSERT(host_ctx.scope != nullptr);
  //~ KJ_ASSERT(host_ctx.arena != nullptr);
  host_ctx.scope = nullptr;
  host_ctx.arena = nullptr;
}

class CdmProxyImpl final: public CdmProxy::Server {

  cdm::ContentDecryptionModule_10* m_cdm;
  kj::AutoCloseFd m_memfd;
  XAlloc m_allocator;
  void* m_encrypted_buffers;

public:

  kj::Maybe<int> getFd() override {
    return m_memfd.get();
  }

  kj::Promise<void> initialize(InitializeContext context) override {
    return kj::startFiber(FIBER_STACK_SIZE, [context, this](kj::WaitScope& scope) mutable {
      KJ_DLOG(INFO, "initialize");
      set_host_context(&scope, &m_allocator);
      auto allow_distinctive_identifier = context.getParams().getAllowDistinctiveIdentifier();
      auto allow_persistent_state       = context.getParams().getAllowPersistentState();
      auto use_hw_secure_codecs         = context.getParams().getUseHwSecureCodecs();
      m_cdm->Initialize(allow_distinctive_identifier, allow_persistent_state, use_hw_secure_codecs);
      clear_host_context();
      KJ_DLOG(INFO, "exiting initialize");
    });
  }

  kj::Promise<void> setServerCertificate(SetServerCertificateContext context) override {
    return kj::startFiber(FIBER_STACK_SIZE, [context, this](kj::WaitScope& scope) mutable {
      KJ_DLOG(INFO, "setServerCertificate");
      set_host_context(&scope, &m_allocator);
      auto promise_id              = context.getParams().getPromiseId();
      auto server_certificate_data = context.getParams().getServerCertificateData();
      m_cdm->SetServerCertificate(promise_id, server_certificate_data.begin(), server_certificate_data.size());
      clear_host_context();
      KJ_DLOG(INFO, "exiting setServerCertificate");
    });
  }

  kj::Promise<void> createSessionAndGenerateRequest(CreateSessionAndGenerateRequestContext context) override {
    return kj::startFiber(FIBER_STACK_SIZE, [context, this](kj::WaitScope& scope) mutable {
      KJ_DLOG(INFO, "createSessionAndGenerateRequest");
      set_host_context(&scope, &m_allocator);
      auto promise_id     = context.getParams().getPromiseId();
      auto session_type   = context.getParams().getSessionType();
      auto init_data_type = context.getParams().getInitDataType();
      auto data           = context.getParams().getInitData();
      m_cdm->CreateSessionAndGenerateRequest(promise_id, static_cast<cdm::SessionType>(session_type), static_cast<cdm::InitDataType>(init_data_type), data.begin(), data.size());
      clear_host_context();
      KJ_DLOG(INFO, "exiting createSessionAndGenerateRequest");
    });
  }

  kj::Promise<void> updateSession(UpdateSessionContext context) override {
    return kj::startFiber(FIBER_STACK_SIZE, [context, this](kj::WaitScope& scope) mutable {
      KJ_DLOG(INFO, "updateSession");
      set_host_context(&scope, &m_allocator);
      auto promise_id = context.getParams().getPromiseId();
      auto session_id = context.getParams().getSessionId();
      auto response   = context.getParams().getResponse();
      m_cdm->UpdateSession(promise_id, session_id.begin(), session_id.size(), response.begin(), response.size());
      clear_host_context();
      KJ_DLOG(INFO, "exiting updateSession");
    });
  }

  kj::Promise<void> closeSession(CloseSessionContext context) override {
    return kj::startFiber(FIBER_STACK_SIZE, [context, this](kj::WaitScope& scope) mutable {
      KJ_DLOG(INFO, "closeSession");
      set_host_context(&scope, &m_allocator);
      auto promise_id = context.getParams().getPromiseId();
      auto session_id = context.getParams().getSessionId();
      m_cdm->CloseSession(promise_id, session_id.begin(), session_id.size());
      clear_host_context();
      KJ_DLOG(INFO, "exiting closeSession");
    });
  }

  kj::Promise<void> timerExpired(TimerExpiredContext context) override {
    return kj::startFiber(FIBER_STACK_SIZE, [context, this](kj::WaitScope& scope) mutable {
      KJ_DLOG(INFO, "timerExpired");
      set_host_context(&scope, &m_allocator);
      auto context_ = reinterpret_cast<void*>(context.getParams().getContext());
      m_cdm->TimerExpired(context_);
      clear_host_context();
      KJ_DLOG(INFO, "exiting timerExpired");
    });
  }

  kj::Promise<void> decrypt(DecryptContext context) override {
    return kj::startFiber(FIBER_STACK_SIZE, [context, this](kj::WaitScope& scope) mutable {
      KJ_DLOG(INFO, "decrypt");
      set_host_context(&scope, &m_allocator);

      auto encrypted_buffer = get_input_buffer_and_fix_pointers(
        reinterpret_cast<uint8_t*>(m_encrypted_buffers), context.getParams().getEncryptedBufferOffset());

      m_allocator.forget();

      XDecryptedBlock block;
      cdm::Status status = m_cdm->Decrypt(*encrypted_buffer, static_cast<cdm::DecryptedBlock*>(&block));

      if (status == cdm::kSuccess) {
        auto target = context.getResults().getDecryptedBuffer();
        target.getBuffer().setOffset(m_allocator.getOffset(block.DecryptedBuffer()->Data()));
        target.getBuffer().setSize(block.DecryptedBuffer()->Size());
        target.setTimestamp(block.Timestamp());
      }

      if (block.DecryptedBuffer() != nullptr) {
        block.DecryptedBuffer()->Destroy();
      }

      context.getResults().setStatus(status);

      clear_host_context();
      KJ_DLOG(INFO, "exiting decrypt");
    });
  }

  kj::Promise<void> initializeVideoDecoder(InitializeVideoDecoderContext context) override {
    return kj::startFiber(FIBER_STACK_SIZE, [context, this](kj::WaitScope& scope) mutable {
      KJ_DLOG(INFO, "initializeVideoDecoder");
      set_host_context(&scope, &m_allocator);
      cdm::VideoDecoderConfig_2 video_decoder_config;
      video_decoder_config.codec             = static_cast<cdm::VideoCodec>(context.getParams().getVideoDecoderConfig().getCodec());
      video_decoder_config.profile           = static_cast<cdm::VideoCodecProfile>(context.getParams().getVideoDecoderConfig().getProfile());
      video_decoder_config.format            = static_cast<cdm::VideoFormat>(context.getParams().getVideoDecoderConfig().getFormat());
      video_decoder_config.coded_size.width  = context.getParams().getVideoDecoderConfig().getCodedSize().getWidth();
      video_decoder_config.coded_size.height = context.getParams().getVideoDecoderConfig().getCodedSize().getHeight();
      auto extra_data                        = context.getParams().getVideoDecoderConfig().getExtraData();
      video_decoder_config.extra_data        = const_cast<uint8_t*>(extra_data.begin()); // somehow this field is non-const
      video_decoder_config.extra_data_size   = extra_data.size();
      video_decoder_config.encryption_scheme = static_cast<cdm::EncryptionScheme>(context.getParams().getVideoDecoderConfig().getEncryptionScheme());

      cdm::Status status = m_cdm->InitializeVideoDecoder(video_decoder_config);

      context.getResults().setStatus(status);
      clear_host_context();
      KJ_DLOG(INFO, "exiting initializeVideoDecoder");
    });
  }

  kj::Promise<void> deinitializeDecoder(DeinitializeDecoderContext context) override {
    return kj::startFiber(FIBER_STACK_SIZE, [context, this](kj::WaitScope& scope) mutable {
      KJ_DLOG(INFO, "deinitializeDecoder");
      set_host_context(&scope, &m_allocator);
      auto decoder_type = static_cast<cdm::StreamType>(context.getParams().getDecoderType());
      m_cdm->DeinitializeDecoder(decoder_type);
      clear_host_context();
      KJ_DLOG(INFO, "exiting deinitializeDecoder");
    });
  }

  kj::Promise<void> resetDecoder(ResetDecoderContext context) override {
    return kj::startFiber(FIBER_STACK_SIZE, [context, this](kj::WaitScope& scope) mutable {
      KJ_DLOG(INFO, "resetDecoder");
      set_host_context(&scope, &m_allocator);
      auto decoder_type = static_cast<cdm::StreamType>(context.getParams().getDecoderType());
      m_cdm->ResetDecoder(decoder_type);
      clear_host_context();
      KJ_DLOG(INFO, "exiting resetDecoder");
    });
  }

  kj::Promise<void> decryptAndDecodeFrame(DecryptAndDecodeFrameContext context) override {
    return kj::startFiber(FIBER_STACK_SIZE, [context, this](kj::WaitScope& scope) mutable {
      KJ_DLOG(INFO, "decryptAndDecodeFrame");
      set_host_context(&scope, &m_allocator);

      auto encrypted_buffer = get_input_buffer_and_fix_pointers(
        reinterpret_cast<uint8_t*>(m_encrypted_buffers), context.getParams().getEncryptedBufferOffset());

      m_allocator.forget();

      XVideoFrame frame;
      cdm::Status status = m_cdm->DecryptAndDecodeFrame(*encrypted_buffer, static_cast<cdm::VideoFrame*>(&frame));

      if (status == cdm::kSuccess) {
        auto target = context.getResults().getVideoFrame();
        target.setFormat(frame.Format());
        target.getSize().setWidth (frame.Size().width);
        target.getSize().setHeight(frame.Size().height);

        target.getFrameBuffer().setOffset(m_allocator.getOffset(frame.FrameBuffer()->Data()));
        target.getFrameBuffer().setSize(frame.FrameBuffer()->Size());

        target.setKYPlaneOffset(frame.PlaneOffset(cdm::kYPlane));
        target.setKUPlaneOffset(frame.PlaneOffset(cdm::kUPlane));
        target.setKVPlaneOffset(frame.PlaneOffset(cdm::kVPlane));
        target.setKYPlaneStride(frame.Stride(cdm::kYPlane));
        target.setKUPlaneStride(frame.Stride(cdm::kUPlane));
        target.setKVPlaneStride(frame.Stride(cdm::kVPlane));
        target.setTimestamp(frame.Timestamp());
      }

      if (frame.FrameBuffer() != nullptr) {
        frame.FrameBuffer()->Destroy();
      }

      context.getResults().setStatus(status);

      clear_host_context();
      KJ_DLOG(INFO, "exiting decryptAndDecodeFrame");
    });
  }

  kj::Promise<void> onQueryOutputProtectionStatus(OnQueryOutputProtectionStatusContext context) override {
    return kj::startFiber(FIBER_STACK_SIZE, [context, this](kj::WaitScope& scope) mutable {
      KJ_DLOG(INFO, "onQueryOutputProtectionStatus");
      set_host_context(&scope, &m_allocator);
      auto result                 = context.getParams().getResult();
      auto link_mask              = context.getParams().getLinkMask();
      auto output_protection_mask = context.getParams().getOutputProtectionMask();
      m_cdm->OnQueryOutputProtectionStatus(static_cast<cdm::QueryResult>(result), link_mask, output_protection_mask);
      clear_host_context();
      KJ_DLOG(INFO, "exiting onQueryOutputProtectionStatus");
    });
  }

  kj::Promise<void> onStorageId(OnStorageIdContext context) override {
    return kj::startFiber(FIBER_STACK_SIZE, [context, this](kj::WaitScope& scope) mutable {
      KJ_DLOG(INFO, "onStorageId");
      set_host_context(&scope, &m_allocator);
      auto version    = context.getParams().getVersion();
      auto storage_id = context.getParams().getStorageId();
      m_cdm->OnStorageId(version, storage_id.begin(), storage_id.size());
      clear_host_context();
      KJ_DLOG(INFO, "exiting onStorageId");
    });
  }

  CdmProxyImpl(cdm::ContentDecryptionModule_10* cdm, kj::AutoCloseFd memfd, XAlloc allocator, void* encrypted_buffers) :
    m_cdm(cdm), m_memfd(kj::mv(memfd)), m_allocator(kj::mv(allocator)), m_encrypted_buffers(encrypted_buffers) {}

  ~CdmProxyImpl() {}
};

class FileIOWrapper: public cdm::FileIO {

  FileIOProxy::Client m_file_io;

public:

  void Open(const char* file_name, uint32_t file_name_size) override {
    KJ_DLOG(INFO, "Open", file_name, file_name_size);
    auto request = m_file_io.openRequest();
    request.setFileName(kj::StringPtr(file_name, file_name_size));
    request.send().wait(*host_ctx.scope);
    KJ_DLOG(INFO, "exiting Open");
  }

  void Read() override {
    KJ_DLOG(INFO, "Read");
    auto request = m_file_io.readRequest();
    request.send().wait(*host_ctx.scope);
    KJ_DLOG(INFO, "exiting Read");
  }

  void Write(const uint8_t* data, uint32_t data_size) override {
    KJ_DLOG(INFO, "Write", data, data_size);
    auto request = m_file_io.writeRequest();
    request.setData(kj::arrayPtr(data, data_size));
    request.send().wait(*host_ctx.scope);
    KJ_DLOG(INFO, "exiting Write");
  }

  void Close() override {
    KJ_DLOG(INFO, "Close");
    auto request = m_file_io.closeRequest();
    request.send().wait(*host_ctx.scope);
    KJ_DLOG(INFO, "exiting Close");
  }

  FileIOWrapper(FileIOProxy::Client&& io) : m_file_io(io) {}

  ~FileIOWrapper() noexcept {
    KJ_ASSERT(0);
  }
};

class FileIOClientProxyImpl final: public FileIOClientProxy::Server {

  cdm::FileIOClient* m_client;

public:

  kj::Promise<void> onOpenComplete(OnOpenCompleteContext context) override {
    return kj::startFiber(FIBER_STACK_SIZE, [context, this](kj::WaitScope& scope) mutable {
      KJ_DLOG(INFO, "onOpenComplete");
      set_host_context(&scope, nullptr);
      auto status = context.getParams().getStatus();
      m_client->OnOpenComplete(static_cast<cdm::FileIOClient::Status>(status));
      clear_host_context();
      KJ_DLOG(INFO, "exiting onOpenComplete");
    });
  }

  kj::Promise<void> onReadComplete(OnReadCompleteContext context) override {
    return kj::startFiber(FIBER_STACK_SIZE, [context, this](kj::WaitScope& scope) mutable {
      KJ_DLOG(INFO, "onReadComplete");
      set_host_context(&scope, nullptr);
      auto status = context.getParams().getStatus();
      auto data   = context.getParams().getData();
      m_client->OnReadComplete(static_cast<cdm::FileIOClient::Status>(status), data.begin(), data.size());
      clear_host_context();
      KJ_DLOG(INFO, "exiting onReadComplete");
    });
  }

  kj::Promise<void> onWriteComplete(OnWriteCompleteContext context) override {
    return kj::startFiber(FIBER_STACK_SIZE, [context, this](kj::WaitScope& scope) mutable {
      KJ_DLOG(INFO, "onWriteComplete");
      set_host_context(&scope, nullptr);
      auto status = context.getParams().getStatus();
      m_client->OnWriteComplete(static_cast<cdm::FileIOClient::Status>(status));
      clear_host_context();
      KJ_DLOG(INFO, "exiting onWriteComplete");
    });
  }

  FileIOClientProxyImpl(cdm::FileIOClient* client) : m_client(client) {}
};

class HostWrapper: public cdm::Host_10 {

  HostProxy::Client m_host;

public:

  cdm::Buffer* Allocate(uint32_t capacity) override {
    return static_cast<cdm::Buffer*>(new XBuffer(capacity, host_ctx.arena->allocate(capacity)));
  }

  void SetTimer(int64_t delay_ms, void* context) override {
    KJ_DLOG(INFO, "SetTimer", delay_ms, context);
    auto request = m_host.setTimerRequest();
    request.setDelayMs(delay_ms);
    request.setContext(reinterpret_cast<uint64_t>(context));
    request.send().wait(*host_ctx.scope);
    KJ_DLOG(INFO, "exiting SetTimer");
  }

  cdm::Time GetCurrentWallTime() override {
    struct timeval tv;
    struct timezone tz = {0, 0};
    KJ_SYSCALL(gettimeofday(&tv, &tz));
    return static_cast<double>(tv.tv_sec) + tv.tv_usec / 1000000.0;
  }

  void OnInitialized(bool success) override {
    KJ_DLOG(INFO, "OnInitialized", success);
    auto request = m_host.onInitializedRequest();
    request.setSuccess(success);
    request.send().wait(*host_ctx.scope);
    KJ_DLOG(INFO, "exiting OnInitialized");
  }

  void OnResolveKeyStatusPromise(uint32_t promise_id, cdm::KeyStatus key_status) override {
    KJ_UNIMPLEMENTED("OnResolveKeyStatusPromise");
  }

  void OnResolveNewSessionPromise(uint32_t promise_id, const char* session_id, uint32_t session_id_size) override {
    KJ_DLOG(INFO, "OnResolveNewSessionPromise", promise_id, session_id, session_id_size);
    auto request = m_host.onResolveNewSessionPromiseRequest();
    request.setPromiseId(promise_id);
    request.setSessionId(kj::StringPtr(session_id, session_id_size));
    request.send().wait(*host_ctx.scope);
    KJ_DLOG(INFO, "exiting OnResolveNewSessionPromise");
  }

  void OnResolvePromise(uint32_t promise_id) override {
    KJ_DLOG(INFO, "OnResolvePromise", promise_id);
    auto request = m_host.onResolvePromiseRequest();
    request.setPromiseId(promise_id);
    request.send().wait(*host_ctx.scope);
    KJ_DLOG(INFO, "exiting OnResolvePromise");
  }

  void OnRejectPromise(uint32_t promise_id, cdm::Exception exception, uint32_t system_code, const char* error_message, uint32_t error_message_size) override {
    KJ_DLOG(INFO, "OnRejectPromise", promise_id, exception, system_code, error_message, error_message_size);
    auto request = m_host.onRejectPromiseRequest();
    request.setPromiseId(promise_id);
    request.setException(exception);
    request.setSystemCode(system_code);
    request.setErrorMessage(kj::StringPtr(error_message, error_message_size));
    request.send().wait(*host_ctx.scope);
    KJ_DLOG(INFO, "exiting OnRejectPromise");
  }

  void OnSessionMessage(const char* session_id, uint32_t session_id_size, cdm::MessageType message_type, const char* message, uint32_t message_size) override {
    KJ_DLOG(INFO, "OnSessionMessage", session_id, session_id_size, message_type, message, message_size);
    auto request = m_host.onSessionMessageRequest();
    request.setSessionId(kj::StringPtr(session_id, session_id_size));
    request.setMessageType(message_type);
    request.setMessage(kj::StringPtr(message, message_size));
    request.send().wait(*host_ctx.scope);
    KJ_DLOG(INFO, "exiting OnSessionMessage");
  }

  void OnSessionKeysChange(const char* session_id, uint32_t session_id_size, bool has_additional_usable_key, const cdm::KeyInformation* keys_info, uint32_t keys_info_count) override {
    KJ_DLOG(INFO, "OnSessionKeysChange", session_id, session_id_size, has_additional_usable_key, keys_info, keys_info_count);
    auto request = m_host.onSessionKeysChangeRequest();
    request.setSessionId(kj::StringPtr(session_id, session_id_size));
    request.setHasAdditionalUsableKey(has_additional_usable_key);
    auto keys_info_builder = request.initKeysInfo(keys_info_count);
    for (uint32_t i = 0; i < keys_info_count; i++) {
      keys_info_builder[i].setKeyId(kj::arrayPtr(keys_info[i].key_id, keys_info[i].key_id_size));
      keys_info_builder[i].setStatus(keys_info[i].status);
      keys_info_builder[i].setSystemCode(keys_info[i].system_code);
    }
    request.send().wait(*host_ctx.scope);
    KJ_DLOG(INFO, "exiting OnSessionKeysChange");
  }

  void OnExpirationChange(const char* session_id, uint32_t session_id_size, cdm::Time new_expiry_time) override {
    KJ_DLOG(INFO, "OnExpirationChange", session_id, session_id_size, new_expiry_time);
    auto request = m_host.onExpirationChangeRequest();
    request.setSessionId(kj::StringPtr(session_id, session_id_size));
    request.setNewExpiryTime(new_expiry_time);
    request.send().wait(*host_ctx.scope);
    KJ_DLOG(INFO, "exiting OnExpirationChange");
  }

  void OnSessionClosed(const char* session_id, uint32_t session_id_size) override {
    KJ_DLOG(INFO, "OnSessionClosed", session_id, session_id_size);
    auto request = m_host.onSessionClosedRequest();
    request.setSessionId(kj::StringPtr(session_id, session_id_size));
    request.send().wait(*host_ctx.scope);
    KJ_DLOG(INFO, "exiting OnSessionClosed");
  }

  void SendPlatformChallenge(const char* service_id, uint32_t service_id_size, const char* challenge, uint32_t challenge_size) override {
    KJ_UNIMPLEMENTED("SendPlatformChallenge");
  }

  void EnableOutputProtection(uint32_t desired_protection_mask) override {
    KJ_UNIMPLEMENTED("EnableOutputProtection");
  }

  void QueryOutputProtectionStatus() override {
    KJ_DLOG(INFO, "QueryOutputProtectionStatus");
    auto request = m_host.queryOutputProtectionStatusRequest();
    request.send().wait(*host_ctx.scope);
    KJ_DLOG(INFO, "exiting QueryOutputProtectionStatus");
  }

  void OnDeferredInitializationDone(cdm::StreamType stream_type, cdm::Status decoder_status) override {
    KJ_UNIMPLEMENTED("OnDeferredInitializationDone");
  }

  cdm::FileIO* CreateFileIO(cdm::FileIOClient* client) override {
    KJ_DLOG(INFO, "CreateFileIO");
    auto request = m_host.createFileIORequest();
    request.setClient(kj::heap<FileIOClientProxyImpl>(client));
    auto response = request.send().wait(*host_ctx.scope);
    auto file_io  = response.hasFileIO() ? new FileIOWrapper(response.getFileIO()) : nullptr;
    KJ_DLOG(INFO, "exiting CreateFileIO", file_io);
    return file_io;
  }

  void RequestStorageId(uint32_t version) override {
    KJ_DLOG(INFO, "RequestStorageId");
    auto request = m_host.requestStorageIdRequest();
    request.setVersion(version);
    auto response = request.send().wait(*host_ctx.scope);
    KJ_DLOG(INFO, "exiting RequestStorageId");
  }

  HostWrapper(HostProxy::Client&& host) : m_host(host) {}

  ~HostWrapper() noexcept {
    KJ_ASSERT(0);
  }
};

typedef void (*InitializeCdmModuleFunc)();
//~ typedef void (*DeinitializeCdmModuleFunc)();
typedef void* (*CreateCdmInstanceFunc)(int, const char*, uint32_t, GetCdmHostFunc, void*);
typedef const char* (*GetCdmVersionFunc)();

InitializeCdmModuleFunc   init_cdm_mod_func    = nullptr;
//~ DeinitializeCdmModuleFunc deinit_cdm_mod_func  = nullptr;
CreateCdmInstanceFunc     create_cdm_inst_func = nullptr;
GetCdmVersionFunc         get_cdm_ver_func     = nullptr;

static void* get_cdm_host(int host_interface_version, void* user_data) {
  KJ_DLOG(INFO, "get_cdm_host", host_interface_version, user_data);
  KJ_ASSERT(host_interface_version == 10);
  return user_data;
}

class CdmWorkerImpl final: public CdmWorker::Server {

  bool cdm_initialized = false;

public:

  kj::Promise<void> createCdmInstance(CreateCdmInstanceContext context) override {
    return kj::startFiber(FIBER_STACK_SIZE, [context, this](kj::WaitScope& scope) mutable {

      auto cdm_interface_version = context.getParams().getCdmInterfaceVersion();
      auto key_system            = context.getParams().getKeySystem();
      auto host_proxy            = context.getParams().getHostProxy();

      KJ_DLOG(INFO, "createCdmInstance", cdm_interface_version, key_system);
      KJ_ASSERT(cdm_interface_version == 10);

      if (!cdm_initialized) {
        KJ_LOG(INFO, "cdm version", get_cdm_ver_func());
        init_cdm_mod_func();
        cdm_initialized = true;
      }

      int fd;
      KJ_SYSCALL(fd = syscall(SYS_memfd_create, "decrypted buffers", 0));
      kj::AutoCloseFd memfd(fd);

      long page_size;
      KJ_SYSCALL(page_size = sysconf(_SC_PAGESIZE));
      // encrypted buffers + decrypted buffers + 1 page
      KJ_SYSCALL(ftruncate(memfd.get(), SHMEM_ARENA_SIZE * 2 + page_size));
      //TODO: seal memfd?

      void* encrypted_buffers = mmap(nullptr, SHMEM_ARENA_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, 0);
      if (encrypted_buffers == MAP_FAILED) {
        KJ_FAIL_SYSCALL("mmap", errno);
      }

      XAlloc allocator(memfd.get(), SHMEM_ARENA_SIZE, SHMEM_ARENA_SIZE + page_size);

      //TODO: somebody is supposed to dispose of the host object
      void* host = reinterpret_cast<void*>(new HostWrapper(kj::mv(host_proxy)));

      set_host_context(&scope, &allocator);
      void* cdm  = create_cdm_inst_func(cdm_interface_version, key_system.begin(), key_system.size(), get_cdm_host, host);
      clear_host_context();
      KJ_ASSERT(cdm != nullptr);

      context.getResults().setCdmProxy(kj::heap<CdmProxyImpl>(reinterpret_cast<cdm::ContentDecryptionModule_10*>(cdm), kj::mv(memfd), kj::mv(allocator), encrypted_buffers));

      KJ_DLOG(INFO, "exiting createCdmInstance");
    });
  }

  kj::Promise<void> getCdmVersion(GetCdmVersionContext context) override {
    context.getResults().setVersion(get_cdm_ver_func());
    return kj::READY_NOW;
  }
};

#define X_STR_(x) #x
#define X_STR(x) X_STR_(x)

int main(int argc, char* argv[]) {

  kj::TopLevelProcessContext context(argv[0]);
  context.increaseLoggingVerbosity();

  char* cdm_path = getenv("FCDM_CDM_SO_PATH");
  if (cdm_path == nullptr) {
    KJ_LOG(FATAL, "FCDM_CDM_SO_PATH is not set");
    exit(EXIT_FAILURE);
  }

  void* cdm = dlopen(cdm_path, RTLD_LAZY);
  KJ_ASSERT(cdm != nullptr);

  init_cdm_mod_func = (InitializeCdmModuleFunc)dlsym(cdm, X_STR(INITIALIZE_CDM_MODULE));
  KJ_ASSERT(init_cdm_mod_func != nullptr);

  //~ deinit_cdm_mod_func = (DeinitializeCdmModuleFunc)dlsym(cdm, "DeinitializeCdmModule");
  //~ KJ_ASSERT(deinit_cdm_mod_func != nullptr);

  create_cdm_inst_func = (CreateCdmInstanceFunc)dlsym(cdm, "CreateCdmInstance");
  KJ_ASSERT(create_cdm_inst_func != nullptr);

  get_cdm_ver_func = (GetCdmVersionFunc)dlsym(cdm, "GetCdmVersion");
  KJ_ASSERT(get_cdm_ver_func != nullptr);

  KJ_LOG(INFO, "started");

  if (argc != 2) {
    KJ_LOG(FATAL, "wrong number of args");
    exit(EXIT_FAILURE);
  }

  errno = 0;
  intmax_t socket_fd = strtoimax(argv[1], nullptr, 10);
  KJ_ASSERT(errno != ERANGE && errno != EINVAL);

  auto io = kj::setupAsyncIo();
  capnp::TwoPartyServer server(kj::heap<CdmWorkerImpl>());
  server.accept(io.lowLevelProvider->wrapUnixSocketFd(socket_fd), 1 /* maxFdsPerMessage */);

  class ErrorHandlerImpl: public kj::TaskSet::ErrorHandler {
  public:
    void taskFailed(kj::Exception&& exception) override {
      KJ_LOG(FATAL, exception);
      exit(EXIT_FAILURE);
    }
  };

  ErrorHandlerImpl error_handler;
  kj::TaskSet tasks(error_handler);

  tasks.add(server.drain().then([]() -> void {
    KJ_LOG(INFO, "exiting...");
    exit(EXIT_SUCCESS);
  }));

  kj::NEVER_DONE.wait(io.waitScope);
  return 0;
}
