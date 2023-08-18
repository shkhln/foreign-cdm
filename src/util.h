#include <sys/mman.h>
#include <kj/common.h>

class XAlloc {

  uint8_t* m_arena_start;
  uint32_t m_arena_size;
  uint8_t* m_position;

public:

  uint8_t* allocate(uint32_t nbytes) {
    auto cur_pos = m_position;
    auto new_pos = m_position + ((nbytes + 7) & ~7);
    KJ_ASSERT(new_pos < m_arena_start + m_arena_size, "out of mem");
    m_position = new_pos;
    return cur_pos;
  }

  uint32_t getOffset(uint8_t* position) {
    KJ_ASSERT(position >= m_arena_start && position < m_arena_start + m_arena_size, "out of bounds");
    return reinterpret_cast<uintptr_t>(position) - reinterpret_cast<uintptr_t>(m_arena_start);
  }

  void forget() {
    m_position = m_arena_start;
  }

  XAlloc(int fd, uint32_t arena_size, uint32_t offset) {
    void* p = mmap(nullptr, arena_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);
    if (p == MAP_FAILED) {
      KJ_FAIL_SYSCALL("mmap", errno);
    }
    m_arena_start = reinterpret_cast<uint8_t*>(p);
    m_arena_size  = arena_size;
    m_position    = m_arena_start;
  }

  ~XAlloc() {
    if (m_arena_start != nullptr) {
      KJ_SYSCALL(munmap(m_arena_start, m_arena_size));
    }
  }

  XAlloc(XAlloc&& other) :
    m_arena_start(other.m_arena_start),
    m_arena_size (other.m_arena_size),
    m_position   (other.m_position)
  {
    other.m_arena_start = nullptr;
    other.m_arena_size  = 0;
  }

  KJ_DISALLOW_COPY(XAlloc);
};
