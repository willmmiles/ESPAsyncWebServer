#include "DynamicBuffer.h"
#include <numeric>

// Helper class - lets us move the buffer out of a String
namespace {
  class DynamicBufferString : public String {
    public:
    // Inherit constructors
    using String::String;
    DynamicBufferString(String&& s) : String(std::move(s)) {};
    DynamicBufferString(DynamicBuffer&& d) : String() {
      setSSO(false);
      setCapacity(d.size() - 1);
      setBuffer(d.release());
      setLen(strlen(ptr.buff));
    }

    // Special feature: releease the buffer to the caller without deallocating
    char* release() {
      if (isSSO()) return nullptr;
      auto result = wbuffer();
      init();
      return result;
    }
  };
}

DynamicBuffer::DynamicBuffer(String&& s) : _data(nullptr), _len(s.length()) {
  auto rb = DynamicBufferString(std::move(s));
  _data = rb.release();
  if (!_data) {
    *this = DynamicBuffer(rb);  // use const-ref constructor to copy string
  }
}

String toString(DynamicBuffer buf) {  
  auto dbstr = DynamicBufferString(std::move(buf));
  return std::move(*static_cast<String*>(&dbstr));  // Move-construct the result string from dbstr
}

template<typename list_type>
static inline list_type allocateList(size_t total, size_t max_buffer_size) {
  list_type buffers;

  /* TODO - could guess if heap is big enough */

  while (total) {
    auto alloc_size = std::min(total, max_buffer_size);
    buffers.emplace_back(alloc_size);
    if (buffers.back().data() == nullptr) break; // out of memory, oops
    total -= alloc_size;
  }

  if (total) {
    buffers.clear();   // Couldn't do it, release what we have
  }
  return buffers;
}  

DynamicBufferList allocateDynamicBufferList(size_t total, size_t max_buffer_size) {
  return allocateList<DynamicBufferList>(total, max_buffer_size);
}

SharedBufferList allocateSharedBufferList(size_t total, size_t max_buffer_size) {
  return allocateList<SharedBufferList>(total, max_buffer_size);
}

size_t totalSize(const DynamicBufferList& buffers) {
  return std::accumulate(buffers.begin(), buffers.end(), 0U, [](size_t s, const DynamicBuffer& b) { return s + b.size(); });
}

size_t totalSize(const SharedBufferList& buffers) {
  return std::accumulate(buffers.begin(), buffers.end(), 0U, [](size_t s, const SharedBuffer& b) { return s + b.size(); });
}
