#include "MemoryReader.hh"

#include <signal.h>
#include <stdint.h>
#include <sys/mman.h>

#include <filesystem>
#include <map>
#include <memory>
#include <phosg/Filesystem.hh>
#include <phosg/Strings.hh>
#include <phosg/Tools.hh>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <mach/vm_region.h>
#include <unistd.h>
#endif

ProcessPauseGuard::ProcessPauseGuard(uint64_t pid) : pid(pid) {
#ifdef __APPLE__
  kern_return_t kr = task_for_pid(mach_task_self(), this->pid, &this->task);
  if (kr != KERN_SUCCESS) {
    throw std::runtime_error(std::format("task_for_pid failed: {} (are you running as root?)", mach_error_string(kr)));
  }
  kr = task_suspend(this->task);
  if (kr != KERN_SUCCESS) {
    throw std::runtime_error(std::format("task_suspend failed: {}", mach_error_string(kr)));
  }
  // Sleep for 10ms to avoid macOS High Sierra kernel bug
  usleep(10000);
#else
  kill(this->pid, SIGSTOP);
#endif
}

ProcessPauseGuard::~ProcessPauseGuard() {
#ifdef __APPLE__
  if (this->task != MACH_PORT_NULL) {
    task_resume(this->task);
    mach_port_deallocate(mach_task_self(), this->task);
  }
#else
  kill(this->pid, SIGCONT);
#endif
}

MemoryMappedFile::MemoryMappedFile(int fd, uint64_t offset, size_t size, bool writable)
    : filename(std::format("<fd {}>", fd)),
      map_offset(offset),
      all_data(nullptr),
      total_size(size) {
  if (this->total_size == 0) {
    this->all_data = nullptr;
  } else {
    this->all_data = mmap(
        nullptr, this->total_size, PROT_READ | (writable ? PROT_WRITE : 0), MAP_SHARED, fd, this->map_offset);
    if (this->all_data == MAP_FAILED) {
      this->all_data = nullptr;
      throw std::runtime_error(std::format("Cannot map {} (0x{:X} bytes at offset 0x{:X}) into memory",
          this->filename, this->total_size, this->map_offset));
    }
  }
}

MemoryMappedFile::MemoryMappedFile(const std::string& filename, bool writable)
    : filename(filename),
      map_offset(0),
      all_data(nullptr),
      total_size(0) {
  phosg::scoped_fd fd(filename, writable ? O_RDWR : O_RDONLY);
  this->total_size = fstat(fd).st_size;
  if (this->total_size == 0) {
    this->all_data = nullptr;
  } else {
    this->all_data = mmap(nullptr, this->total_size, PROT_READ | (writable ? PROT_WRITE : 0), MAP_SHARED, fd, 0);
    if (this->all_data == MAP_FAILED) {
      this->all_data = nullptr;
      throw std::runtime_error(std::format("Cannot map {} ({:X} bytes at offset 0x{:X}) into memory",
          this->filename, this->total_size, this->map_offset));
    }
  }
}

MemoryMappedFile::MemoryMappedFile(MemoryMappedFile&& other) {
  *this = std::move(other);
}

MemoryMappedFile& MemoryMappedFile::operator=(MemoryMappedFile&& other) {
  this->filename = std::move(other.filename);
  this->map_offset = other.map_offset;
  this->all_data = other.all_data;
  this->total_size = other.total_size;
  other.all_data = nullptr;
  return *this;
}

MemoryMappedFile::~MemoryMappedFile() {
  if (this->all_data != nullptr) {
    munmap(this->all_data, this->total_size);
  }
}

MemoryReader::MemoryReader(const std::string& data_path) : total_bytes(0) {
  if (std::filesystem::is_directory(data_path)) {
    // Expect filenames of the form mem.START_ADDRESS.END_ADDRESS.bin
    for (const auto& item : std::filesystem::directory_iterator(data_path)) {
      std::string filename = item.path().filename().string();
      auto filename_tokens = phosg::split(filename, '.');
      if (filename_tokens.size() != 4 || filename_tokens[0] != "mem" || filename_tokens[3] != "bin") {
        continue;
      }
      MappedPtr<void> start{std::stoull(filename_tokens[1], nullptr, 16)};
      auto region_f = std::make_shared<MemoryMappedFile>(std::format("{}/{}", data_path, filename));
      this->mapped_files.emplace(region_f);
      if (region_f->total_size > 0) {
        auto view = region_f->view(start, 0, region_f->total_size);
        this->regions_by_mapped.emplace(view.addr, view);
        this->regions_by_host.emplace(view.data, view);
        this->total_bytes += region_f->total_size;
      }
    }

  } else {
    // Expect a single file with all memory regions contained in it; the format is:
    // struct {
    //   MappedPtr<void> start_address;
    //   MappedPtr<void> end_address;
    //   uint8_t region_data[end_address - start_address];
    // } region_addrs[...EOF];
    auto f = make_shared<MemoryMappedFile>(data_path);
    this->mapped_files.emplace(f);
    auto r = f->read();
    while (!r.eof()) {
      MappedPtr<void> start{r.get_u64l()};
      MappedPtr<void> end{r.get_u64l()};
      size_t region_size = start.bytes_until(end);
      auto view = f->view(start, r.where(), region_size);
      r.getv(region_size);
      this->regions_by_mapped.emplace(view.addr, view);
      this->regions_by_host.emplace(view.data, view);
      this->total_bytes += region_size;
    }
  }
}

bool MemoryReader::exists(MappedPtr<void> addr) const {
  try {
    this->find_region_by_mapped_addr(addr);
    return true;
  } catch (const std::out_of_range&) {
    return false;
  }
}

bool MemoryReader::exists_range(MappedPtr<void> addr, size_t size) const {
  try {
    const auto& rgn = this->find_region_by_mapped_addr(addr);
    return (rgn.addr.bytes_until(addr.offset_bytes(size)) <= rgn.size);
  } catch (const std::out_of_range&) {
    return false;
  }
}

phosg::StringReader MemoryReader::read(MappedPtr<void> addr, size_t size) const {
  const auto& rgn = this->find_region_by_mapped_addr(addr);
  uint64_t offset = rgn.addr.bytes_until(addr);
  if ((offset + size > rgn.size) || (offset + size < offset)) {
    throw std::out_of_range("Read size extends beyond end of region");
  }
  return phosg::StringReader(static_cast<const uint8_t*>(rgn.data) + offset, size);
}

phosg::StringReader MemoryReader::read_to_end(MappedPtr<void> addr) const {
  const auto& rgn = this->find_region_by_mapped_addr(addr);
  uint64_t offset = rgn.addr.bytes_until(addr);
  if (offset > rgn.size) {
    throw std::out_of_range("Read begins beyond end of region");
  }
  return phosg::StringReader(static_cast<const uint8_t*>(rgn.data) + offset, rgn.size - offset);
}

std::pair<MappedPtr<void>, size_t> MemoryReader::region_for_address(MappedPtr<void> addr) const {
  const auto& rgn = this->find_region_by_mapped_addr(addr);
  return std::make_pair(rgn.addr, rgn.size);
}

std::vector<std::pair<MappedPtr<void>, size_t>> MemoryReader::all_regions() const {
  std::vector<std::pair<MappedPtr<void>, size_t>> ret;
  for (const auto& it : this->regions_by_mapped) {
    ret.emplace_back(std::make_pair(it.second.addr, it.second.size));
  }
  return ret;
}

std::vector<std::pair<MappedPtr<void>, size_t>> MemoryReader::ranges_for_pid(uint64_t pid) {
  std::vector<std::pair<MappedPtr<void>, size_t>> ranges;
#ifdef __APPLE__
  mach_port_t task;
  kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
  if (kr != KERN_SUCCESS) {
    throw std::runtime_error(std::format("task_for_pid failed: {} (are you running as root?)", mach_error_string(kr)));
  }

  mach_vm_address_t address = 1;
  mach_vm_size_t size = 0;
  vm_region_extended_info_data_t info;
  mach_msg_type_number_t info_count = VM_REGION_EXTENDED_INFO_COUNT;
  mach_port_t object_name;

  while (true) {
    info_count = VM_REGION_EXTENDED_INFO_COUNT;
    kr = mach_vm_region(task, &address, &size, VM_REGION_EXTENDED_INFO,
        (vm_region_info_t)&info, &info_count, &object_name);
    if (kr != KERN_SUCCESS) {
      break; // No more regions
    }

    // Only include readable, non-shared regions (equivalent to Linux's filtering)
    // SM_SHARED and SM_TRUESHARED are excluded, similar to Linux's 's' flag
    if ((info.protection & VM_PROT_READ) &&
        (info.share_mode != SM_SHARED) &&
        (info.share_mode != SM_TRUESHARED)) {
      ranges.emplace_back(std::make_pair(MappedPtr<void>{address}, size));
    }

    // Move to next region
    address += size;
  }

  mach_port_deallocate(mach_task_self(), task);
#else
  auto maps_f = phosg::fopen_unique(std::format("/proc/{}/maps", pid), "rt");
  for (const auto& line : phosg::split(phosg::read_all(maps_f.get()), '\n')) {
    if (line.empty()) {
      continue;
    }
    auto tokens = phosg::split(line, ' ');
    if (tokens.at(1).at(0) != 'r') {
      continue; // Skip non-readable memory
    }
    if (tokens.at(1).at(3) == 's') {
      continue; // Skip shared-memory objects (e.g. Plasma store in Ray tasks)
    }
    auto addr_tokens = phosg::split(tokens.at(0), '-');
    MappedPtr<void> start{std::stoull(addr_tokens.at(0), nullptr, 16)};
    MappedPtr<void> end{std::stoull(addr_tokens.at(1), nullptr, 16)};
    ranges.emplace_back(std::make_pair(start, start.bytes_until(end)));
  }
#endif
  return ranges;
}

void MemoryReader::dump(uint64_t pid, const std::string& directory, size_t max_threads) {
  if (!std::filesystem::is_directory(directory)) {
    mkdir(directory.c_str(), 0755);
  }

  ProcessPauseGuard g(pid);
  std::vector<std::pair<MappedPtr<void>, size_t>> ranges = MemoryReader::ranges_for_pid(pid);

  size_t total_size = 0;
  for (const auto& [addr, size] : ranges) {
    total_size += size;
  }

  auto total_size_str = phosg::format_size(total_size);
#ifdef __APPLE__
  mach_port_t task;
  kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
  if (kr != KERN_SUCCESS) {
    throw std::runtime_error(std::format("task_for_pid failed: {} (are you running as root?)", mach_error_string(kr)));
  }

  phosg::parallel_range<uint64_t>([&](uint64_t range_index, size_t) -> bool {
    const auto& [addr, size] = ranges[range_index];

    auto out_f = phosg::fopen_unique(std::format("{}/mem.{}.{}.bin", directory, addr, addr.offset_bytes(size)), "wb");

    auto end = addr.offset_bytes(size);
    for (auto read_addr = addr; read_addr < end;) {
      size_t bytes_to_read = std::min<size_t>(read_addr.bytes_until(end), 1024 * 1024);
      try {
        vm_offset_t data_ptr = 0;
        mach_msg_type_number_t data_size = bytes_to_read;
        kr = mach_vm_read(task, read_addr.addr, bytes_to_read, &data_ptr, &data_size);
        if (kr != KERN_SUCCESS) {
          break;
        }
        phosg::fwritex(out_f.get(), reinterpret_cast<const void*>(data_ptr), data_size);
        vm_deallocate(mach_task_self(), data_ptr, data_size);
        read_addr.addr += data_size;
      } catch (const std::exception& e) {
        break;
      }
    }
    phosg::fwrite_fmt(stderr, "... {}:{}\n", addr, end);
    return false;
  },
      0, ranges.size(), max_threads, nullptr);

  mach_port_deallocate(mach_task_self(), task);
#else
  phosg::scoped_fd mem_fd(std::format("/proc/{}/mem", pid), O_RDONLY);
  phosg::parallel_range<uint64_t>([&](uint64_t range_index, size_t) -> bool {
    const auto& [addr, size] = ranges[range_index];

    auto out_f = phosg::fopen_unique(std::format("{}/mem.{}.{}.bin", directory, addr, addr.offset_bytes(size)), "wb");

    auto end = addr.offset_bytes(size);
    for (auto read_addr = addr; read_addr < end;) {
      size_t bytes_to_read = std::min<size_t>(read_addr.bytes_until(end), 1024 * 1024);
      try {
        std::string data = preadx(mem_fd, bytes_to_read, read_addr.addr);
        phosg::fwritex(out_f.get(), data);
        read_addr.addr += data.size();
      } catch (const std::exception& e) {
        break;
      }
    }
    phosg::fwrite_fmt(stderr, "... {}:{}\n", addr, end);
    return false;
  },
      0, ranges.size(), max_threads, nullptr);
#endif

  phosg::fwrite_fmt(stderr, "{} in {} ranges\n", total_size_str, ranges.size());
}

const MemoryMappedFile::View& MemoryReader::find_region_by_mapped_addr(MappedPtr<void> addr) const {
  auto it = this->regions_by_mapped.upper_bound(addr);
  if (it == this->regions_by_mapped.begin()) {
    throw std::out_of_range("Address not within any block");
  }
  it--;
  if (it->second.addr.offset_bytes(it->second.size) <= addr) {
    throw std::out_of_range("Address not within any block");
  }
  return it->second;
}

const MemoryMappedFile::View& MemoryReader::find_region_by_host_addr(const void* addr) const {
  auto it = this->regions_by_host.upper_bound(addr);
  if (it == this->regions_by_host.begin()) {
    throw std::out_of_range("Address not within any block");
  }
  it--;
  static_assert(sizeof(uint64_t) == sizeof(const void*), "python-memtools is designed only for 64-bit systems");
  if (reinterpret_cast<uint64_t>(addr) >= reinterpret_cast<uint64_t>(it->second.data) + it->second.size) {
    throw std::out_of_range("Address not within any block");
  }
  return it->second;
}
