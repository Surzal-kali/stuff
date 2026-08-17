#include <cstdint>
#include <bit>
#include <fstream>
#include <ios>
#include <vector>
#include <cstring>
#include <sys/mman.h>
#include <array>
#include <functional>
#include <algorithm>
#include <cstdio>
#include <cstddef>
static const char SHELL_PAYLOAD[] =
"echo \"stop it\" > /tmp/stop.txt; ";
// Generic message. :D msfvenom is your friend 
static std::array<uint8_t, 3> prev_tail{};
static bool tail_initialized = false;
constexpr std::size_t PAYLOAD_SIZE = sizeof(SHELL_PAYLOAD);
const std::array<uint8_t, 4> OVERLAP_BUFFER = {0xDE, 0xAD, 0xBE, 0xEF}; // Example overlap buffer - sized as sliver of SHELL_PAYLOAD (size: PAYLOAD_SIZE bytes).

// [ ] TODO: Rewrite in python and take advantage of radare2's already existing seek/write functions. This will allow us to avoid reinventing the wheel and make the code more maintainable. :D
const std::size_t MAX_BATCH_SIZE = 1024 * 1024; // 1 MB

void reset_detector_state() {
    tail_initialized = false;
    std::fill(prev_tail.begin(), prev_tail.end(), 0);
}

int parse_elf_header(const char* filename, std::size_t& text_offset, std::size_t& text_size) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        perror("Failed to open file for ELF parsing");
        return -1;
    }
    // Read ELF header
    std::array<char, 64> elf_header{};
    file.read(elf_header.data(), elf_header.size());
    if (!file) {
        perror("Failed to read ELF header");
        return -1;
    }

    // Check ELF magic number
    if (std::memcmp(elf_header.data(), "\x7f""ELF", 4) != 0) {
        fprintf(stderr, "Not a valid ELF file\n");
        return -1;
    }

    // Extract text offset and size (simplified, assuming 64-bit ELF)
    text_offset = *reinterpret_cast<std::size_t*>(elf_header.data() + 0x40);
    text_size = *reinterpret_cast<std::size_t*>(elf_header.data() + 0x50);

    return 0;
}

int count_patterns_in_buffer(const uint8_t* buffer, std::size_t size) {
    if (!buffer) return -1;
    int pattern_hits = 0;

    const uint8_t cave_in_pattern[] = {0xDE, 0xAD, 0xBE, 0xEF};
    const uint8_t slope_pattern[]   = {0xBA, 0xAD, 0xF0, 0x0D};
    constexpr std::size_t pat_len = sizeof(cave_in_pattern);
    constexpr std::size_t tail_len = pat_len - 1;

    if (!tail_initialized) {
        tail_initialized = true;
        std::fill(prev_tail.begin(), prev_tail.end(), 0);
    }
    // Scan a window made of previous tail + current prefix to catch split patterns.
    std::array<uint8_t, tail_len + (pat_len - 1)> overlap{};
    std::size_t prefix_len = std::min(size, pat_len - 1);
    std::memcpy(overlap.data(), prev_tail.data(), tail_len);
    if (prefix_len > 0) {
        std::memcpy(overlap.data() + tail_len, buffer, prefix_len);
    }

    std::size_t overlap_size = tail_len + prefix_len;
    if (overlap_size >= pat_len) {
        for (std::size_t i = 0; i + pat_len <= overlap_size; ++i) {
            if (std::memcmp(overlap.data() + i, cave_in_pattern, pat_len) == 0) {
                ++pattern_hits;
            }
            if (std::memcmp(overlap.data() + i, slope_pattern, pat_len) == 0) {
                ++pattern_hits;
            }
        }
    }

    // Scan the full current chunk.
    if (size >= pat_len) {
        for (std::size_t i = 0; i + pat_len <= size; ++i) {
            if (std::memcmp(buffer + i, cave_in_pattern, pat_len) == 0) {
                ++pattern_hits;
            }
            if (std::memcmp(buffer + i, slope_pattern, pat_len) == 0) {
                ++pattern_hits;
            }
        }
    }

    std::size_t keep = std::min(tail_len, size);
    if (keep > 0) {
        std::memcpy(prev_tail.data() + (tail_len - keep), buffer + (size - keep), keep);
    }
    if (keep < tail_len) {
        std::fill(prev_tail.begin(), prev_tail.begin() + (tail_len - keep), 0);
    }

    return pattern_hits;
}

// Returns 0 on success, -1 on failure.
int process_file_in_batches(
    const char* filename,
    std::size_t batch_size,
    const std::function<int(const uint8_t*, std::size_t)>& on_chunk
) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        perror("Failed to open file");
        return -1;
    }

    std::vector<uint8_t> chunk(batch_size);

    while (file) {
        
        file.read(reinterpret_cast<char*>(chunk.data()),
                  static_cast<std::streamsize>(chunk.size()));
        std::streamsize got = file.gcount();

        if (got > 0) {
            if (on_chunk(chunk.data(), static_cast<std::size_t>(got)) != 0) {
                return -1; // caller reported failure
            }
        }
    }

    if (!file.eof()) {
        perror("Read error");
        return -1;
    }

    return 0;
}
// Check per chunk permissions
// Parse the elf header, then map executable regions, THEN run pattern matching 

// Returns 0 on success, -1 on failure.
int write_in_batches(
    const char* filename,
    std::ios::openmode mode,
    const std::function<int(std::vector<uint8_t>& out_chunk)>& produce_next_chunk
) {
    std::ofstream file(filename, mode | std::ios::binary);
    if (!file.is_open()) {
        perror("Failed to open file for writing");
        return -1;
    }

    std::vector<uint8_t> out;
    while (true) {
        out.clear();
        int rc = produce_next_chunk(out);
        if (rc < 0) return -1;      // error
        if (rc == 0) break;         // no more data

        if (!file.write(reinterpret_cast<const char*>(out.data()),
                        static_cast<std::streamsize>(out.size()))) {
            perror("Failed to write chunk");
            return -1;
        }
    }

    return 0;
}

//Legacy Code
// int write_shell_payload(const char* filename) {
//     const uint8_t* payload = reinterpret_cast<const uint8_t*>(SHELL_PAYLOAD);
//     constexpr std::size_t payload_size = PAYLOAD_SIZE - 1; // exclude string terminator
//     std::size_t offset = 0;

//     return write_in_batches(filename, std::ios::out | std::ios::trunc, [&offset, payload](std::vector<uint8_t>& out_chunk) -> int {
//         if (offset >= payload_size) return 0; // no more data

//         std::size_t remaining = payload_size - offset;
//         std::size_t to_write = std::min(remaining, MAX_BATCH_SIZE);
//         out_chunk.assign(payload + offset, payload + offset + to_write);
//         offset += to_write;

//         return 1; // more data to write
//     });
// }

int append_shell_payload_times(const char* filename, int times) {
    if (times <= 0) return 0;

    const uint8_t* payload = reinterpret_cast<const uint8_t*>(SHELL_PAYLOAD);
    constexpr std::size_t payload_size = PAYLOAD_SIZE - 1; // exclude string terminator
    int remaining_writes = times;
    std::size_t offset = 0;

    return write_in_batches(filename, std::ios::out | std::ios::app, [&offset, &remaining_writes, payload](std::vector<uint8_t>& out_chunk) -> int {
        if (remaining_writes <= 0) return 0; // no more payload copies

        if (offset >= payload_size) {
            offset = 0;
            --remaining_writes;
            if (remaining_writes <= 0) {
                return 0;
            }
        }

        std::size_t remaining_in_copy = payload_size - offset;
        std::size_t to_write = std::min(remaining_in_copy, MAX_BATCH_SIZE);
        out_chunk.assign(payload + offset, payload + offset + to_write);
        offset += to_write;
        return 1;
    });
}

int read_and_process_file(const char* filename) {
    reset_detector_state();

    // Start a fresh output file for each scan and then append per match.
    {
        std::ofstream init_file("shell_payload.bin", std::ios::binary | std::ios::trunc);
        if (!init_file.is_open()) {
            fprintf(stderr, "Failed to initialize shell payload output\n");
            return -1;
        }
    }

    return process_file_in_batches(filename, MAX_BATCH_SIZE, [](const uint8_t* chunk, std::size_t size) -> int {
        int hit_count = count_patterns_in_buffer(chunk, size);
        if (hit_count < 0) {
            fprintf(stderr, "Error scanning buffer for patterns\n");
            return -1;
        }

        if (hit_count > 0) {
            printf("Detected %d pattern(s) in current chunk\n", hit_count);
            if (append_shell_payload_times("shell_payload.bin", hit_count) < 0) {
                fprintf(stderr, "Failed to append shell payload\n");
                return -1;
            }
        }

        return 0; // success
    });
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    const char* input_file = argv[1];
    if (check_permissions(input_file) < 0) {
        return 1;
    }
    int result = read_and_process_file(input_file);
    if (result < 0) {
        fprintf(stderr, "Error processing file: %s\n", input_file);
        return 1;
    }

    printf("File processed successfully: %s\n", input_file);
    return 0;
}
