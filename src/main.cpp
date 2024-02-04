#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <system_error>
#include <stdexcept>
#include <vector>

inline int open_file(const char * filename) {
	int fd = ::open(filename, O_RDONLY);
	if (fd < 0) {
		throw std::system_error(errno, std:: system_category());
	}
	return fd;
}

inline int create_file(const char * filename) {
	int fd = ::open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		throw std::system_error(errno, std:: system_category());
	}
	return fd;
}

inline uint64_t filesize(const int fd) {
	struct stat sb;
	if (fstat(fd, &sb) != 0) {
		throw std::system_error(errno, std:: system_category());
	}
	return sb.st_size;
}

struct filereader {
	inline filereader(const char * filename)
	: m_fd(open_file(filename))
	, m_offset(0)
	, m_size(filesize(m_fd))
	{}

	inline filereader(const std::string & filename)
	: filereader(filename.c_str()) {}

	inline ~filereader() noexcept { ::close(m_fd); }

	inline void read(void * buffer, const size_t amount) {
		if (::read(m_fd, buffer, amount) != ssize_t(amount)) {
			throw std::system_error(errno, std:: system_category());
		}
		m_offset += amount;
	}

	template<typename T>
	inline void read(T & buffer) {
		return read(&buffer, sizeof(T));
	}

	template<typename T>
	inline T read() {
		T tmp;
		read(&tmp, sizeof(T));
		return tmp;
	}

	inline std::string read_string(const size_t length) {
		std::string tmp(length, 0);
		read(&tmp[0], length);
		return tmp;
	}

	inline void seek(const uint64_t offset) {
		if (lseek(m_fd, offset, SEEK_SET) < 0) {
			throw std::system_error(errno, std:: system_category());
		}
		m_offset = offset;
	}

	inline uint64_t offset() const noexcept {
		return m_offset;
	}

	inline uint64_t size() const noexcept {
		return m_size;
	}

	int m_fd;
	uint64_t m_offset;
	uint64_t m_size;
};

struct filewriter {
	inline filewriter(const char * filename) : fd(create_file(filename)) {}
	inline filewriter(const std::string & filename) : fd(create_file(filename.c_str())) {}
	inline ~filewriter() { ::close(fd); }

	inline void write(const void * buffer, const size_t amount) {
		if (::write(fd, buffer, amount) != ssize_t(amount)) {
			throw std::system_error(errno, std:: system_category());
		}
	}

	int fd;
};

inline void make_directory(const std::string & filename) {
	for (
		size_t i = 0, end = filename.find('/', 0);
		end != std::string::npos;
		i = end + 1, end = filename.find('/', i)
	) {
		const std::string path(filename, 0, end);
		if (mkdir(path.c_str(), 0755) != 0) {
			if (errno != EEXIST) {
				throw std::system_error(errno, std:: system_category());
			}
		}
	}
}

inline uint32_t decrypt_v1_int(
	const uint32_t input,
	uint32_t & key
) noexcept {
	const auto result = input ^ key;
	key = (key * 7) + 3;
	return result;
}

inline uint32_t decrypt_v3_int(
	const uint32_t input,
	const uint32_t key
) noexcept {
	return input ^ key;
}

std::string decrypt_v1_filename(
	const std::string & input,
	uint32_t & key
) {
	std::string output(input.length(), 0);
	for (uint i = 0, n = input.length(); i < n; ++i) {
		const auto chr = char(input[i] ^ (key & 0xff));
		key = (key * 7) + 3;
		if (chr == '\\' || chr == 0x5c) {
			output[i] = '/';
		} else {
			output[i] = chr;
		}
	}
	return output;
}

std::string decrypt_v3_filename(
	const std::string & input,
	const uint32_t key
) {
	std::string output(input.length(), 0);
	for (uint i = 0, n = input.length(); i < n; ++i) {
		const auto chr = input[i] ^ ((key >> (8 * (i % 4))) & 0xff);
		if (chr == '\\' || chr == 0x5c) {
			output[i] = '/';
		} else {
			output[i] = chr;
		}
	}
	return output;
}

struct file_record {

	inline file_record(
		const uint32_t offset,
		const uint32_t size,
		const uint32_t key,
		std::string name
	)
	: m_offset(offset)
	, m_size(size)
	, m_key(key)
	, m_name(std::move(name))
	{
		printf("%u %u %*.*s\n",
			m_offset, m_size,
			int(m_name.length()), int(m_name.length()),
			m_name.c_str());
	}

	void extract(filereader & input) const {
		std::vector<uint8_t> buffer(m_size);
		input.seek(m_offset);
		input.read(buffer.data(), m_size);
		auto tmpkey = m_key;
		uint j = 0;
		for (uint i = 0; i < m_size; ++i) {
			if (j == 4) {
				j = 0;
				tmpkey = (tmpkey * 7) + 3;
			}
			buffer[i] ^= (tmpkey >> (8 * (i % 4))) & 0xff;
			j++;
		}
		make_directory(m_name);
		filewriter output(m_name);
		output.write(buffer.data(), m_size);
	}

	uint32_t m_offset;
	uint32_t m_size;
	uint32_t m_key;
	std::string m_name;
};

void unpack_v1(filereader & input) {
	auto directory_key = uint32_t(0xdeadcafe);
	std::vector<file_record> records;
	while (input.offset() < input.size()) {
		const auto name_length = decrypt_v1_int(input.read<uint32_t>(), directory_key);
		const auto name = decrypt_v1_filename(input.read_string(name_length), directory_key);
		const auto size = decrypt_v1_int(input.read<uint32_t>(), directory_key);
		const auto offset = input.offset();
		const auto file_key = directory_key;
		input.seek(offset + size);
		records.emplace_back(offset, size, file_key, name);
	}
	for (const auto & r : records) {
		r.extract(input);
	}
}

void unpack_v3(filereader & input) {
	const auto directory_key = (input.read<uint32_t>() * 9) + 3;
	std::vector<file_record> records;
	while (const auto offset = decrypt_v3_int(input.read<uint32_t>(), directory_key)) {
		const auto size = decrypt_v3_int(input.read<uint32_t>(), directory_key);
		const auto file_key = decrypt_v3_int(input.read<uint32_t>(), directory_key);
		const auto name_length = decrypt_v3_int(input.read<uint32_t>(), directory_key);
		const auto name = decrypt_v3_filename(input.read_string(name_length), directory_key);
		records.emplace_back(offset, size, file_key, name);
	}
	for (const auto & r : records) {
		r.extract(input);
	}
}

void unpack(const char * filename) {
	filereader input(filename);
	char signature[7];
	input.read(signature);
	if (strncmp(signature, "RGSSAD", sizeof(signature)) != 0) {
		throw std::runtime_error("Invalid input file");
	}
	const auto version = input.read<uint8_t>();
	switch (version) {
		case 1: return unpack_v1(input);
		case 3: return unpack_v3(input);
	}
	throw std::runtime_error("Unsupported version");
}

int main(int argc, char ** argv) {
	if (argc >= 2) {
		unpack(argv[1]);
	}
	return 0;
}
