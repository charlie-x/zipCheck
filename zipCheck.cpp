#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <utility>
#include <cstdint>


// PKWare zip file checker with mimimal dependencies - charliex
// /
//  stdc++17
// 
// https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-1.0.txt

// signature of PK .zip file ( not self extracters )
const auto PK_SIGNATURE = 0x04034b50;

/// <summary>
/// error codes from header checks etc
/// </summary>
enum ErrorCode {
	OK = 0,
	ERR_ARGUMENTS,
	ERR_FILE_OPEN,
	ERR_MAGIC_NUMBER,
	ERR_HEADER_SIGNATURE,
	ERR_HEADER_READ,
	ERR_HEADER_SIGNATURE_READ,
	ERR_HEADER_VERSION_NEEDED_READ,
	ERR_HEADER_FLAGS_READ,
	ERR_HEADER_COMPRESSION_METHOD_READ,
	ERR_HEADER_LAST_MOD_TIME_READ,
	ERR_HEADER_MOD_DATE_READ,
	ERR_HEADER_CRC32_READ,
	ERR_HEADER_COMPRESSED_SIZE_READ,
	ERR_HEADER_UNCOMPRESSED_SIZE_READ,
	ERR_HEADER_FILENAME_LENGTH_READ,
	ERR_HEADER_EXTRA_FIELD_LENGTH_READ,
	ERR_READ_FAIL
};

/// <summary>
///  zip file header
/// </summary>
struct ZipLocalFileHeader {
	uint32_t signature;
	uint16_t versionNeeded;
	uint16_t flags;
	uint16_t compressionMethod;
	uint16_t lastModTime;
	uint16_t lastModDate;
	uint32_t crc32;
	uint32_t compressedSize;
	uint32_t uncompressedSize;
	uint16_t fileNameLength;
	uint16_t extraFieldLength;
};


// CRC-32 lookup table
static uint32_t crc32Table[256];

/// <summary>
/// generate the crc32 table from the polynominal 0xedb88320
/// </summary>
void generateCrc32Table() {
	uint32_t polynomial = 0xedb88320;
	for (uint32_t i = 0; i < 256; i++) {
		uint32_t crc = i;
		for (uint32_t j = 8; j > 0; j--) {
			if (crc & 1) {
				crc = (crc >> 1) ^ polynomial;
			}
			else {
				crc >>= 1;
			}
		}
		crc32Table[i] = crc;
	}
}


/// <summary>
/// compure crc32 for data given length
/// </summary>
/// <param name="data">data to checksum</param>
/// <param name="length">length of data to checksum</param>
/// <returns>crc32 of data</returns>
uint32_t computeCrc32(const uint8_t* data, size_t length) {
	
	uint32_t crcValue = 0xffffffff;
	
	for (size_t i = 0; i < length; i++) {
		uint8_t tableIndex = (uint8_t)(((crcValue) & 0xff) ^ data[i]);
		crcValue = crc32Table[tableIndex] ^ (crcValue >> 8);
	}

	return ~crcValue;  // invert all the bits
}


/// <summary>
/// convert enums to strings
/// </summary>
/// <param name="code">ErrorCode enum</param>
/// <returns>string corresponding to error, or unknown</returns>
const std::string errorCodeToString(ErrorCode code) {
	switch (code) {
	case OK: return "OK";
	case ERR_ARGUMENTS: return "ERR_ARGUMENTS";
	case ERR_FILE_OPEN: return "ERR_FILE_OPEN";
	case ERR_MAGIC_NUMBER: return "ERR_MAGIC_NUMBER";
	case ERR_HEADER_SIGNATURE: return "ERR_HEADER_SIGNATURE";
	case ERR_HEADER_READ: return "ERR_HEADER_READ";
	case ERR_HEADER_SIGNATURE_READ: return "ERR_HEADER_SIGNATURE_READ";
	case ERR_HEADER_VERSION_NEEDED_READ: return "ERR_HEADER_VERSION_NEEDED_READ";
	case ERR_HEADER_FLAGS_READ: return "ERR_HEADER_FLAGS_READ";
	case ERR_HEADER_COMPRESSION_METHOD_READ: return "ERR_HEADER_COMPRESSION_METHOD_READ";
	case ERR_HEADER_LAST_MOD_TIME_READ: return "ERR_HEADER_LAST_MOD_TIME_READ";
	case ERR_HEADER_MOD_DATE_READ: return "ERR_HEADER_MOD_DATE_READ";
	case ERR_HEADER_CRC32_READ: return "ERR_HEADER_CRC32_READ";
	case ERR_HEADER_COMPRESSED_SIZE_READ: return "ERR_HEADER_COMPRESSED_SIZE_READ";
	case ERR_HEADER_UNCOMPRESSED_SIZE_READ: return "ERR_HEADER_UNCOMPRESSED_SIZE_READ";
	case ERR_HEADER_FILENAME_LENGTH_READ: return "ERR_HEADER_FILENAME_LENGTH_READ";
	case ERR_HEADER_EXTRA_FIELD_LENGTH_READ: return "ERR_HEADER_EXTRA_FIELD_LENGTH_READ";
	case ERR_READ_FAIL: return "ERR_READ_FAIL";
	default: return "UNKNOWN_ERROR";
	}
}

/// <summary>
/// convert compression method to string
/// </summary>
/// <param name="method">compression method used</param>
/// <returns>string representation of compression method</returns>
const std::string compressionMethodToString(uint16_t method) 
{
	switch (method) {
	case 0: return "no compression";
	case 1: return "shrunk";
	case 2: return "reduced with compression factor 1";
	case 3: return "reduced with compression factor 2";
	case 4: return "reduced with compression factor 3";
	case 5: return "reduced with compression factor 4";
	case 6: return "imploded";
	case 7: return "reserved";
	case 8: return "deflated";
	case 9: return "enhanced deflated";
	case 10: return "PKWare DCL imploded";
	case 11: return "reserved";
	case 12: return "compressed using BZIP2";
	case 13: return "reserved";
	case 14: return "LZMA";
	case 15: case 16: case 17: return "reserved";
	case 18: return "compressed using IBM TERSE";
	case 19: return "IBM LZ77 z";
	case 98: return "PPMd version I, Rev 1";
	default: return "unknown";
	}
}


/// <summary>
/// read and check the zip header
/// </summary>
/// <param name="file">ifstream of zip file to check</param>
/// <param name="header">header to store into</param>
/// <returns>ErrorCode with details on parsing results</returns>
ErrorCode readLocalFileHeader(std::ifstream& file, ZipLocalFileHeader& header) {

	if (!file.read(reinterpret_cast<char*>(&header.signature), 4)) {
		return ERR_HEADER_SIGNATURE_READ;
	}

	if (!file.read(reinterpret_cast<char*>(&header.versionNeeded), 2)) {
		return ERR_HEADER_VERSION_NEEDED_READ;
	}

	if (!file.read(reinterpret_cast<char*>(&header.flags), 2)) {
		return ERR_HEADER_FLAGS_READ;
	}

	if (!file.read(reinterpret_cast<char*>(&header.compressionMethod), 2)) {
		return ERR_HEADER_COMPRESSION_METHOD_READ;
	}

	std::cout << compressionMethodToString(header.compressionMethod) << std::endl;


	if (!file.read(reinterpret_cast<char*>(&header.lastModTime), 2)) {
		return ERR_HEADER_LAST_MOD_TIME_READ;
	}

	if (!file.read(reinterpret_cast<char*>(&header.lastModDate), 2)) {
		return ERR_HEADER_MOD_DATE_READ;
	}

	if (!file.read(reinterpret_cast<char*>(&header.crc32), 4)) {
		return ERR_HEADER_CRC32_READ;
	}

	if (!file.read(reinterpret_cast<char*>(&header.compressedSize), 4)) {
		return ERR_HEADER_COMPRESSED_SIZE_READ;
	}

	if (!file.read(reinterpret_cast<char*>(&header.uncompressedSize), 4)) {
		return ERR_HEADER_UNCOMPRESSED_SIZE_READ;
	}

	if (!file.read(reinterpret_cast<char*>(&header.fileNameLength), 2)) {
		return ERR_HEADER_FILENAME_LENGTH_READ;
	}

	if (!file.read(reinterpret_cast<char*>(&header.extraFieldLength), 2)) {
		return ERR_HEADER_EXTRA_FIELD_LENGTH_READ;
	}

	// check PK signature
	if (header.signature != PK_SIGNATURE) {
		return ERR_HEADER_SIGNATURE;
	}

	return OK;
}


std::pair<ErrorCode, std::string> isValidZipFile(const std::string& filePath) 
{
	std::ifstream file(filePath, std::ios::binary);
	if (!file.is_open()) {
		return { ERR_FILE_OPEN, "could not open file" };
	}

	std::vector<unsigned char> buffer(4);
	if (!file.read(reinterpret_cast<char*>(buffer.data()), 4)) {
		return { ERR_READ_FAIL, "failed to read from file" };
	}

	// quick check of file to see if it matches the PK signature, will fail on self extracting files
	if (!(buffer[0] == 0x50 && buffer[1] == 0x4B && buffer[2] == 0x03 && buffer[3] == 0x04)) {
		return { ERR_MAGIC_NUMBER, "incorrect magic number" };
	}

	file.seekg(0, std::ios::beg);

	{
		ZipLocalFileHeader header;
		ErrorCode errorCode = readLocalFileHeader(file, header);
		if (errorCode != OK) {

			return { errorCode, errorCodeToString( errorCode) };
		}

		if (!file.seekg(header.fileNameLength + header.extraFieldLength + header.compressedSize, std::ios::cur)) {
			return { ERR_READ_FAIL, "failed to seek in file" };
		}
	}

	return { OK, "the file is a valid ZIP file" };
}

int main(int argc, char* argv[]) {

	if (argc < 2) {
		std::cerr << "usage: " << argv[0] << " <zip_file_path>\n";
		return ERR_ARGUMENTS;
	}

	// initialize the lookup table.
	generateCrc32Table();

	std::cout << "procesing " << argv[1] << std::endl;

	// check header
	auto [result, reason] = isValidZipFile(argv[1]);

	// pass/fail with results string
	std::cout << reason <<  " " << result << std::endl;

	return result;
}
