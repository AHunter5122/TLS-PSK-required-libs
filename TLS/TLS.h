#ifndef TLS_h
#define TLS_h
#include <WiFiUdp.h>

#include <ESP8266WiFi.h>
#include <string.h>
#include <vector>

class TLS
{

public:
	TLS();
	static bool handshake(const char* psk_value, const char* psk_id, WiFiClient client, const char* host, const int httpPort);
	static void sendAppData(char* data, int dataSize, WiFiClient client, const char* key, const char* host, const int httpPort);
	static void connectWiFi(const char* id, const char* pass);
	static String hexValue(uint8_t ch);
	static unsigned long sendNTPpacket(IPAddress& address, WiFiUDP udp, const int NTP_PACKET_SIZE);
	static void client_hello(uint8_t* buffer, std::vector<uint8_t>& crand);
	static void client_key_exchange(uint8_t *buffer, const char* id, int id_size);
	static void change_cipher_spec(uint8_t* buffer, int bufferSize);
	static int array_copy(uint8_t *main, int startaddr, uint8_t *extra, int extralen);
	static void hmac256(uint8_t* secret, int secretSize, uint8_t* data, int dataSize, uint8_t* temp);
	static void printHex(uint8_t* data, int dataSize);
	static void PRF(uint8_t* secret, const char* label, uint8_t* seed, int  secretSize, int labelSize, int seedSize, int quantity, std::vector<uint8_t>& cache);
	static void preMasterSecret(const char* psk, int psk_size, std::vector<uint8_t>& pms);
	static void sendPacket(uint8_t* packet, int packetSize, WiFiClient client, const char* host, const int httpPort);
	static bool receivePacket(std::vector<uint8_t>& v, WiFiClient client);
	static void getServerRandom(std::vector<uint8_t>& packet, std::vector<uint8_t>& srand);
	static void masterSecret(std::vector<uint8_t>& pms, std::vector<uint8_t>& cRand, std::vector<uint8_t>& sRand, const char* label, int labelSize, std::vector<uint8_t>& masterSecret);
	static void client_finished(std::vector<uint8_t>& secret, std::vector<uint8_t>& messages, uint8_t* buffer);
	static void insertClientPacket(uint8_t* packet, int packetSize, std::vector<uint8_t>& allPackets);
	static void sha256Hash(std::vector<uint8_t>& messages, uint8_t* buffer);
	//static void AESencrypt(uint8_t* plain, int plainSize, uint8_t* cipher, uint8_t* key, int bits);
	static void applicationData(uint8_t *buffer, char* data, int dataSize, const char* key);
	static byte packetBuffer[];

};



#endif