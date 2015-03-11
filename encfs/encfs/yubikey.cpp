/*
  Yubikey support
  Added by P. Elliott
*/

#include <yklib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <ctype.h>
#include <conio.h>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>

#define DBG false

using namespace std;

// Covnvert the return code to a string
const char * returnRetcode(YKLIB_RC rc)
{
    switch (rc) {
        case YKLIB_OK:                  return("YKLIB_OK");
        case YKLIB_FAILURE:             return("YKLIB_FAILURE");
        case YKLIB_NOT_OPENED:          return("YKLIB_NOT_OPENED");
        case YKLIB_INVALID_PARAMETER:   return("YKLIB_INVALID_PARAMETER");
        case YKLIB_NO_DEVICE:           return("YKLIB_NO_DEVICE");
        case YKLIB_MORE_THAN_ONE:       return("YKLIB_MORE_THAN_ONE");
        case YKLIB_WRITE_ERROR:         return("YKLIB_WRITE_ERROR");
        case YKLIB_INVALID_RESPONSE:    return("YKLIB_INVALID_RESPONSE");
        case YKLIB_NOT_COMPLETED:       return("YKLIB_NOT_COMPLETED");
        case YKLIB_NOT_CONFIGURED:      return("YKLIB_NOT_CONFIGURED");
        case YKLIB_NOT_READY:           return("YKLIB_NOT_READY");
        case YKLIB_PROCESSING:          return("YKLIB_PROCESSING");
        case YKLIB_TIMER_WAIT:          return("YKLIB_TIMER_WAIT");
        case YKLIB_UNSUPPORTED_FEATURE: return("YKLIB_UNSUPPORTED_FEATURE");
        default:                        return("Unknown");
    }
}

void hex2bin(string str, BYTE * bytes, int size=16)  
{  
    // loop through the string - 2 bytes at a time converting it to decimal equivalent
    // and store in byte array
	int v;
	for (int i=0; i<size; i++) {
		sscanf_s(str.substr(i*2, 2).c_str(), "%x%x", &v); 
		bytes[i] = BYTE(v);
	}
} 


void bin2hex(BYTE * m, char * s, int size=16)
{
	// For some reason sprintf_s causes a corruption....
	//for (int i = 0; i < size; i++) sprintf_s(&s[2*i], size*2+1, "%02x", m[i]);
	for (int i = 0; i < size; i++) sprintf(&s[2*i], "%02x", m[i]);
	s[size*2] = '\0';
	//printf("Converted = %s\n",s);
}


// Print out the SHA1 digest
void print_sha1(BYTE * m)
{
    int i;

    printf("HMAC-SHA1 = ");
    for (i = 0; i < SHA1_DIGEST_SIZE; i++) printf("%02x", m[i]);
    printf ("\n");
}


// Print out byte array as hex
void print_hex(BYTE * m, int size=16)
{
    int i;

    printf("VALUE = ");
    for (i = 0; i < size; i++) printf("%02x", m[i]);
    printf ("\n");
}


// Return the slot as a string
const char * get_slot(BYTE slot)
{
	if (slot == YKLIB_FIRST_SLOT) return "YKLIB_FIRST_SLOT";
	else return "YKLIB_SECOND_SLOT";
}


void yk_challenge(CYkLib * yk, YKLIB_RC * rc, BYTE targetSlot, BYTE * ip, BYTE * op, int size=16)
{

	/*
	* YkLib:writeChallengeBegin() always sends a 64 byte frame to the Yubikey sha1-hmac and
	* the data (ip,size) is zero padded on the RHS before sending. 
	*/
	// printf("Challenge size: %d\n",size);

	*rc = yk->writeChallengeBegin(targetSlot, YKLIB_CHAL_HMAC, ip, size);
	if (*rc != YKLIB_OK) return;
	
	if (DBG) printf("Slot = %s\n", get_slot(targetSlot));
	
	*rc = yk->waitForCompletion(YKLIB_MAX_CHAL_WAIT, op, SHA1_DIGEST_SIZE);
	if (*rc == YKLIB_INVALID_RESPONSE ) return;
	
	printf("Press Yubikey button\n");
    while (*rc == YKLIB_TIMER_WAIT) *rc = yk->waitForCompletion(YKLIB_MAX_CHAL_WAIT, op, SHA1_DIGEST_SIZE);
	printf("Response received - attempting to mount\n");
}


void yk_response(CYkLib * yk, YKLIB_RC * rc, BYTE * ip, BYTE * op, int size=16)
{
	yk_challenge(yk, rc, YKLIB_FIRST_SLOT, ip, op, size);
	//printf("Challenge size: %d\n",size);
	if (*rc != YKLIB_OK) {
		printf ("Bad response on first slot (%s)\n", returnRetcode(*rc));
		printf("Trying second slot\n");
		yk_challenge(yk, rc, YKLIB_SECOND_SLOT, ip, op, size);
		if (*rc != YKLIB_OK) {
			printf ("Bad response for second slot(%s)\n", returnRetcode(*rc));
			exit(1);
		}
	}
}


void yk_serial(CYkLib * yk, YKLIB_RC * rc, BYTE * serial)
{
	// Get the serial number
	char s[33];
	*rc = yk->readSerialBegin();
	if (*rc == YKLIB_OK){
		*rc = yk->waitForCompletion(YKLIB_MAX_SERIAL_WAIT, serial, sizeof(DWORD));
		bin2hex(serial,s,4);
		printf("Serial number: %s \n",s);
	}
	else {
		printf ("Bad response from Yubikey(%s)\n", returnRetcode(*rc));
		exit(1);
	}
}

void verify_serial(string p1, BYTE * buffer)
{
	BYTE p1b[4];
	hex2bin(p1, p1b, 4);
	if (memcmp(p1b,buffer,4) != 0 ) {
		printf("File Id does not match Yubikey Id, should be:\n" );
		print_hex(buffer);
		printf("Not:\n");
		print_hex(p1b);
		exit(1);
	}
	else {
		if (DBG) printf("File Id matches Yubikey Id\n");
	}
}

void aes_ecb_enc(BYTE * key, BYTE * ib, BYTE * ob)
{
	AES_KEY k;
	AES_set_encrypt_key(key, 128, &k);
	AES_encrypt(ib, ob, &k);
}


void aes_ecb_dec(BYTE * key, BYTE * ib, BYTE * ob)
{
	AES_KEY k;
	AES_set_decrypt_key(key, 128, &k);
	AES_decrypt(ib, ob, &k);
}


// The main Yubikey sha1-hmac challenge & AES unwrap function
bool yk_unwrap(BYTE * buf, int * size)
	// NOTE: buf size must be > 16 bytes in order to pass back the expected data!
{
	CYkLib yk; // This causes a link problem unless libcmt.lib is added to the linker ignore list!
	BYTE ykhash[20], serial[4], wk[16];
    YKLIB_RC rc;
    STATUS status;
    string p1, p2;
	char tmp[33];

	// Yubikey Challenge and response
	if (DBG) printf("Checking Yubikey environment\n");
	char * YK_WRAP_PATH = getenv("YK_WRAP_PATH");
	if ( YK_WRAP_PATH != NULL ) {
		if (DBG) printf("The current YK_WRAP_PATH is: %s\n",YK_WRAP_PATH);
		
		// Check for a Yubikey
		memset(&status, 0, sizeof(status));
		if ( ! yk.enumPorts() ) printf("Please insert Yubikey\n");
		while ( ! yk.enumPorts() ) Sleep(1000);
		if (DBG) printf("Number of Yubikeys found %d\n", yk.enumPorts());
		yk.openKey();

		// Open the file
		if (DBG) printf("Opening file: %s\n", YK_WRAP_PATH);
		ifstream the_file ( YK_WRAP_PATH );
		if ( !the_file.is_open() ) {
			cout<<"Could not open file\n";
			exit(1);
		}
		else {
			// Get the first two fileds of the first line
			the_file >> p1;
			the_file >> p2;
			if (DBG) printf("  Serial num : %s\n", p1.c_str());
			if (DBG) printf("  Wrapped Key: %s\n", p2.c_str());
		}

		// Process the wrapped key data
		if (p2.size() != 32) {
			printf("File keys is not 32 hex digits\n");
			exit(1);
		}
		hex2bin(p2, wk);

		// Compare serial numbers (file vs key)
		yk_serial(&yk, &rc, serial);
		verify_serial(p1, serial);

		// Get the Yubikey Response
		yk_response(&yk, &rc, buf, ykhash, *size);
		if (DBG) print_sha1(ykhash);

		// Process the wk using buffer as the wrapping key
		aes_ecb_dec(ykhash, wk, buf);
		*size = 16;
		
		if (DBG) {
			bin2hex(buf,tmp);
			printf("Dec WK: %s\n", tmp);
		}

		return true;
	}
	else {
		printf("YK_WRAP_PATH environment variable not set, skipping Yubikey.\n");
		return false;
	}
}

