/*****************************************************************************
 * Author:  Paul Elliott <paul.elliott@emb-sec.com>
 * Company: Embedded Security Solutions, www.emb-sec.com
 *
 * Based on original code by Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2015, Paul Elliott, Valient Gough
 *
 * This library is free software; you can distribute it and/or modify it under
 * the terms of the GNU General Public License (GPL), as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GPL in the file COPYING for more
 * details.
 */

#include "ACipherFileIO.h"

#include "Cipher.h"
#include "MemoryPool.h"

#include <rlog/rlog.h>
#include <rlog/Error.h>

#include <fcntl.h>
#include <cerrno>

#include <openssl/bio.h>
#include <openssl/evp.h>

#include "SSL_Cipher.h"


/*
	Support for Authenticated Encryption
	====================================
	
	Authenticated encryption is implemented using AES-256-OCB (from openssl 1.1.0-dev).
	
	OCB stands for 'Offset Codebook' mode, it is a provably secure construction that provides
	both encryption and authentication. In my opionin this is the fastest and most efficent
	autheticated encryption mode available and this is why it has been integrated.

	OCB is the subject of a patent by Phillip Rogaway and requires a license, however this is
	free for open source software, for details please check the link below.

	http://web.cs.ucdavis.edu/~rogaway/ocb/ocb-faq.htm

	An alternative authenticated encryption mode is GCM (also available in openssl) which is
	not the subject of any patents, however it is not as fast as OCB. It should be relatively 
	straight forward to integrate.

	The following are enforced features and are not optional, associated XML config will be ignored:
		o Block authentication, one tag per block 
		o File header

*/


using boost::shared_ptr;
using boost::dynamic_pointer_cast;

// Borrowed from yubikey.cpp
void bin2hex(BYTE *, char *, int=16);


/*
    - Version 2:0 adds support for a per-file initialization vector with a
      fixed HEADER_SIZE byte header.  The headers are enabled globally within a
      filesystem at the filesystem configuration level.
      When headers are disabled, 2:0 is compatible with version 1:0.
*/
static rel::Interface ACipherFileIO_iface("FileIO/Cipher", 2, 0, 1);


static bool checkSize( int fsBlockSize, int cipherBlockSize )
{
    int blockBoundary = fsBlockSize % cipherBlockSize ;
    if(blockBoundary != 0)
    {
		rError("CipherFileIO: blocks should be multiple of cipher block size");
		return true;
    } else
		return false;
}


// Convert a long int to a byte array
inline void int2bytes(BYTE * b, uint64_t v, int size = 8)
{
    for(int i=0; i<8; ++i)
    {
        b[i] = v & 0xff;
        v >>= 8;
    }
}


// Test a byte array for all zeros
inline bool isZero(BYTE * b, int size=HEADER_SIZE)
{
	for(int i=0; i<size; ++i)
	{
		if (b[i] != 0 ) return false;
	}
	return true;
}


// Bit wise XOR of 16 element byte arrays
inline void xor(BYTE *r, BYTE *a, BYTE *b, int size=HEADER_SIZE)
{
    int i;
	for (i=0; i < size; ++i) {
		r[i] = a[i] ^ b[i];
	}
}


// Calculate a NONCE based on the block number
inline void calcNonce(BYTE * n, uint64_t blockNum, BYTE * iv)
{
	BYTE bn[HEADER_SIZE] = {0};
	int2bytes(bn,blockNum,8);
	xor(n, bn, iv, HEADER_SIZE); 
}


#ifdef DBG
// Print a byte array in hex followed by a format string and any additional parameters
void printb(BYTE *b, int size, char * fmt, ...)
{
 		char * bstr = new char[size*2 +1];
		bin2hex(b, bstr, size);
		printf("%-32s : ", bstr);

		va_list args;
		va_start(args, fmt);
		vprintf(fmt, args);
		va_end(args);
}
#endif


/*
 * #######################################################################
 * #       Functions for stream offset translation, RAW <-> USER         #
 * #######################################################################
 */


inline static off_t roundUpDivide( off_t numerator, int denominator )
{
    // integer arithmetic always rounds down, so we can round up by adding
    // enough so that any value other then a multiple of denominator gets
    // rouned to the next highest value.
    return ( numerator + denominator - 1 ) / denominator;
}


// Map from raw offset to user
inline off_t map2userOffset(off_t offset, int bs)
{
	off_t blocks = roundUpDivide(offset - HEADER_SIZE, bs + TAG_SIZE);

	// Given a raw offset returns the offset in the user file
	return offset - (blocks * TAG_SIZE) - HEADER_SIZE;
}


inline off_t map2rawOffset(off_t offset, int bs)
{
	off_t blocks = roundUpDivide(offset, bs);

	// Given a user offset returns the data offset in the raw file
	return offset + (blocks * TAG_SIZE) + HEADER_SIZE;
}


/* 
  Used by the [read|write]OneBlock functions to locate the tag insertion point.
  
  Note: we can't use map2rawOffset() for this as it will behave differently in the case
  of a newly created empty file. For an empty file it would return the position of the
  tag and for any other file the position of the data.

  This function always returns the position of the tag. 
*/
inline off_t locateRawOffset(off_t offset, int bs)
{
	off_t blocks, partial;
	
	blocks  = offset / bs;
	partial = offset % bs;

	// Points at the target data without subtracting the TAG in the target block
	return  blocks * (bs + TAG_SIZE) + partial + HEADER_SIZE;
}


/*
 * #######################################################################
 */


// Authenticated Cipher Class
ACipherFileIO::ACipherFileIO( const shared_ptr<FileIO> &_base, const FSConfigPtr &cfg)
	: BlockFileIO( cfg->config->blockSize, cfg ) // using the configured block size
    , base( _base )
    , haveHeader( cfg->config->uniqueIV )
    , externalIV( 0 )
    , lastFlags( 0 )
{
    fsConfig = cfg;
    cipher   = cfg->cipher;
    key      = cfg->key;

	ctx_ae = fsConfig->config->ctx_ae;
	ctx_ad = fsConfig->config->ctx_ad;

	memset(fileIV, 0, HEADER_SIZE); // fileIV init

    static bool warnOnce = false;

    if(!warnOnce)
        warnOnce = checkSize( fsConfig->config->blockSize,
                              fsConfig->cipher->cipherBlockSize() );
}


ACipherFileIO::~ACipherFileIO()
{
}


rel::Interface ACipherFileIO::Interface() const
{
    return ACipherFileIO_iface;
}


int ACipherFileIO::open( int flags )
{
    int res = base->open( flags );
    if( res >= 0 ) lastFlags = flags;
    return res;
}


void ACipherFileIO::setFileName( const char *fileName )
{
    base->setFileName( fileName );
}


const char *ACipherFileIO::getFileName() const
{
    return base->getFileName();
}


bool ACipherFileIO::setIV( uint64_t iv )
{
    //rDebug("in setIV, current IV = %" PRIu64 ", new IV = %" PRIu64  ", fileIV = %" PRIu64, externalIV, iv, fileIV);
    if(externalIV == 0)
    {
		// we're just being told about which IV to use.  since we haven't
		// initialized the fileIV, there is no need to just yet..
		externalIV = iv;
		if(!isZero((BYTE *)fileIV)) rWarning("fileIV initialized before externalIV!");
    } else 
	{
		// we have an old IV, and now a new IV, so we need to update the fileIV
		// on disk.
		if(isZero((BYTE *)fileIV))
		{
			// ensure the file is open for read/write..
			int newFlags = lastFlags | O_RDWR;
			int res = base->open( newFlags );
			if(res < 0)
			{
				if(res == -EISDIR)
				{
					// duh -- there are no file headers for directories!
					externalIV = iv;
					return base->setIV( iv );
				} else
				{
					rDebug("writeHeader failed to re-open for write");
					return false;
				}
			}
    		initHeader();
		}

		uint64_t oldIV = externalIV;
		externalIV = iv;
		if(!writeHeader())
		{
			externalIV = oldIV;
			return false;
		}
    }
    return base->setIV( iv );
}


int ACipherFileIO::getAttr( struct stat *stbuf ) const
{
    int res = base->getAttr( stbuf );
    // adjust size
	if((res == 0) && S_ISREG(stbuf->st_mode)) {
		if (stbuf->st_size > 0) {
			rAssert(stbuf->st_size >= HEADER_SIZE);
			stbuf->st_size = map2userOffset(stbuf->st_size, blockSize());
		}
	}
    return res;
}


off_t ACipherFileIO::getSize() const
{
    off_t size = base->getSize();
    // No check on S_ISREG here -- don't call getSize over getAttr unless this is a normal file!
    if(size > 0) {
		rAssert(size >= HEADER_SIZE);
		size = map2userOffset(size, blockSize());
    }
    return size;
}


void ACipherFileIO::initHeader( )
{
    // check if the file has a header, and read it if it does..  Otherwise,
    // create one.
    off_t rawSize = base->getSize();
    if(rawSize >= HEADER_SIZE)
    {
		// rDebug("reading existing header, rawSize = %" PRIi64, (long long int) rawSize);
		// has a header.. read it

		IORequest req;
		req.offset  = 0;
		req.data    = fileIV;
		req.dataLen = HEADER_SIZE;
		base->read( req ); // Read from raw file

#ifdef DBG
		printf("initHeader(): Decoding file IV\n");
		printf("externalIV: %X\n", externalIV);
		printb(returnSSLKey(key), 16, "KEY\n" );
		printb(fileIV, 12, "fileIV\n");
#endif
		cipher->streamDecode( fileIV, HEADER_SIZE, externalIV, key );

		rAssert(!isZero(fileIV)); // 0 is never used..
    } 
	else {
		rDebug("creating new file IV header");

		BYTE buf[HEADER_SIZE] = {0};
		do {
			if(!cipher->randomize( fileIV, HEADER_SIZE, false )) throw RLOG_ERROR("Unable to generate a random file IV");
			if(isZero(fileIV)) rWarning("Unexpected result: randomize returned all null bytes!");
		} 
		while(isZero(fileIV)); // don't accept 0 as an option..

		if( base->isWritable() ) {

#ifdef DBG
			printf("initHeader(): Encoding file IV\n");
			printf("externalIV: %X\n", externalIV);
			printb(returnSSLKey(key), 16, "KEY\n");
			printb(fileIV, 12, "fileIV\n");
#endif
			memcpy(buf, fileIV, HEADER_SIZE);

			cipher->streamEncode( buf, HEADER_SIZE, externalIV, key );

			IORequest req;
			req.offset  = 0;
			req.data    = buf;
			req.dataLen = HEADER_SIZE;

			base->write( req ); // Write to raw file
		} 
		else rDebug("base not writable, IV not written..");
    }
}



bool ACipherFileIO::writeHeader( )
{
	printf("writeHeader()\n");

    if( !base->isWritable() )
    {
	// open for write..
	int newFlags = lastFlags | O_RDWR;
		if( base->open( newFlags ) < 0 )
		{
			rDebug("writeHeader failed to re-open for write");
			return false;
		}
    } 

    if(isZero(fileIV)) rError("Internal error: fileIV == 0 in writeHeader!!!");

#ifdef DBG
	printf("writeHeader(): Encoding file IV\n");
	printf("externalIV: %X\n", externalIV);
	printb(returnSSLKey(key), 16, "KEY\n");
	printb(fileIV, 12, "fileIV before\n");
#endif

    cipher->streamEncode( fileIV, HEADER_SIZE, externalIV, key );

    IORequest req;
    req.offset  = 0;
    req.data    = fileIV;
    req.dataLen = HEADER_SIZE;

    base->write( req );

    return true;
}


/* 
  The [read|write]OneBlock function are needed by the base class BlockFileIO, all requests
  are guarenteed to be aligned to a single block.
*/


ssize_t ACipherFileIO::readOneBlock( const IORequest &req ) const
{
    // read raw data, then decipher it..
    int bs = blockSize();
    off_t blockNum = req.offset / bs;
 
#ifdef DBG
	printf("Doing: readOneBlock()\n");
	printf("  Block size %d\n", bs);
	printf("  Req Size   %d\n", req.dataLen);
	printf("  Req Offset %d\n", req.offset);
#endif

    ssize_t readSize = 0;
	BYTE nonce[HEADER_SIZE], tag[TAG_SIZE];

	// Form a TAG request
	IORequest tagReq = req;
	tagReq.data      = tag;
	tagReq.dataLen   = TAG_SIZE;
	tagReq.offset    = locateRawOffset(tagReq.offset, bs);

	// Align the payload request
	IORequest tmpReq = req;
	tmpReq.offset    = tagReq.offset + TAG_SIZE;
    
	readSize = base->read( tagReq ); // Read TAG from the base class
	//printf("  Read (%d) TAG bytes\n", readSize);
    readSize = base->read( tmpReq ); // Read data from the base class
	//printf("  Read (%d) DATA bytes\n", readSize);

	int outlen, tmplen;
    bool ok;
    if(readSize > 0)
    {
		if(isZero((BYTE *)fileIV)) const_cast<ACipherFileIO*>(this)->initHeader();
	
		/*
			File hole support
			=================

			The current implementation simply passes zero blocks through, there is
			no authentication. This is identified as a low impact security issue in the
			EncFS Security Audit by Taylor Hornby, Jan 14 2014. It allows an attacker
			to insert additonal zero blocks that would not be detected.
		*/

		// Code to check for zero blocks if configured for zero-block pass-through
		bool skipBlock = true;
		if( _allowHoles ) {
			for (int i=0; i<readSize; ++i) {
				if (tmpReq.data[i] != 0) {
					skipBlock = false;
					break;
				}
			}
		} 

		ok = true;
		if (!skipBlock) {
			// Get the key and IV
			BYTE * k = returnSSLKey(key);
			calcNonce( (BYTE *)nonce, blockNum, (BYTE *)fileIV );
#ifdef DBG
			printb(nonce,  12, "nonce Read for block: %d\n", blockNum );
			printb((BYTE *)fileIV, 12, "File IV for block: %d\n", blockNum );
#endif
			EVP_CIPHER_CTX_ctrl(ctx_ad, EVP_CTRL_AEAD_SET_TAG, 16, (void *)tag);          // Set expected TAG value
			EVP_DecryptInit_ex(ctx_ad, NULL, NULL, k, nonce);							  // Specify key and IV (nonce)
			EVP_DecryptUpdate(ctx_ad, tmpReq.data, &outlen, tmpReq.data, (int)readSize);  // Decrypt plaintext

			ok = EVP_DecryptFinal_ex(ctx_ad, tmpReq.data+outlen, &tmplen) > 0;            // Finalise
			outlen += tmplen;

		}

#ifdef DBG
		if (!ok) printb( (BYTE *)tagReq.data, 16, "TAG authentication failure, block: %d\n", blockNum );
#endif

		if(!ok) {
			rDebug("decodeBlock failed for block %" PRIi64 ", size %i",	blockNum, (int)readSize );
			readSize = -1;
		}
    } 
	else rDebug("readSize zero for offset %" PRIi64, req.offset);

    return readSize;
}


bool ACipherFileIO::writeOneBlock( const IORequest &req )
{
    int bs = blockSize();
    off_t blockNum = req.offset / bs;

    if(isZero(fileIV)) initHeader();

	int outlen, tmplen;
	BYTE nonce[HEADER_SIZE], tag[TAG_SIZE];

	MemBlock mb = MemoryPool::allocate( bs ); // Temporary due to OCB inline bug - remove when fixed

	// Form the tag request
	IORequest tagReq = req;
	tagReq.data    = tag;
	tagReq.dataLen = TAG_SIZE;
	tagReq.offset  = locateRawOffset(tagReq.offset, bs);

	// Align the payload request
	IORequest tmpReq = req;
	tmpReq.offset  = tagReq.offset + TAG_SIZE;
	
	bool ok;

#ifdef DBG
	printf("Doing: writeOneBlock()\n");
	printf("  Block size %d\n", bs);
	printf("  Req Size   %d -> %d\n", req.dataLen, tmpReq.dataLen);
	printf("  Req Offset %d -> %d\n", req.offset, tmpReq.offset);
	printf("  String %s<EOF>\n", req.data);
#endif

	// Get the key and IV
	BYTE * k = returnSSLKey(key);
	calcNonce((BYTE *)nonce,blockNum,(BYTE *)fileIV);

#ifdef DBG
	printb(nonce, 12, "NONCE Write for block: %d\n", blockNum );
#endif

	// NOTE: Currently there is an issue with EVP_aes_256_ocb() and in place encryption does not work
	// therefore we are using a temporary buffer!

	EVP_EncryptInit_ex(ctx_ae, NULL, NULL, k, nonce);                           // Set key/nonce
    EVP_EncryptUpdate(ctx_ae, mb.data, &outlen, tmpReq.data, (int)req.dataLen); // Encrypt plaintext
    EVP_EncryptFinal_ex(ctx_ae, mb.data+outlen, &tmplen);		                // Finalise
	
	outlen += tmplen;
    EVP_CIPHER_CTX_ctrl(ctx_ae, EVP_CTRL_AEAD_GET_TAG, 16, tag); // Get TAG
	tmpReq.data = mb.data;
	tagReq.data = tag;

	ok = true; // Assume all is well, fix this later

#ifdef DBG             
	printb(tag, 16, "Write TAG\n");
#endif DBG

	if( ok ) {
		ok = base->write( tagReq );	// Write TAG
		ok = base->write( tmpReq );	// Write data
	}
	else {
		rDebug("encodeBlock failed for block %" PRIi64 ", size %i", blockNum, req.dataLen);
		ok = false;
    }

	MemoryPool::release( mb );
    
	return ok;
}


int ACipherFileIO::truncate( off_t size )
{
    int res = 0;
	int bs  = blockSize();

	if(isZero(fileIV)) {
		// empty file.. create the header..
		if( !base->isWritable() ) {
			// open for write..
			int newFlags = lastFlags | O_RDWR;
			if( base->open( newFlags ) < 0 ) rDebug("writeHeader failed to re-open for write");
		}
		initHeader();
	}

	// can't let BlockFileIO call base->truncate(), since it would be using the wrong size..
	res = BlockFileIO::truncate( size, 0 );

	if(res == 0) {
		// Include the extra meta data, that is the header and all tags
		// In other words covert from user size to raw size
		base->truncate( map2rawOffset(size, bs));
	}
	return res;
}


bool ACipherFileIO::isWritable() const
{
    return base->isWritable();
}

