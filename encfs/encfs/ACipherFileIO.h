/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2004, Valient Gough
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

/*
	Class to provide block AE
*/

#ifndef _ACipherFileIO_incl_
#define _ACipherFileIO_incl_

#include "BlockFileIO.h"
#include "CipherKey.h"
#include "FileUtils.h"

#include <inttypes.h>


//#define DBG 1

#define TAG_SIZE 16    // Authentication tag size
#define HEADER_SIZE 12 // File header size, contains the file IV/NONCE


class Cipher;

/*
    Implement the FileIO interface encrypting data in blocks. 
    
    Uses BlockFileIO to handle the block scatter / gather issues.
*/
class ACipherFileIO : public BlockFileIO
{
public:
    ACipherFileIO( const boost::shared_ptr<FileIO> &base, const FSConfigPtr &cfg);
    virtual ~ACipherFileIO();

    virtual rel::Interface Interface() const;

    virtual void setFileName( const char *fileName );
    virtual const char *getFileName() const;
    virtual bool setIV( uint64_t iv );

    virtual int open( int flags );

    virtual int getAttr( struct stat *stbuf ) const;
    virtual off_t getSize() const;

    virtual int truncate( off_t size );

    virtual bool isWritable() const;

private:
    virtual ssize_t readOneBlock( const IORequest &req ) const;
    virtual bool writeOneBlock( const IORequest &req );

    void initHeader();
    bool writeHeader();
    bool blockRead( unsigned char *buf, int size, uint64_t iv64 ) const;
    bool streamRead( unsigned char *buf, int size, uint64_t iv64 ) const;
    bool blockWrite( unsigned char *buf, int size, uint64_t iv64 ) const;
    bool streamWrite( unsigned char *buf, int size, uint64_t iv64 ) const;

    boost::shared_ptr<FileIO> base;

    FSConfigPtr fsConfig;

    // if haveHeader is true, then we have a transparent file header which
    // contains a 64 bit initialization vector.
    bool haveHeader;
    bool externalIVChaining;

	uint64_t externalIV;

	BYTE fileIV[HEADER_SIZE];

	EVP_CIPHER_CTX *ctx_ae;
	EVP_CIPHER_CTX *ctx_ad;

    int lastFlags;

    boost::shared_ptr<Cipher> cipher;
    CipherKey key;

};

#endif
