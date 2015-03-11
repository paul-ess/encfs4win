# encfs4win
encfs ported to Windows

Updated by P.Elliott, Embedded Security Solutions

Added authenticated encryption using AES-256-OCB (mainly in new file ACipherIO.cpp)
Added Yubikey support (yubikey.cpp)

AES-256-OCB is in my opinion the best and most performant AE mode. Although this is a patented technology it is free for open 
source code, GCM could also be added quite easily if needed and this is not subject to any licence.

DICLAIMER:

	My background is in security engineering with a hardware bias and whilst I have used C/C++ for algorithm modelling I cannot 
	claim to be an experience production level programmer, however I have tried my best to make reasonable updates and hope I
	haven't done anything too heinous.

	Certainly it would benefit from a wider review.

	I am a new user of GIT so appologies if I have doen anything wrong.

	NOTE: this version is very provisional and needs further testing.


Everything has been compiled on a Win7 machine using VC Express 2008, there no use of cross compilation

OCB support requires a development version of OpenSSL, 1.1.0-dev has been used
The boost version is now 1_53

YubikeyLib is required for Yubikey support

The Yubikey functionality (if enabled) currently expects an environmental variable: YK_WRAP_PATH, this points to a simple text file 
holding the Yubikey ID and an encrypted value in ASCII Hex format, e.g:

	0027fea1 0123456789abcdef0123456789abcdef

When you enter your user password it is passed through a SHA1-HMAC in the Yubikey (using a secret key in the Yubikey token) and the
resulting value is used to decrypt the RHS entry in the text file above, this is then used to decrypt the volume key. The Yubikey ID
must match the ID of the Yubikey being used. The RHS value can be any old random number, however if you want to share a volume with
another Yubikey user then you need to transcrypt it for that user. A tool to do this will be added at some point soon.


Better documentation to follow...
