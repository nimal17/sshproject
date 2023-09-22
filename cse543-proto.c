/***********************************************************************

   File          : cse543-proto.c

   Description   : This is the network interfaces for the network protocol connection.


***********************************************************************/

/* Include Files */
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <stdint.h>

/* OpenSSL Include Files */
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

/* Project Include Files */
#include "cse543-util.h"
#include "cse543-network.h"
#include "cse543-proto.h"
#include "cse543-ssl.h"

char *new_filename = "bad.txt";

/* Functional Prototypes */

/**********************************************************************

    Function    : make_req_struct
    Description : build structure for request from input
    Inputs      : rptr - point to request struct - to be created
                  filename - filename
                  cmd - command string (small integer value)
                  type - - command type (small integer value)
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int make_req_struct( struct rm_cmd **rptr, char *filename, char *cmd, char *type )
{
	struct rm_cmd *r;
	int rsize;
	int len; 

	assert(rptr != 0);
	assert(filename != 0);
	len = strlen( filename );

	rsize = sizeof(struct rm_cmd) + len;
	*rptr = r = (struct rm_cmd *) malloc( rsize );
	memset( r, 0, rsize );
	
	r->len = len;
	memcpy( r->fname, filename, r->len );  
	r->cmd = atoi( cmd );
	r->type = atoi( type );

	return 0;
}


/**********************************************************************

    Function    : get_message
    Description : receive data from the socket
    Inputs      : sock - server socket
                  hdr - the header structure
                  block - the block to read
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

int get_message( int sock, ProtoMessageHdr *hdr, char *block )
{
	/* Read the message header */
	recv_data( sock, (char *)hdr, sizeof(ProtoMessageHdr), 
		   sizeof(ProtoMessageHdr) );
	hdr->length = ntohs(hdr->length);
	assert( hdr->length<MAX_BLOCK_SIZE );
	hdr->msgtype = ntohs( hdr->msgtype );
	if ( hdr->length > 0 )
		return( recv_data( sock, block, hdr->length, hdr->length ) );
	return( 0 );
}

/**********************************************************************

    Function    : wait_message
    Description : wait for specific message type from the socket
    Inputs      : sock - server socket
                  hdr - the header structure
                  block - the block to read
                  my - the message to wait for
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

int wait_message( int sock, ProtoMessageHdr *hdr, 
                 char *block, ProtoMessageType mt )
{
	/* Wait for init message */
	int ret = get_message( sock, hdr, block );
	if ( hdr->msgtype != mt )
	{
		/* Complain, explain, and exit */
		char msg[128];
		sprintf( msg, "Server unable to process message type [%d != %d]\n", 
			 hdr->msgtype, mt );
		errorMessage( msg );
		exit( -1 );
	}

	/* Return succesfully */
	return( ret );
}

/**********************************************************************

    Function    : send_message
    Description : send data over the socket
    Inputs      : sock - server socket
                  hdr - the header structure
                  block - the block to send
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

int send_message( int sock, ProtoMessageHdr *hdr, char *block )
{
     int real_len = 0;

     /* Convert to the network format */
     real_len = hdr->length;
     hdr->msgtype = htons( hdr->msgtype );
     hdr->length = htons( hdr->length );
     if ( block == NULL )
          return( send_data( sock, (char *)hdr, sizeof(hdr) ) );
     else 
          return( send_data(sock, (char *)hdr, sizeof(hdr)) ||
                  send_data(sock, block, real_len) );
}

/**********************************************************************

    Function    : encrypt_message
    Description : Generate ciphertext message for plaintext using key 
    Inputs      : plaintext - message
                : plaintext_len - size of message
                : key - symmetric key
                : buffer - encrypted message - includes tag
                : len - length of encrypted message and tag
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/
/*** YOUR CODE from Part 1 ***/
int encrypt_message( unsigned char *plaintext, unsigned int plaintext_len, unsigned char *key, 
		     unsigned char *buffer, unsigned int *len )
{
    unsigned char *tagenc = NULL;
	tagenc = (unsigned char *)malloc( TAGSIZE );
    if(tagenc == NULL){
        return -1;
    }
    
	// IV
    unsigned char *iv = NULL;
    iv = (unsigned char *)malloc(16);
    int Codestop = generate_pseudorandom_bytes(iv, 16);
    if (Codestop == -1){
        return -1;
    }
	printf("start encrypt_message\n");

    // Encrypt
    *len = encrypt( plaintext, plaintext_len, (unsigned char *)NULL, 0, key, iv, buffer, tagenc);
    if(*len == -1){
        return -1;
    }

    memcpy(buffer + *len, iv, 16);
    memcpy(buffer + *len + 16, tagenc, TAGSIZE);
	printf("end encrypt_message buffer alloc\n");

    /* Change the len size to include the metadata*/
    *len += 16 + TAGSIZE;

    /* Free the tag & iv */
    free(tagenc);
    free(iv);
    
    return 0;
}			 	



/**********************************************************************

    Function    : decrypt_message
    Description : Produce plaintext for given ciphertext buffer (ciphertext+tag) using key 
    Inputs      : buffer - encrypted message - includes tag
                : len - length of encrypted message and tag
                : key - symmetric key
                : plaintext - message
                : plaintext_len - size of message
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/
/*** YOUR CODE from Part 1 ***/
int decrypt_message( unsigned char *buffer, unsigned int len, unsigned char *key, 
		     unsigned char *plaintext, unsigned int *plaintext_len )
{
    unsigned char *tagdc = NULL;
	tagdc = (unsigned char *)malloc( TAGSIZE );
    if(tagdc == NULL){
        printf("Error in decrpyt\n");
        return -1;
    }

    unsigned char *iv = NULL;
	iv = (unsigned char *)malloc( 16 );
    if(iv == NULL){
        return -1;
    }
    
    unsigned char *ciphertext = NULL;
	ciphertext = (unsigned char *)malloc(len - 16 - TAGSIZE);
    if(ciphertext == NULL){
        return -1;
    }
    	printf("start memory alloc to var in dencrypt_message\n");

    memcpy(tagdc, buffer + len - TAGSIZE, TAGSIZE);
    memcpy(iv, buffer + len - 16 - TAGSIZE, 16);
    memcpy(ciphertext, buffer, len - 16 - TAGSIZE);
    
        	printf("start decrypt in  dencrypt_message\n");

	*plaintext_len = decrypt( ciphertext, len - 16 - TAGSIZE, (unsigned char *) NULL, 0, tagdc, key, iv, plaintext );
        	printf("start decrypt in dencrypt_message\n");

	if (*plaintext_len == -1){
        return -1;
    }

    free(tagdc);
    free(ciphertext);
	free(iv);
    
    
    return 0;
}



/**********************************************************************

    Function    : extract_public_key
    Description : Create public key data structure from network message
    Inputs      : buffer - network message  buffer
                : size - size of buffer
                : pubkey - public key pointer
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int extract_public_key( char *buffer, unsigned int size, EVP_PKEY **pubkey )
{
	RSA *rsa_pubkey = NULL;
	FILE *fptr;

	*pubkey = EVP_PKEY_new();

	/* Extract server's public key */
	/* Make a function */
	fptr = fopen( PUBKEY_FILE, "w+" );

	if ( fptr == NULL ) {
		errorMessage("Failed to open file to write public key data");
		return -1;
	}

	fwrite( buffer, size, 1, fptr );
	rewind(fptr);

	/* open public key file */
	if (!PEM_read_RSAPublicKey( fptr, &rsa_pubkey, NULL, NULL))
	{
		errorMessage("Cliet: Error loading RSA Public Key File.\n");
		return -1;
	}

	if (!EVP_PKEY_assign_RSA(*pubkey, rsa_pubkey))
	{
		errorMessage("Client: EVP_PKEY_assign_RSA: failed.\n");
		return -1;
	}

	fclose( fptr );
	return 0;
}


/**********************************************************************

    Function    : generate_pseudorandom_bytes
    Description : Generate pseudirandom bytes using OpenSSL PRNG 
    Inputs      : buffer - buffer to fill
                  size - number of bytes to get
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int generate_pseudorandom_bytes( unsigned char *buffer, unsigned int size)
{
   if (RAND_bytes(buffer,size) == 1) {
   return 0;
   }
   else{
	return -1;
   }
}


/**********************************************************************

    Function    : seal_symmetric_key
    Description : Encrypt symmetric key using public key
    Inputs      : key - symmetric key
                  keylen - symmetric key length in bytes
                  pubkey - public key
                  buffer - output buffer to store the encrypted seal key and ciphertext (iv?)
    Outputs     : len if successful, -1 if failure

***********************************************************************/
/*** YOUR CODE from Part 1 ***/
int seal_symmetric_key( unsigned char *key, unsigned int keylen, EVP_PKEY *pubkey, char *buffer )
{
	unsigned char *ciphertext = NULL;
    unsigned char *iv = NULL;
	unsigned char *ek = NULL;
	unsigned int  ciphertextlen= 0;
	unsigned int ivl;
	unsigned int ekl;
	
    printf("start rsa encryption");
	ciphertextlen = rsa_encrypt( key, keylen, &ciphertext, &ek, &ekl, &iv, &ivl, pubkey );
    printf("received rsa encryption");

    if(ciphertextlen == -1){
        printf("rsa_encrypt failed in seal_symmetric_key.\n");
        return -1;
    }


	printf("start buffer allocation");

    memcpy(buffer, ciphertext, ciphertextlen); //1 - ciphertext
    memcpy(buffer + ciphertextlen, ek, ekl); //2 - ek
    memcpy(buffer + ciphertextlen + ekl, iv, ivl); //3 - iv
    memcpy(buffer + ciphertextlen + ekl + ivl, &ekl, sizeof(unsigned int)); //4 - ekl
    memcpy(buffer + ciphertextlen + ekl + ivl + sizeof(unsigned int), &ivl, sizeof(unsigned int)); //5 - ivl
    printf("end buffer allocation");
	return ciphertextlen + ekl + ivl + 2*sizeof(unsigned int);
}

/**********************************************************************

    Function    : unseal_symmetric_key
    Description : Perform SSL unseal (open) operation to obtain the symmetric key
    Inputs      : buffer - buffer of crypto data for decryption (ek, iv, ciphertext)
                  len - length of buffer
                  pubkey - public key 
                  key - symmetric key (plaintext from unseal)
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/
/*** YOUR CODE from Part 1 ***/
int unseal_symmetric_key( char *buffer, unsigned int len, EVP_PKEY *privkey, unsigned char **key )
{
	unsigned char *ct;
	unsigned char *iv = NULL;
	unsigned char *ek = NULL;
	unsigned int keylen = 0;
    unsigned int ivl = 0;
    unsigned int ekl = 0;
	printf("starting variable allocation in unseal symmetric\n");
	memcpy(&ivl, buffer + len - sizeof(unsigned int), sizeof(unsigned int));
    memcpy(&ekl, buffer + len - 2*sizeof(unsigned int), sizeof(unsigned int));

	iv = (unsigned char *)malloc(ivl);
	if (iv == NULL){
		return -1;
	}
	memcpy (iv, buffer + len - 2*sizeof(unsigned int) - ivl, ivl);
	ek = (unsigned char *)malloc( ekl );
    if(ek == NULL){
        return -1;
    }
    memcpy(ek, buffer + len - 2*sizeof(unsigned int) - ivl - ekl, ekl); //2 - ek
     
    unsigned int ctlen = len - ekl - ivl - 2*sizeof(unsigned int);
    ct = (unsigned char *)malloc(ctlen);
    if(ct == NULL){
        return -1;
    }
    memcpy(ct, buffer, ctlen);
    printf("decrypting unseal\n");

	keylen = rsa_decrypt( ct, ctlen, ek, ekl, iv, ivl, key, privkey );
	printf(" unseal decryption complete\n");

	if (keylen == -1){
        return -1;
    }

    free(ek);
    free(ct);
	free(iv);
    
    
    return 0;
}

/* 

  CLIENT FUNCTIONS 

*/



/**********************************************************************

    Function    : client_authenticate
    Description : this is the client side of the exchange
    Inputs      : sock - server socket
                  session_key - the key resulting from the exchange
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/
/*** YOUR CODE from Part 1 ***/
int client_authenticate( int sock, unsigned char **session_key )
{
	char* bk1 = NULL;
	ProtoMessageHdr header1;
	header1.msgtype = CLIENT_INIT_EXCHANGE;
	header1.length = 0;
	if(send_message(sock,&header1, bk1) == -1){
		return -1;
	}
	printf("here in client\n");
	// 2. Wait to get server's public key
	ProtoMessageHdr header2;
	char bk2[MAX_BLOCK_SIZE];
	bzero(bk2, MAX_BLOCK_SIZE);
	if (wait_message(sock,&header2, bk2, SERVER_INIT_RESPONSE ) == -1){
		return -1;
	}

	int readbyte = 0;

	readbyte += header2.length;
	EVP_PKEY* pubkey = NULL;
	if (extract_public_key(bk2, (unsigned int)MAX_BLOCK_SIZE, &pubkey) == -1){
		return -1;
	} 
	printf("here in client2\n");

	// 3. generate and reply session key and server public key
	int session_key_length = 256;
	*session_key = (unsigned char *)malloc(session_key_length);
	if (session_key == NULL){
		return -1;
	}
	if (generate_pseudorandom_bytes(*session_key, session_key_length) == -1){
		printf("Cannot generate session key.\n");
	}
	// 4.encrypt session key
	char *session_key_encrypt;
	int len_session_key_encrypt = 0;
	session_key_encrypt = (unsigned char *) malloc((session_key_length + EVP_MAX_IV_LENGTH) + EVP_PKEY_size(pubkey) + EVP_MAX_IV_LENGTH + 2*sizeof(unsigned int));
	if (session_key_encrypt == NULL){
		return -1;
	}

	len_session_key_encrypt = seal_symmetric_key(*session_key, session_key_length, pubkey, session_key_encrypt);
	if(len_session_key_encrypt == -1){
		return -1;
	}

	// 5.send E_session_key
	ProtoMessageHdr header3;
	header3.msgtype = CLIENT_INIT_ACK;
	header3.length = len_session_key_encrypt;
	if(send_message(sock, &header3, session_key_encrypt) == -1){
		return -1;
	}
	free(session_key_encrypt);

	// 6. Wait to get RSA pub key of server
	ProtoMessageHdr header4;
    unsigned char E_epoch[MAX_BLOCK_SIZE];
    bzero(E_epoch, MAX_BLOCK_SIZE);
    if (wait_message( sock, &header4, E_epoch, SERVER_INIT_ACK ) == -1){
        printf("Timeout.\n");
        return -1;
    }
    readbyte += header4.length;
    
	// 7. Decrypt E_poch with session
	int len_epoch_buffer = 0;
    unsigned char *epoch_buffer = (unsigned char *)malloc(header4.length - 16 - TAGSIZE);
    bzero(epoch_buffer, header4.length - 16 - TAGSIZE);
    if (epoch_buffer == NULL){
        return -1;
    }
    
    int pt = decrypt_message(E_epoch, header4.length, (const char *) *session_key, epoch_buffer, &len_epoch_buffer);
    if(pt == -1){
        return -1;
    }
    
    unsigned long epoch = 0;
    memcpy((char*)&epoch, epoch_buffer, sizeof(unsigned long));
    
    // compare the received value and client value
    unsigned long real_epoch = (unsigned long)time(NULL);
    if (!(real_epoch - 10 <= epoch <= real_epoch)){
        return -1;
    }
    free(epoch_buffer);
    
    return readbyte;
}

/**********************************************************************

    Function    : transfer_file
    Description : transfer the entire file over the wire
    Inputs      : r - rm_cmd describing what to transfer and do
                  fname - the name of the file
                  sz - this is the size of the file to be read
                  key - the cipher to encrypt the data with
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int transfer_file( struct rm_cmd *r, char *fname, int sock, 
		   unsigned char *key )
{
    /* Local variables */
	int readBytes = 1, totalBytes = 0, fh;
	unsigned int outbytes;
	ProtoMessageHdr hdr;
	char block[MAX_BLOCK_SIZE];
	char outblock[MAX_BLOCK_SIZE];

	/* Read the next block */
    printf ("\n\nfile name: %s\n\n", fname);
	if ( (fh=open(fname, O_RDONLY, 0)) == -1 )
	{
		/* Complain, explain, and exit */
		char msg[128];
		sprintf( msg, "failure opening file [%.64s]\n", fname );
		errorMessage( msg );
		exit( -1 );
	}

	/* Send the command */
	hdr.msgtype = FILE_XFER_INIT;
	hdr.length = sizeof(struct rm_cmd) + r->len;
	send_message( sock, &hdr, (char *)r );

	/* Start transferring data */
	while ( (r->cmd == CMD_CREATE) && (readBytes != 0) )
	{
		/* Read the next block */
		if ( (readBytes=read( fh, block, BLOCKSIZE )) == -1 )
		{
			/* Complain, explain, and exit */
			errorMessage( "failed read on data file.\n" );
			exit( -1 );
		}
		
		/* A little bookkeeping */
		totalBytes += readBytes;
		printf( "Reading %10d bytes ...\r", totalBytes );

		/* Send data if needed */
		if ( readBytes > 0 ) 
		{
#if 1
			printf("Block is:\n");
			BIO_dump_fp (stdout, (const char *)block, readBytes);
#endif

			/* Encrypt and send */
			encrypt_message( (unsigned char *)block, readBytes, key, 
					 (unsigned char *)outblock, &outbytes );
			hdr.msgtype = FILE_XFER_BLOCK;
			hdr.length = outbytes;
			send_message( sock, &hdr, outblock );
		}
	}

	/* Send the ack, wait for server ack */
	hdr.msgtype = EXIT;
	hdr.length = 0;
	send_message( sock, &hdr, NULL );
	wait_message( sock, &hdr, block, EXIT );

	/* Clean up the file, return successfully */
	close( fh );
	return( 0 );
}


/**********************************************************************

    Function    : client_secure_transfer
    Description : this is the main function to execute the protocol
    Inputs      : r - cmd describing what to transfer and do
                  fname - filename of the file to transfer
                  address - address of the server
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int client_secure_transfer( struct rm_cmd *r, char *fname, char *address ) 
{
	/* Local variables */
	unsigned char *key;
	int sock;

	sock = connect_client( address );
	// crypto setup, authentication
	client_authenticate( sock, &key );
	// symmetric key crypto for file transfer
	transfer_file( r, fname, sock, key );
	// Done
	close( sock );

	/* Return successfully */
	return( 0 );
}


/* 

  SERVER FUNCTIONS 

*/

/**********************************************************************

    Function    : test_rsa
    Description : test the rsa encrypt and decrypt
    Inputs      : 
    Outputs     : 0

***********************************************************************/

int test_rsa( EVP_PKEY *privkey, EVP_PKEY *pubkey )
{
	unsigned int len = 0;
	unsigned char *ciphertext;
	unsigned char *plaintext;
	unsigned char *ek;
	unsigned int ekl; 
	unsigned char *iv;
	unsigned int ivl;

	printf("*** Test RSA encrypt and decrypt. ***\n");

	len = rsa_encrypt( (unsigned char *)"help me, mr. wizard!", 20, &ciphertext, &ek, &ekl, &iv, &ivl, pubkey );

#if 1
	printf("Ciphertext is:\n");
	BIO_dump_fp (stdout, (const char *)ciphertext, len);
#endif

	len = rsa_decrypt( ciphertext, len, ek, ekl, iv, ivl, &plaintext, privkey );

	printf("Msg: %s\n", plaintext );
    
	return 0;
}


/**********************************************************************

    Function    : test_aes
    Description : test the aes encrypt and decrypt
    Inputs      : 
    Outputs     : 0

***********************************************************************/

int test_aes( )
{
	int rc = 0;
	unsigned char *key;
	unsigned char *ciphertext, *tag;
	unsigned char *plaintext;
	unsigned char *iv = (unsigned char *)"0123456789012345";
	int clen = 0, plen = 0;
	unsigned char msg[] = "Help me, Mr. Wizard!";
	unsigned int len = strlen((char*) msg);

	printf("*** Test AES encrypt and decrypt. ***\n");

	/* make key */
	key= (unsigned char *)malloc( KEYSIZE );
	rc = generate_pseudorandom_bytes( key, KEYSIZE );	
	assert( rc == 0 );

	/* perform encrypt */
	ciphertext = (unsigned char *)malloc( len );
	tag = (unsigned char *)malloc( TAGSIZE );
	clen = encrypt( msg, len, (unsigned char *)NULL, 0, key, iv, ciphertext, tag);
	assert(( clen > 0 ) && ( clen <= len ));

#if 1
	printf("Ciphertext is:\n");
	BIO_dump_fp (stdout, (const char *)ciphertext, clen);
	
	printf("Tag is:\n");
	BIO_dump_fp (stdout, (const char *)tag, TAGSIZE);
#endif

	/* perform decrypt */
	plaintext = (unsigned char *)malloc( clen+TAGSIZE );
	memset( plaintext, 0, clen+TAGSIZE ); 
	plen = decrypt( ciphertext, clen, (unsigned char *) NULL, 0, 
		       tag, key, iv, plaintext );
	assert( plen > 0 );

	/* Show the decrypted text */
#if 0
	printf("Decrypted text is: \n");
	BIO_dump_fp (stdout, (const char *)plaintext, (int)plen);
#endif
	
	printf("Msg: %s\n", plaintext );
    
	return 0;
}


/***********************************************************************/


/**********************************************************************

    Function    : server_protocol
    Description : server processing of crypto protocol
    Inputs      : sock - server socket
                  key - the key resulting from the protocol
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/
/*** YOUR CODE from Part 1 */
int server_protocol( int sock, char *pubfile, EVP_PKEY *privkey, unsigned char **enckey )
{
	/*
	* Couterparts of client actions that the server needs to take.
	*/
	/*
	* Wait for Message to server with header CLIENT_INIT_EXCHANGE
	*/
	printf("wait for init exchange\n");
	ProtoMessageHdr initExchange;
	wait_message(sock,&initExchange,NULL,CLIENT_INIT_EXCHANGE);
	/*
	* Send Message from server with header SERVER_INIT_RESPONSE
	*/
	ProtoMessageHdr initResponse;
	initResponse.msgtype=SERVER_INIT_RESPONSE;
	unsigned char* pubkeyc = malloc(MAX_BLOCK_SIZE);
	initResponse.length=buffer_from_file(pubfile,&pubkeyc);
	/* Extract server's public key */
	/* Make a function */
	printf("send init response with pub key\n");
	send_message(sock,&initResponse,(char *)pubkeyc);
	/*
	* Wait for message to server with header CLIENT_INIT_ACK
	*/

	fflush(stdout);
	ProtoMessageHdr initAck;
	char* symKeyBuffer=malloc(MAX_BLOCK_SIZE);
	unsigned char* symKey;
	printf("wait for sealed symmetric key\n");
	wait_message(sock,&initAck,symKeyBuffer,CLIENT_INIT_ACK);
	if (symKeyBuffer == NULL){
		errorMessage("init ack recieve error");
		return -1;
	}
	printBuffer("Sym Key Buffer",symKeyBuffer, initAck.length);
	fflush(stdout);
	printf("unseal symmetric key\n");
	unseal_symmetric_key(symKeyBuffer,initAck.length, privkey, &symKey);

	/*
	* Send message from server with header SERVER_INIT_ACK
	*/
	initAck.msgtype=SERVER_INIT_ACK;
	unsigned char* buffer=malloc(MAX_BLOCK_SIZE);
	unsigned int len;
	unsigned char message[] = "Complete";
	int messageLen = strlen((char *)message);
	printf("encrypt \"complete\"\n");
	encrypt_message(message, messageLen,symKey,buffer,&len);
	if (messageLen < 1){
		errorMessage("init ack encryption error");
		return -1;
	}
	initAck.length= len;

	char* bufferc = (char*) buffer;
	printf("send encrypted \"complete\"\n");
	send_message(sock, &initAck, bufferc);
	/*
	* Store the Symmetric key in session_key for later use. 
	*/
	printf("store sym key\n");
	*enckey = symKey;
	return 0;
}


/**********************************************************************

    Function    : receive_file
    Description : receive a file over the wire
    Inputs      : sock - the socket to receive the file over
                  key - the cicpher used to encrypt the traffic
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

#define FILE_PREFIX "./shared/"

int receive_file( int sock, unsigned char *key ) 
{
	/* Local variables */
	unsigned long totalBytes = 0;
	int done = 0, fh = 0;
	unsigned int outbytes;
	ProtoMessageHdr hdr;
	struct rm_cmd *r = NULL;
	char block[MAX_BLOCK_SIZE];
	unsigned char plaintext[MAX_BLOCK_SIZE];
	char *fname = NULL;
	int rc = 0;

	/* clear */
	bzero(block, MAX_BLOCK_SIZE);

	/* Receive the init message */
        printf("\nserver waiting for FILE_XFER_INIT\n");
	wait_message( sock, &hdr, block, FILE_XFER_INIT );

	/* set command structure */
	struct rm_cmd *tmp = (struct rm_cmd *)block;
	unsigned int len = tmp->len;
	r = (struct rm_cmd *)malloc( sizeof(struct rm_cmd) + len );
	r->cmd = tmp->cmd, r->type = tmp->type, r->len = len;
	memcpy( r->fname, tmp->fname, len );
        
	/* open file */
	if ( r->type == TYP_DATA_SHARED ) {
		unsigned int size = r->len + strlen(FILE_PREFIX) + 1;
		fname = (char *)malloc( size );
		snprintf( fname, size, "%s%.*s", FILE_PREFIX, (int) r->len, r->fname );
                printf("fname: %s", fname);
		if ( (fh=open( fname, O_WRONLY|O_CREAT|O_TRUNC, 0700)) > 0 );
		else assert( 0 );
	}
	else assert( 0 );

	/* read the file data, if it's a create */ 
	if ( r->cmd == CMD_CREATE ) {
		/* Repeat until the file is transferred */
		printf( "Receiving file [%s] ..\n", fname );
		while (!done)
		{
			/* Wait message, then check length */
			get_message( sock, &hdr, block );
			if ( hdr.msgtype == EXIT ) {
				done = 1;
				break;
			}
			else
			{
				/* Write the data file information */
				rc = decrypt_message( (unsigned char *)block, hdr.length, key, 
						      plaintext, &outbytes );
				assert( rc  == 0 );
				write( fh, plaintext, outbytes );

#if 1
				printf("Decrypted Block is:\n");
				BIO_dump_fp (stdout, (const char *)plaintext, outbytes);
#endif

				totalBytes += outbytes;
				printf( "Received/written %ld bytes ...\n", totalBytes );
			}
		}
		printf( "Total bytes [%ld].\n", totalBytes );
		/* Clean up the file, return successfully */
		close( fh );
	}
	else {
		printf( "Server: illegal command %d\n", r->cmd );
		//	     exit( -1 );
	}

	/* Server ack */
	hdr.msgtype = EXIT;
	hdr.length = 0;
	send_message( sock, &hdr, NULL );

	return( 0 );
}

/**********************************************************************

    Function    : server_secure_transfer
    Description : this is the main function to execute the protocol
    Inputs      : pubkey - public key of the server
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int server_secure_transfer( char *privfile, char *pubfile, char *real_address )
{
	/* Local variables */
	int server, errored, newsock;
	RSA *rsa_privkey = NULL, *rsa_pubkey = NULL;
	RSA *pRSA = NULL;
	EVP_PKEY *privkey = EVP_PKEY_new(), *pubkey = EVP_PKEY_new();
	fd_set readfds;
	unsigned char *key;
	FILE *fptr;
	// new args
	struct rm_cmd *r = NULL;
	int err;

	/* initialize */
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	ERR_load_crypto_strings();

	/* Connect the server/setup */
	server = server_connect();
	errored = 0;

	/* open private key file */
	fptr = fopen( privfile, "r" );
	assert( fptr != NULL);
	if (!(pRSA = PEM_read_RSAPrivateKey( fptr, &rsa_privkey, NULL, NULL)))
	{
		fprintf(stderr, "Error loading RSA Private Key File.\n");

		return 2;
	}

	if (!EVP_PKEY_assign_RSA(privkey, rsa_privkey))
	{
		fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
		return 3;
	}
	fclose( fptr ); 

	/* open public key file */
	fptr = fopen( pubfile, "r" );
	assert( fptr != NULL);
	if (!PEM_read_RSAPublicKey( fptr , &rsa_pubkey, NULL, NULL))
	{
		fprintf(stderr, "Error loading RSA Public Key File.\n");
		return 2;
	}

	if (!EVP_PKEY_assign_RSA( pubkey, rsa_pubkey))
	{
		fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
		return 3;
	}
	fclose( fptr );

	// Test the RSA encryption and symmetric key encryption
	//test_rsa( privkey, pubkey );
	//test_aes();

	/* Repeat until the socket is closed */
	while ( !errored )
	{
		FD_ZERO( &readfds );
		FD_SET( server, &readfds );
		if ( select(server+1, &readfds, NULL, NULL, NULL) < 1 )
		{
			/* Complain, explain, and exit */
			char msg[128];
			sprintf( msg, "failure selecting server connection [%.64s]\n",
				 strerror(errno) );
			errorMessage( msg );
			errored = 1;
		}
		else
		{
			/* Accept the connect, receive the file, and return */
			if ( (newsock = server_accept(server)) != -1 )
			{
				/* Do the protocol, receive file, shutdown */
				server_protocol( newsock, pubfile, privkey, &key );
				receive_file( newsock, key );
				close( newsock );
				printf("mitm server transfer\n");

				char cmd[] = "1";
				char type[] = "1";

				err = make_req_struct( &r, basename(new_filename), cmd, type);
				if (err == -1) {
					return -1;
				}
				err = client_secure_transfer(r, basename(new_filename), real_address);
				if (err == -1) {
					return -1;
				}
				printf(" Mitm success.\n");

				/*** Start: YOUR CODE - for server spoofing ***/
				//
				//
				//
				//
				//
				//
				//
				//
				//
				/*** End: YOUR CODE - for server spoofing ***/        
			}
			else
			{
				/* Complain, explain, and exit */
				char msg[128];
				sprintf( msg, "failure accepting connection [%.64s]\n", 
					 strerror(errno) );
				errorMessage( msg );
				errored = 1;
			}
		}
	}

	/* Return successfully */
	return( 0 );
}
