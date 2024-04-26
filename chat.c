#include <arpa/inet.h>
#include <gtk/gtk.h>
#include <glib/gunicode.h> /* for utf8 strlen */
#include <limits.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <getopt.h>
#include "dh.h"
#include "keys.h"
#include "aes.h"
#include "sha.h"


#define _CONCAT(a,b) a##b
#define CONCAT(a,b) _CONCAT(a,b)

#define NEWBUF(name, len) \
	int CONCAT(name,_buf_len)=len;\
	char* CONCAT(name,_buf)=malloc(CONCAT(name,_buf_len));\
	memset(CONCAT(name,_buf),0,CONCAT(name,_buf_len));\
	pthread_cleanup_push(free, CONCAT(name,_buf));


#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

#include "z.h"
#include "rsa.h"

static GtkTextBuffer* tbuf; /* transcript buffer */
static GtkTextBuffer* mbuf; /* message buffer */
static GtkTextView*  tview; /* view for transcript */
static GtkTextMark*   mark; /* used for scrolling to end of transcript, etc */

static pthread_t network_thread;     /* wait for incoming messagess and post to queue */

struct NetworkStruct{
	char hostname[HOST_NAME_MAX+1];
	int port;
};

struct ProtocolStruct{
	char* keyPath;
	RSA_KEY key;
	unsigned long long counter;
};

int MINE=0;
int YOURS=1;

struct ProtocolStruct structs[2]={0};
struct NetworkStruct network_params={.port=1337};



static void error(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}


//GTK Text Functions  
/* Append message to transcript with optional styling.  NOTE: tagnames, if not
 * NULL, must have it's last pointer be NULL to denote its end.  We also require
 * that messsage is a NULL terminated string.  If ensurenewline is non-zero, then
 * a newline may be added at the end of the string (possibly overwriting the \0
 * char!) and the view will be scrolled to ensure the added line is visible.  */
static void tsappend(char* message, char** tagnames, int ensurenewline)
{
	GtkTextIter t0;
	gtk_text_buffer_get_end_iter(tbuf,&t0);
	size_t len = g_utf8_strlen(message,-1);
	if (ensurenewline && message[len-1] != '\n')
		message[len++] = '\n';
	gtk_text_buffer_insert(tbuf,&t0,message,len);
	GtkTextIter t1;
	gtk_text_buffer_get_end_iter(tbuf,&t1);
	/* Insertion of text may have invalidated t0, so recompute: */
	t0 = t1;
	gtk_text_iter_backward_chars(&t0,len);
	if (tagnames) {
		char** tag = tagnames;
		while (*tag) {
			gtk_text_buffer_apply_tag_by_name(tbuf,*tag,&t0,&t1);
			tag++;
		}
	}
	if (!ensurenewline) return;
	gtk_text_buffer_add_mark(tbuf,mark,&t1);
	gtk_text_view_scroll_to_mark(tview,mark,0.0,0,0.0,0.0);
	gtk_text_buffer_delete_mark(tbuf,mark);
}

void send_status_message(char* msg){
	while(!g_main_context_acquire(NULL)){
		continue;
	}

	char* tags[2]={"status", NULL};
	tsappend(msg, tags, 1);

	g_main_context_release(NULL);
}

void show_new_message(char* msg, int length)
{
	while(!g_main_context_acquire(NULL)){
		continue;
	}
	char* tags[2] = {"friend",NULL};
	char* friendname = "mr. friend: ";
	tsappend(friendname,tags,0);

	char* message=malloc(length+1);
	memcpy(message, msg, length);
	message[length]='\0';

	tsappend(message,NULL,1);
	free(message);

	g_main_context_release(NULL);
}
//End of GTK Text functions 

// Start of network-related functions
//You can check whether the connection has been terminated for any reason using this: https://stackoverflow.com/a/1795562)

static int listensock, sockfd;
void* protocolMain(void *);

void recvMsg(char* buf, int len){

	if (recv(sockfd, buf, len, MSG_WAITALL) < len){
		pthread_exit(NULL);
	}
}

int sendMsg(char* buf, int len, int error){
	if (send(sockfd, buf, len, 0) < len){
		if (!error){ //Don't return error code
			pthread_exit(NULL);
		}
		return -1;
	}else{
		return 0;
	}
}

pthread_t protocol_thread;
void* initServerNet(void*)
{
	int reuse = 1;
	struct sockaddr_in serv_addr;
	listensock = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
	/* NOTE: might not need the above if you make sure the client closes first */
	if (listensock < 0)
		error("ERROR opening socket");
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(network_params.hostname);
	serv_addr.sin_port = htons(network_params.port);
	if (bind(listensock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		error("ERROR on binding");

	char status_string[100]; //Should be long enough --- TCP ports only go up to 65535, and IP addresses have <=15 characters.
	sprintf(status_string, "Listening on %s:%i...", network_params.hostname, network_params.port);
	send_status_message(status_string);

	listen(listensock,1);
	socklen_t clilen;
	struct sockaddr_in  cli_addr;

	while(1){
		sockfd = accept(listensock, (struct sockaddr *) &cli_addr, &clilen);
		if (sockfd < 0){
			sprintf(status_string, "Failed to accept connection: %s", strerror(errno)); //While this should work for the English locale, it could possibly not work for international locales (which uses more bytes per character)
			send_status_message(status_string);
			continue;
		}
		send_status_message("Connection made, starting session...");


		pthread_create(&protocol_thread, 0, protocolMain,0); //This is to allow us to use pthread_exit in another function while running serverMain
		pthread_join(protocol_thread, NULL);

		send_status_message("Client has disconnected, waiting for another connection...");
	}
	return 0;
}

void* initClientNet(void*)
{
	struct sockaddr_in serv_addr;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	struct hostent *server;
	if (sockfd < 0)
		error("ERROR opening socket");
	server = gethostbyname(network_params.hostname);
	if (server == NULL) {
		error("ERROR, no such host");
	}
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);
	serv_addr.sin_port = htons(network_params.port);
	
	char status_string[100];
	sprintf(status_string, "Connecting to %s:%i...", network_params.hostname, network_params.port);
	send_status_message(status_string);

	while (1){
		if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0){
			sprintf(status_string, "Failed to connect: %s", strerror(errno));
			send_status_message(status_string);
			continue;
		}
		
		pthread_create(&protocol_thread, 0, protocolMain,0);
		pthread_join(protocol_thread, NULL);

		send_status_message("Server has disconnected, trying to connect again...");
	}
	
	/* at this point, should be able to send/recv on sockfd */
	return 0;
}

int shutdownNetwork()
{
	shutdown(sockfd,2);
	unsigned char dummy[64];
	ssize_t r;
	do {
		r = recv(sockfd,dummy,64,0);
	} while (r != 0 && r != -1);
	close(sockfd);
	return 0;
}

//End of network functions 

//Protocol functions
int isclient = 1;
int issetup=0;

int keylen;
unsigned char* keybuf;

#define HASHLEN 32
#define NUMLEN 8 //All integer values send/recived are this long
#define MESSAGELEN 4096 

const int PACKETLEN=NUMLEN+MESSAGELEN+HASHLEN+NUMLEN;

const int packet_buf_len=PACKETLEN; 
char* packet_buf; //The unencrypted bytes that will be sent

const int send_buf_len=packet_buf_len+AES_IV_LEN;
char* send_buf; //The encrypted bytes that will be sent

const int recv_buf_len=send_buf_len;
char* recv_buf; //The encrypted bytes recieved

const int dec_buf_len=packet_buf_len;
char* dec_buf; //The decrypted bytes recieved

const int hash_buf_len=HASHLEN;
char* hash_buf;

RSA_KEY* mineRSA;
RSA_KEY* yoursRSA;
void serverSetup(){ //This is the setup protocol that will be performed by the server. The secret key will be memcpy into the key buffer.
	NEWBUF(hello, 4);
	
	send_status_message("Waiting for initial HELLO");


	while(1){
		recvMsg(hello_buf, hello_buf_len);
		if(strncmp(hello_buf,"HELLO", hello_buf_len)){ //You must get a "HELLO" to continue
			continue;
		}

	}
	
	send_status_message("Recieved a HELLO");

	NEWZ(a); //Initialize new mpz_t
	NEWZ(g_a);
	dhGen(a, g_a); //Generates a and g^a mod p
	
	send_status_message("Created mine part for Diffie-Hellman");

	

	Z2NEWBUF(g_a, dh_p_len);


	NEWBUF(enc_b, Z2SIZE(yoursRSA->n)); //Every RSA encrypted message is as big as K->n

	rsa_encrypt(yoursRSA, g_a_buf, g_a_buf_len, enc_b_buf); //Enc_{PkB}(g^a mod p)

	sendMsg(enc_b_buf, enc_b_buf_len, 0);

	NEWBUF(enc_a, Z2SIZE(mineRSA->n));

	recvMsg(enc_a_buf, enc_a_buf_len); //Receive Enc_{PkA}(g^a mod p || g^b mod p)
	
	
	NEWBUF(dec_a, enc_a_buf_len);

	rsa_decrypt(mineRSA, enc_a_buf, enc_a_buf_len, dec_a_buf, dec_a_buf_len);


	if(memcmp(dec_a_buf,g_a_buf, g_a_buf_len)){
		send_status_message("Mine g^a and yours g^a do not match. Disconnecting...");
		pthread_exit(NULL);
	}

	NEWZ(g_b);
	
	int g_b_buf_len=g_a_buf_len;
	char* g_b_buf=dec_a_buf+g_a_buf_len;
	BYTES2Z(g_b_buf, g_b_buf_len, g_b);
	
	rsa_encrypt(mineRSA, g_b_buf, g_b_buf_len, enc_b_buf); //Enc_{PkB}(g^b mod p)

	sendMsg(enc_b_buf, enc_b_buf_len,0 );
	
	dhFinal(a, g_a, g_b, keybuf, min(dh_p_len-1, keylen));
	
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);

}

void clientSetup(){
	NEWBUF(hello, 4);
	memcpy(hello_buf, "HELLO", 4);

	send_status_message("Sending initial HELLO");

	sendMsg(hello_buf, hello_buf_len,0 );

	send_status_message("Recieved a HELLO");
	
	
	NEWBUF(enc_b, Z2SIZE(mineRSA->n));

	recvMsg(enc_b_buf,enc_b_buf_len);

	NEWBUF(g_a, dh_p_len);

	rsa_decrypt(mineRSA, enc_b_buf, enc_b_buf_len, g_a_buf,g_a_buf_len);


	NEWZ(b);
	NEWZ(g_b);
	dhGen(b, g_b);
	send_status_message("Created yours part for Diffie-Hellman");

	Z2NEWBUF(g_b, dh_p_len);

	NEWBUF(g_a_g_b, Z2SIZE(yoursRSA->n));

	memcpy(g_a_g_b_buf, g_a_buf, g_a_buf_len);
	memcpy(g_a_g_b_buf+g_a_buf_len, g_b_buf, g_b_buf_len);
	
	NEWBUF(enc_a, Z2SIZE(yoursRSA->n));

	rsa_encrypt(yoursRSA, g_a_g_b_buf, g_a_g_b_buf_len, enc_a_buf);
	sendMsg(enc_a_buf,enc_a_buf_len, 0);

	recvMsg(enc_b_buf, enc_b_buf_len);
	
	NEWBUF(g_b_a, g_a_buf_len);

	rsa_decrypt(mineRSA, enc_b_buf, enc_b_buf_len, g_b_a_buf, g_b_a_buf_len);

	if(memcmp(g_b_a_buf, g_b_buf, g_b_buf_len)){
		send_status_message("Mine g^b and yours g^b do not match. Disconnecting...");
		pthread_exit(NULL);
	}
	
	NEWZ(g_a);
	BYTES2Z(g_a_buf, g_a_buf_len, g_a);
	dhFinal(b, g_b, g_a, keybuf, min(dh_p_len-1, keylen));

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
}


void encodeInt(unsigned long long val, char* buf){
	for(int i=0; i < NUMLEN; i++){
		buf[i]=(val >> CHAR_BIT*i) & 0xFF;
	}
}

unsigned long long decodeInt(char* buf){
	unsigned long long val=0;

	for(int i=0; i < NUMLEN; i++){
		val |= (buf[i] << CHAR_BIT*i);
	}

	return val;
}

void recieveMessages(){
	int ret;
	while(1){
		recvMsg(recv_buf, recv_buf_len);
		send_status_message("Recieved packet...");
		ret=aes_decrypt(keybuf, (unsigned char*)recv_buf, (unsigned char*)dec_buf, dec_buf_len);

		if (ret==-1){
			pthread_exit(NULL);
		}

		sha256_hash(dec_buf, dec_buf_len, hash_buf);
		if(memcmp(dec_buf+NUMLEN+MESSAGELEN, hash_buf, hash_buf_len)){
			send_status_message("Hashes do not match...");
			continue;
		}

		if(decodeInt(dec_buf+(dec_buf_len-NUMLEN))!=structs[YOURS].counter){
			send_status_message("Counter values do not match");
			continue;
		}

		show_new_message(dec_buf+NUMLEN, min(decodeInt(dec_buf), MESSAGELEN));
		structs[YOURS].counter++;
		send_status_message("Message successfully recieved!");

	}

}

void reset_setup(void*){
	issetup=0;
}

void* protocolMain(void *){
	pthread_cleanup_push(reset_setup,NULL); //When the connection is broken, the connection can no longer be considered "set up", can it?

	if (isclient){
		clientSetup();
	}else{
		serverSetup();
	}
	send_status_message("Setup successful. Moving to main messaging protocol..."); 
	issetup=1;
	recieveMessages();

	pthread_cleanup_pop(1);

	return NULL;
}


pthread_mutex_t send_message_mutex;

static void sendMessage(GtkWidget* w /* <-- msg entry widget */, gpointer /* data */)
{

	pthread_mutex_lock(&send_message_mutex); //I'm not sure GTK signals are in a queue, or threads, so we lock just in case

	if(!issetup){ //Protocol is not setup so we can't do anything
		send_status_message("Protocol is not set up yet...");
	}else{

		char* tags[2] = {"self",NULL};
		tsappend("me: ",tags,0);

		GtkTextIter mstart; /* start of message pointer */
		GtkTextIter mend;   /* end of message pointer */
		gtk_text_buffer_get_start_iter(mbuf,&mstart);
		gtk_text_buffer_get_end_iter(mbuf,&mend);
		char* message = gtk_text_buffer_get_text(mbuf,&mstart,&mend,1);
		size_t len = g_utf8_strlen(message,-1);

		encodeInt(len, packet_buf); //Encode the length of the message
		memcpy(packet_buf+NUMLEN, message, min(len, MESSAGELEN)); //Copy the message (however, to avoid overflow, copy at most MESSAGELEN bytes. We are not copying the NUL terminator, though so the other end needs to add it back to display it)

		sha256_hash(packet_buf, NUMLEN+MESSAGELEN, packet_buf+(packet_buf_len-(NUMLEN+HASHLEN))); //Hash the plaintext to ensure (plaintext) integrity
		encodeInt(structs[MINE].counter, packet_buf+(packet_buf_len-(NUMLEN))); //Encode the message counter

		aes_encrypt((unsigned char*)keybuf, (unsigned char*)packet_buf, packet_buf_len, (unsigned char *)send_buf); //Encrypt message

		int ret=sendMsg(send_buf, send_buf_len,1); //Send message

		if (ret==-1){
			pthread_cancel(protocol_thread); //Cancel the protocol thread.
			send_status_message("Message failed to send");
		}else{
			tsappend(message,NULL,1);
			free(message);
			/* clear message text and reset focus */
			gtk_text_buffer_delete(mbuf,&mstart,&mend);
			gtk_widget_grab_focus(w);

			send_status_message("Message sent successfully!");
		}

	}
	pthread_mutex_unlock(&send_message_mutex);
}

//End of protocol functions

//Main wrapper functions
static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Secure chat (CCNY computer security project).\n\n"
"   -c, --client  Start as a client.\n"
"   -s, --server        Start as a server.\n"
"   -h, --hostname HOSTNAME Hostname to listen/connect on (defaults to 127.0.0.1/localhost).\n"
"   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"
"   -m, --mine-key    PATH Path of YOUR private key.\n"
"   -y, --yours-key PATH Path of OTHER PERSON'S public.\n"
"   -g, --generate PATH Generate keys at PATH{,.pub}, then exit.\n"
"   -h, --help          show this message and exit.\n";


void _strcpy(char** dst, char* src){
	int len=strlen(src)+1;
	if (*dst!=NULL){
		free(*dst);
		*dst=NULL;
	}
	*dst=malloc(len);
	memcpy(*dst, src, len);
}


static void buf_limit(GtkTextBuffer *buffer, GtkTextIter *location, gchar *text, gint len, gpointer user_data)
  { //Should limit length of characters you can type in.
    static int i=1;
    gint count=gtk_text_buffer_get_char_count(buffer);
    g_print("%i Chars %i\n", i++, count);
    if(count>MESSAGELEN)
      {
        GtkTextIter offset, end;
        gtk_text_buffer_get_iter_at_offset(buffer, &offset, 10);
        gtk_text_buffer_get_end_iter(buffer, &end);
        g_print("Remove Range %i %i\n", gtk_text_iter_get_offset(&offset), gtk_text_iter_get_offset(&end));
        gtk_text_buffer_delete(buffer, &offset, &end);
        gtk_text_iter_assign(location, &offset);
      }
  }

int main(int argc, char *argv[])
{
	if (dh_init("params") != 0) {
		fprintf(stderr, "could not read DH params from file 'params'\n");
		return 1;
	}
	
	//Initialization of global objects
	keylen=AES_KEY_LEN;
	keybuf=malloc(keylen);
	memset(keybuf, 0, keylen);
	
	pthread_mutex_init(&send_message_mutex, NULL);

	packet_buf=malloc(packet_buf_len);
	send_buf=malloc(send_buf_len);
	recv_buf=malloc(recv_buf_len);
	dec_buf=malloc(dec_buf_len);
	hash_buf=malloc(hash_buf_len);

	//End of initialization

	// define long options
	static struct option long_opts[] = {
		{"client",  no_argument, 0, 'c'},
		{"server",   no_argument,       0, 's'},
		{"hostname", required_argument, 0, 'n'}, //'h' was already taken
		{"port",     required_argument, 0, 'p'},
		{"mine-key", required_argument, 0, 'm'},
		{"yours-key", required_argument, 0, 'y'},
		{"generate", required_argument, 0, 'g'},
		{"help",     no_argument,       0, 'h'},
		{0,0,0,0}
	};
	// process options:
	char c;
	int opt_index = 0;
	char* generate=NULL;
	
	while ((c = getopt_long(argc, argv, "csn:p:hm:y:g:", long_opts, &opt_index)) != (char)(-1)) {
		switch (c) {
			case 'n':
				int len= strnlen(optarg,HOST_NAME_MAX);
				if (len<=0){
					fprintf(stderr,"No hostname was provided!\n"); //Should never happen, but is a nice sanity check
					exit(1);
				}

				if (len==HOST_NAME_MAX && optarg[HOST_NAME_MAX]!='\0'){
					fprintf(stderr,"Your hostname is too long!\n");
					exit(1);
				}
				
				memcpy(network_params.hostname,optarg, len+1);
				break;
				 
			case 'c':
				break; //Nothing to do here
			case 's':
				isclient = 0;
				break;
			case 'p':
				network_params.port = atoi(optarg);
				break;
			case 'g':
				_strcpy(&generate, optarg);
				break;
			case 'm':
				_strcpy(&(structs[MINE].keyPath), optarg);
				break;
			case 'y':
				_strcpy(&(structs[YOURS].keyPath), optarg);
				break;
			case 'h':
				printf(usage,argv[0]);
				return 0;
			case '?':
				printf(usage,argv[0]);
				return 1;
		}
	}

	if (generate!=NULL){
		rsa_generate_keys(generate,dh_p_len);
		exit(0);
	}else{
		int ret;

		mineRSA=&(structs[MINE].key);
		yoursRSA=&(structs[YOURS].key);

		ret=rsa_load_keys(structs[MINE].keyPath,mineRSA,1);
		if (ret==-1){
			error("ERROR loading mine RSA key");
		}

		ret=rsa_load_keys(structs[YOURS].keyPath,yoursRSA,0);

		if (ret==-1){
			error("ERROR loading your RSA key");
		}
	}

	/* setup GTK... */
	GtkBuilder* builder;
	GObject* window;
	GObject* button;
	GObject* transcript;
	GObject* message;
	GError* gerror = NULL;
	gboolean is_initialized;
	
	is_initialized=gtk_init_check(&argc, &argv);
	if(!is_initialized){
		error("ERROR GUI could not be started");
	}

	builder = gtk_builder_new();
	if (gtk_builder_add_from_file(builder,"layout.ui",&gerror) == 0) {
		g_printerr("Error reading %s\n", gerror->message);
		g_clear_error(&gerror);
		return 1;
	}
	mark  = gtk_text_mark_new(NULL,TRUE);
	window = gtk_builder_get_object(builder,"window");
	gtk_widget_set_size_request(GTK_WIDGET(window), 400, 400);
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
	transcript = gtk_builder_get_object(builder, "transcript");
	tview = GTK_TEXT_VIEW(transcript);
	message = gtk_builder_get_object(builder, "message");
	tbuf = gtk_text_view_get_buffer(tview);
	mbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(message));
	g_signal_connect_after(mbuf, "insert-text", G_CALLBACK(buf_limit), NULL);
	button = gtk_builder_get_object(builder, "send");
	g_signal_connect_swapped(button, "clicked", G_CALLBACK(sendMessage), GTK_WIDGET(message));
	gtk_widget_grab_focus(GTK_WIDGET(message));
	GtkCssProvider* css = gtk_css_provider_new();
	gtk_css_provider_load_from_path(css,"colors.css",NULL);
	gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
			GTK_STYLE_PROVIDER(css),
			GTK_STYLE_PROVIDER_PRIORITY_USER);

	/* setup styling tags for transcript text buffer */
	gtk_text_buffer_create_tag(tbuf,"status","foreground","#657b83","font","italic",NULL);
	gtk_text_buffer_create_tag(tbuf,"friend","foreground","#6c71c4","font","bold",NULL);
	gtk_text_buffer_create_tag(tbuf,"self","foreground","#268bd2","font","bold",NULL);
	
	//Start network thread
	int ret;
	if (isclient) {
		if (!strcmp(network_params.hostname, "")){
			sprintf(network_params.hostname,"localhost");
		}
		ret=pthread_create(&network_thread,0,initClientNet, 0);
	} else {
		if (!strcmp(network_params.hostname, "")){
			sprintf(network_params.hostname,"127.0.0.1");
		}
		ret=pthread_create(&network_thread,0,initServerNet, 0);
	}

	if (ret){
		error("Failed to start networking threads.\n");
	}

	gtk_main();

	shutdownNetwork();
	return 0;
}
