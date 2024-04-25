#include <arpa/inet.h>
#include <bits/getopt_core.h>
#include <bits/getopt_ext.h>
#include <gtk/gtk.h>
#include <glib/gunicode.h> /* for utf8 strlen */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <getopt.h>
#include "dh.h"
#include "keys.h"

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

static GtkTextBuffer* tbuf; /* transcript buffer */
static GtkTextBuffer* mbuf; /* message buffer */
static GtkTextView*  tview; /* view for transcript */
static GtkTextMark*   mark; /* used for scrolling to end of transcript, etc */

static pthread_t network_thread;     /* wait for incoming messagess and post to queue */
NetworkStruct args={.port=1337};

void* recvMsg(void*);       /* for trecv */

#define max(a, b)         \
	({ typeof(a) _a = a;    \
	 typeof(b) _b = b;    \
	 _a > _b ? _a : _b; })

/* network stuff... */

static int listensock, sockfd;
int isclient = 1;
int is
static void error(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

int keylen=Z2SIZE(dh_params.p)-1;
int keybuf=malloc(keylen);

#define _CONCAT(a,b) a##b
#define CONCAT(a,b) _CONCAT(a,b)

#define _INITBUF(name, len) \
	int CONCAT(name,_buf_len)=len;\
	char* CONCAT(name,_buf)=malloc(CONCAT(name,_buf_len));

#define INITBUF(name,len) _INITBUF(name, len)
#define NEWBUF(name, len) \
	INITBUF(name, len)\
	memset(CONCAT(name,_buf),0,CONCAT(name,_buf_len));\
	pthread_cleanup_push(free, CONCAT(name,_buf));


void serverSetup(){ //This is the setup protocol that will be performed by the server. The secret key will be memcpy into the key buffer.
	NEWBUF(hello, 4);
	
	send_message(STATUS, "Waiting for initial HELLO");

	int ret;
	while(1){
	recvMsg(hello_buf, hello_buf_len); //If recvMsg gets a -1, call pthread_exit() in recvMsg
	if(strncmp(hello_buf,"HELLO", hello_buf_len)){ //You must get a "HELLO" to continue
		continue;
	}

	}
	
	send_message(STATUS, "Recieved a HELLO");

	NEWZ(a); //Initialize new mpz_t
	NEWZ(g_a);
	dhGen(a, g_a); //Generates a and g^a mod p
	
	send_message(STATUS, "Created mine part for Diffie-Hellman");

	RSA_KEY* mineRSA=structs[MINE].key;
	RSA_KEY* yoursRSA=structs[YOURS].key;
	

	Z2NEWBYTES(g_a, Z2SIZE(dh_params.p)); //Creates new buffer *_buf, along with *_buf_len with size equal to provided size (use NEWBUF).


	NEWBUF(enc_b, Z2SIZE(yoursRSA->n)); //Every RSA encrypted message is as big as K->n

	rsa_encrypt(structs[YOURS].key, g_a_buf, g_a_buf_len, enc_b_buf, enc_b_buf_len); //Enc_{PkB}(g^a mod p)

	sendMsg(enc_b_buf, enc_b_buf_len);

	NEWBUF(enc_a, Z2SIZE(mineRSA->n));

	recvMsg(enc_a_buf, enc_a_buf_len); //Receive Enc_{PkA}(g^a mod p || g^b mod p)
	
	
	NEWBUF(dec_a, enc_a_buf_len);

	rsa_decrypt(structs[MINE].key, enc_a_buf, enc_a_buf_len, dec_a_buf, dec_a_buf_len); //Only copy dec_buflen bytes --- If there's not enough bytes to fill it up, memset to 0


	if(memcmp(dec_a_buf,g_a_buf, g_a_buf_len)){
		send_message(STATUS, "Mine g^a and yours g^a do not match. Disconnecting...");
		pthread_exit(NULL);
	}

	NEWZ(g_b);
	
	int g_b_buf_len=g_a_buf_len;
	char* g_b_buf=dec_a_buf+g_a_buf_len;
	BYTES2Z(g_b_buf, g_b_buf_len, g_b);
	
	rsa_encrypt(structs[YOURS].key, g_b_buf, g_b_buf_len, enc_b_buf, enc_b_buf_len); //Enc_{PkB}(g^b mod p)

	sendMsg(enc_b_buf, enc_b_buf_len);

	dhFinal(a, g_a, g_b, keybuf, keylen);

}

void clientSetup(){

	NEWBUF(hello, 4);
	memcpy(hello_buf, "HELLO", 4);

	send_message(STATUS, "Sending initial HELLO");

	sendMsg(hello_buf, hello_buf_len);

	send_message(STATUS, "Recieved a HELLO");
	
	RSA_KEY* mineRSA=structs[MINE].key;
	RSA_KEY* yoursRSA=structs[YOURS].key;
	
	NEWBUF(enc_b, Z2SIZE(mineRSA->n));

	recvMsg(enc_b_buf,enc_b_buf_len);

	NEWBUF(g_a, Z2SIZE(dh_params.p));

	rsa_decrypt(structs[MINE].key, enc_b_buf, enc_b_buf_len, g_a_buf,g_a_buf_len);


	NEWZ(b);
	NEWZ(g_b);
	dhGen(b, g_b);
	send_message(STATUS, "Created yours part for Diffie-Hellman");

	Z2NEWBYTES(g_b); //Creates new buffer *_buf, along with *_buf_len

	NEWBUF(g_a_g_b, Z2SIZE(yoursRSA->n));

	memcpy(g_a_b_buf, g_a_buf, g_a_buf_len);
	memcpy(g_a_g_b_buf+g_a_buf_len, g_b_buf, g_b_buf_len);
	
	NEWBUF(enc_a, Z2SIZE(yoursRSA->n));

	rsa_encrypt(structs[YOURS].key, g_a_g_b_buf, g_a_g_b_buf_len, enc_a_buf, enc_a_buf_len);
	sendMsg(enc_a_buf,enc_a_buf_len);

	recvMsg(enc_b_buf, enc_b_buf_len);
	
	NEWBUF(g_b_a, g_a_buf_len);

	rsa_decrypt(structs[MINE].key, enc_b_buf, enc_b_buf_len, g_b_a_buf, g_b_a_buf_len);

	if(memcmp(g_b_a_buf, g_b_buf, g_b_buf_len)){
		send_message(STATUS, "Mine g^b and yours g^b do not match. Disconnecting...");
		pthread_exit(NULL);
	}
	
	NEWZ(g_a);
	BYTES2Z(g_a_buf, g_a_buf_len, g_a);
	dhFinal(b, g_b, g_a, keybuf, keylen);
}


void reset_setup(void*){
	issetup=0;
}

#define HASHLEN 32
#define NUMLEN 8 //All integer values send/recived are this long
#define MESSAGELEN 4096 

int PACKETLEN=NUMLEN+MESSAGELEN+HASHLEN+NUMLEN;

INITBUF(packet, PACKETLEN);

INITBUF(send, packet_buf_len);

INITBUF(recv, send_buf_len);
	
INITBUF(dec, recv_buf_len);
	
INITBUF(hash, HASHLEN);

void recieveMessages(){
	while(1){
		recvMsg(recv_buf, recv_buf_len);
		send_message(STATUS, "Recieved packet...");
		aes_decrypt(keybuf, keylen, recv_buf, recv_buf_len, dec_buf, dec_buf_len);
		sha256_hash(dec_buf, dec_buf_len, hash_buf);
		if(memcmp(dec_buf+NUMLEN+MESSAGELEN, hash_buf, hash_buf_len)){
			send_message(STATUS, "Hashes do not match...");
			continue;
		}
//send_message has overloads, one without length, and one with. send_message copies into its own buffer
		if(decodeInt(dec_buf+(dec_buf_len-NUMLEN))!=structs[YOURS].counter){
			send_message(STATUS, "Counter values do not match");
			continue;
		}

		send_message(YOURS, dec_buf+NUMLEN, min(decodeInt(dec_buf), MESSAGELEN));
		structs[YOURS].counter++;
		send_message(STATUS, "Message successfully recieved!");

	}

}

void networkMain(){
	pthread_cleanup_push(reset_setup,NULL); //When the connection is broken, the connection can no longer be considered "set up", can it?

	if (isclient){
		clientSetup();
	}else{
		serverSetup();
	}
	send_message(STATUS, "Setup successful. Moving to main messaging protocol..."); 
	issetup=1;
	recieveMessages();
}

// Start of network-related functions
//Don't just accept first one --- once the connection ends (you can check using this: https://stackoverflow.com/a/1795562), accept the next one, and start protocol over

pthread_t main_network_thread;
int initServerNet(void*)
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
	serv_addr.sin_addr.s_addr = inet_addr(args.hostname);
	serv_addr.sin_port = htons(args.port);
	if (bind(listensock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		error("ERROR on binding");

	char status_string[80]; //Should be long enough --- TCP ports only go up to 65535, and IP addresses have <=15 characters.
	sprintf(status_string, "Listening on %s:%i...", args.hostname, args.port);
	send_message(STATUS,status_string);

	listen(listensock,1);
	socklen_t clilen;
	struct sockaddr_in  cli_addr;

	while(1){
		sockfd = accept(listensock, (struct sockaddr *) &cli_addr, &clilen);
		if (sockfd < 0){
			sprintf(status_string, "Failed to accept connection: %s", strerror(errno)); //While this should work for the English locale, it could possibly not work for international locales (which uses more bytes per character)
			send_message(STATUS, status_string);
			continue;
		}
		send_message(STATUS, "Connection made, starting session...");


		pthread_create(&main_network_thread, 0, networkMain,0); //This is to allow us to use pthread_exit in another function while running serverMain
		pthread_join(main_network_thread, NULL);

		send_message(STATUS, "Client has disconnected, waiting for another connection...");
	}
	return 0;
}

static int initClientNet(void*)
{
	struct sockaddr_in serv_addr;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	struct hostent *server;
	if (sockfd < 0)
		error("ERROR opening socket");
	server = gethostbyname(hostname);
	if (server == NULL) {
		error("ERROR, no such host");
	}
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);
	serv_addr.sin_port = htons(port);
	
	char status_string[80];
	sprintf(status_string, "Connecting to %s:%i...", args.hostname, args.port);
	send_message(STATUS,status_string);

	while (1){
		if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0){
			sprintf(status_string, "Failed to connect: %s", strerror(errno));
			send_message(STATUS, status_string);
			continue;
		}
		
		pthread_create(&main_network_thread, 0, networkMain,0); //This is to allow us to use pthread_exit in another function while running serverMain
		pthread_join(main_network_thread, NULL);

		send_message(STATUS, "Server has disconnected, trying to connect again...");
	}
	
	/* at this point, should be able to send/recv on sockfd */
	return 0;
}

static int shutdownNetwork()
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

/* end of network stuff. */


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

pthread_mutex_t send_message_mutex;
int mutex_dummy=pthread_mutex_init(&send_message_mutex, NULL); //So I can initialize the mutex before main()

static void sendMessage(GtkWidget* w /* <-- msg entry widget */, gpointer /* data */)
{

	pthread_mutex_lock(&send_message_mutex);

	if(!issetup){ //Is not setup so we can't do anything
		send_message(STATUS, "Protocol is not set up yet...");
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

		aes_encrypt(packet_buf, packet_buf_len, send_buf); //Encrypt message

		int ret=sendMsg(send_buf, send_buf_len,1); //Send message. The 1 at the end tells it to return a -1 upon error, instead of a pthread_exit

		if (ret==-1){
			pthread_cancel(main_network_thread); //Cancel the main network thread.
			send_message(STATUS, "Message failed to send");
		}else{
			tsappend(message,NULL,1);
			free(message);
			/* clear message text and reset focus */
			gtk_text_buffer_delete(mbuf,&mstart,&mend);
			gtk_widget_grab_focus(w);

			send_message(STATUS, "Message sent successfully!");
		}

		return;

		/* XXX we should probably do the actual network stuff in a different
		 * thread and have it call this once the message is actually sent. */
		ssize_t nbytes;
		if ((nbytes = send(sockfd,message,len,0)) == -1)
			error("send failed");
	}
	pthread_mutex_unlock(&send_message_mutex);
}

static gboolean shownewmessage(gpointer msg)
{
	char* tags[2] = {"friend",NULL};
	char* friendname = "mr. friend: ";
	tsappend(friendname,tags,0);
	char* message = (char*)msg;
	tsappend(message,NULL,1);
	free(message);
	return 0;
}

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

	// define long options
	static struct option long_opts[] = {
		{"client",  no_argument, 0, 'c'},
		{"server",   no_argument,       0, 's'},
		{"hostname", required_argument, 0, 'n'}, //'h' was already taken
		{"port",     required_argument, 0, 'p'},
		{"mine-keys", required_argument, 0, 'm'},
		{"yours-keys", required_argument, 0, 'y'},
		{"generate", no_argument, 0, 'g'},
		{"help",     no_argument,       0, 'h'},
		{0,0,0,0}
	};
	// process options:
	char c;
	int opt_index = 0;
	char* generate=NULL;

	//char hostname[HOST_NAME_MAX+1] = ""; For NetworkStruct->hostname
	
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
				
				memcpy(args.hostname,optarg, len+1);
				break;
			case 'c':
				break; //Nothing to do here
			case 's':
				isclient = 0;
				break;
			case 'p':
				args.port = atoi(optarg);
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
	/* NOTE: might want to start this after gtk is initialized so you can
	 * show the messages in the main window instead of stderr/stdout.  If
	 * you decide to give that a try, this might be of use:
	 * https://docs.gtk.org/gtk4/func.is_initialized.html */

	if (generate!=NULL){
		rsa_generate_keys(generate,dh_get_params().p); //Generates, then saves to keyPath. Makes sure that len(n)>2*len(dh_p)
		exit(0);
	}else{
		rsa_load_keys(structs[MINE],1); //MINE=0. structs is an array of structs. 1 indicates load both private (0 means public). Should error at any error.
		
		rsa_load_keys(structs[YOURS],0);
	}

	/* setup GTK... */
	GtkBuilder* builder;
	GObject* window;
	GObject* button;
	GObject* transcript;
	GObject* message;
	GError* error = NULL;
	gtk_init(&argc, &argv);
	builder = gtk_builder_new();
	if (gtk_builder_add_from_file(builder,"layout.ui",&error) == 0) {
		g_printerr("Error reading %s\n", error->message);
		g_clear_error(&error);
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
	
	while(!gtk_is_initialized()){ //Wait for GTK to initialize. It's not best practice to busy-loop instead of using some sort of signaling, but I don't care enough to figure that out
	}
	
	//Start network thread
	int ret;
	if (isclient) {
		if (!strcmp(args.hostname, "")){
			sprintf(args.hostname, "localhost");
		}
		ret=pthread_create(&network_thread,0,initClientNet, 0);
	} else {
		if (!strcmp(hostname, "")){
			sprintf(args.hostname, "127.0.0.1");
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

/* thread function to listen for new messages and post them to the gtk
 * main loop for processing: */
void* recvMsg(void*)
{
	size_t maxlen = 512;
	char msg[maxlen+2]; /* might add \n and \0 */
	ssize_t nbytes;
	while (1) {
		if ((nbytes = recv(sockfd,msg,maxlen,0)) == -1)
			error("recv failed");
		if (nbytes == 0) {
			/* XXX maybe show in a status message that the other
			 * side has disconnected. */
			return 0;
		}
		char* m = malloc(maxlen+2);
		memcpy(m,msg,nbytes);
		if (m[nbytes-1] != '\n')
			m[nbytes++] = '\n';
		m[nbytes] = 0;
		g_main_context_invoke(NULL,shownewmessage,(gpointer)m);
	}
	return 0;
}
