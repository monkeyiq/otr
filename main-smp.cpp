#include <popt.h>
extern "C" {
#include <libotr/proto.h>
#include <libotr/privkey.h>
#include <libotr/message.h>
#include <libotr/b64.h>

    struct my_OtrlMessageAppOps
    {
        struct s_OtrlMessageAppOps base;
        void (*extended_write_fingerprints)( void *opdata, OtrlUserState us,
                                             const char *accountname, const char *protocol, const char *username );
    };
};

#include <cstdlib>
#include <iostream>
#include <boost/bind.hpp>
#include <boost/smart_ptr.hpp>
#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <boost/asio/basic_socket_iostream.hpp>

#define SMP_OK  1
#define SMP_BAD 2
    
using   boost::asio::ip::tcp;
typedef boost::asio::ip::tcp::iostream   iosockstream;
typedef boost::shared_ptr<iosockstream>  h_iosockstream;

#include <string>
#include <iostream>
#include <sstream>
#include <fstream>
using namespace std;

const string PROGRAM_NAME = "otr-smp";
unsigned long Verbose = 0;
unsigned long runSMP = 0;
int secure = false;

std::stringstream nothing;
#define VMSG ( Verbose ?  cout : nothing )

void usage(poptContext optCon, int exitcode, char *error, char *addl)
{
    
    poptPrintUsage(optCon, stderr, 0);
    if (error) fprintf(stderr, "%s: %s0", error, addl);
    exit(exitcode);
}

const char* maybenull( const char* v )
{
    return v ? v : "<null>";
}

bool ok( gcry_error_t et )
{
    return gcry_err_code(et) == GPG_ERR_NO_ERROR;
}

const char* TERM_BOLD = "\033[1m";
const char* TERM_COLOR = "\033[35m";
const char* TERM_COLORSEND = "\033[36m";
const char* TERM_NORM = "\033[0m";

template < class T >
std::string embold(  const T& v )
{
    std::stringstream ss;
    ss << TERM_BOLD << v << TERM_NORM;
    return ss.str();
}

template < class T >
std::string color(  const T& v )
{
    std::stringstream ss;
    ss << TERM_COLOR << v << TERM_NORM;
    return ss.str();
}

template < class T >
std::string colorsend(  const T& v )
{
    std::stringstream ss;
    ss << TERM_COLORSEND << v << TERM_NORM;
    return ss.str();
}


/******************************/
/******************************/
/******************************/

static OtrlPolicy myotr_policy(void *opdata, ConnContext *context)
{
    return OTRL_POLICY_ALLOW_V2
        | OTRL_POLICY_REQUIRE_ENCRYPTION;
}

static void myotr_create_privkey( void *opdata, const char *accountname, const char *protocol )
{
    cerr << "myotr_create_privkey()" << endl;
}

static int myotr_is_logged_in(void *opdata, const char *accountname,
                              const char *protocol, const char *recipient)
{
    return -1;
}

static void myotr_inject_message(void *opdata,
                                 const char *accountname, const char *protocol, const char *recipient,
                                 const char *message)
{
    VMSG << "myotr_inject_message() from:" << accountname
         << " proto:" << protocol
         << " to:" << recipient
         << " msg:" << message
         << endl;
    if( opdata )
    {
        VMSG << "myotr_inject_message(1) have opdata!" << endl;
        iosockstream* stream = (iosockstream*)opdata;
        (*stream) << message << endl << flush;
        VMSG << "INJECTED:" << message << endl;
    }
}

static void myotr_notify( void *opdata, OtrlNotifyLevel level,
                          const char *accountname, const char *protocol,
                          const char *username, const char *title,
                          const char *primary, const char *secondary)
{
    cerr << "myotr_notify() user:" << username << " title:" << title << endl;
    cerr << "myotr_notify() p:" << primary << " sec:" << secondary << endl;
}

static int myotr_display_otr_message( void *opdata,
                                      const char *accountname, const char *protocol, const char *username,
                                      const char *msg)
{
    cerr << "myotr_display_message() from:" << accountname
         << " proto:" << protocol
         << " to:" << username
         << " msg:" << msg
         << endl;
}

static void myotr_update_context_list(void *opdata)
{
    cerr << "myotr_update_context_list()..." << endl;
    
}

static const char* myotr_protocol_name(void *opdata, const char *protocol)
{
    return strdup(protocol);
}

static void myotr_protocol_name_free(void *opdata, const char *protocol_name)
{
    free( (void*)protocol_name );
}

static std::string fingerprint_hash_to_human( unsigned char* hash )
{
    char human[45];
    bzero( human, 45 );
    otrl_privkey_hash_to_human( human, hash );
    std::string ret = human;
    return ret;
}
static std::string fingerprint_hash_to_human( char* hash )
{
    return fingerprint_hash_to_human( (unsigned char*)hash );
}


static void myotr_new_fingerprint( void *opdata, OtrlUserState us,
                                   const char *accountname, const char *protocol,
                                   const char *username, unsigned char fingerprint[20])
{
    runSMP = true;
    cerr << "myotr_new_fingerprint(top)" << endl;
    cerr << " account:" << accountname << " proto:" << protocol << " user:" << username << endl;

    char our_fingerprint[45];
    if( otrl_privkey_fingerprint( us, our_fingerprint, accountname, protocol) )
    {
        cerr << "myotr_new_fingerprint() our   human fingerprint:" << embold( our_fingerprint ) << endl;
    }
    
    cerr << "myotr_new_fingerprint() their human fingerprint:"
         << embold( fingerprint_hash_to_human( fingerprint )) << endl;
}

static void myotr_write_fingerprints(void *opdata)
{
    cerr << "myotr_write_fingerprints()" << endl;
    
}

static void myotr_extended_write_fingerprints( void *opdata, OtrlUserState us,
                                               const char *accountname, const char *protocol, const char *username )
{
    cerr << "myotr_extended_write_fingerprints()" << endl;
    std::stringstream fn;
    fn << "fingerprints-" << accountname;
    gcry_error_t e = otrl_privkey_write_fingerprints( us, fn.str().c_str() );
}




static void myotr_gone_secure(void *opdata, ConnContext *context)
{
    cerr << "myotr_gone_secure()" << endl;
    secure = 1;
}

static void myotr_gone_insecure(void *opdata, ConnContext *context)
{
    cerr << "myotr_gone_insecure() WARNING!" << endl;
}


static void myotr_still_secure(void *opdata, ConnContext *context, int is_reply)
{
    cerr << "myotr_still_secure()" << endl;
}


static void myotr_log_message(void *opdata, const char *message)
{
    cerr << "myotr_log_message():" << message << endl;
}


static int myotr_max_message_size(void *opdata, ConnContext *context)
{
    return 1024*1024;
}


static const char* myotr_account_name( void *opdata, const char *account,
                                       const char *protocol)
{
    return strdup(account);
}

static void myotr_account_name_free( void *opdata, const char *account_name)
{
    free( (void*)account_name );
}

static void myotr_add_appdata(void *data, ConnContext *context)
{
    cerr << "myotr_add_appdata() ctx:" << context << endl;
}


struct my_OtrlMessageAppOps extended_ui_ops =
{
    myotr_policy,
    myotr_create_privkey,
    myotr_is_logged_in,
    myotr_inject_message,
    myotr_notify,
    myotr_display_otr_message,
    myotr_update_context_list,
    myotr_protocol_name,
    myotr_protocol_name_free,
    myotr_new_fingerprint,
    myotr_write_fingerprints,
    myotr_gone_secure,    
    myotr_gone_insecure,
    myotr_still_secure,
    myotr_log_message,
    myotr_max_message_size,
    myotr_account_name,
    myotr_account_name_free,
    myotr_extended_write_fingerprints
};
struct s_OtrlMessageAppOps& ui_ops = extended_ui_ops.base;

/******************************/
/******************************/
/******************************/

OtrlUserState userstate;
std::string keyfile;
const char *accountname = 0;
//const char *protocol = "prpl-oscar";
const char *protocol = "freddy";
const char *recipientname = 0;



void handle_smp( iosockstream& stream, OtrlTLV* tlvs,
                 OtrlUserState userstate, const my_OtrlMessageAppOps* extended_ui_ops, void* opdata )
{
    const s_OtrlMessageAppOps* ui_ops = &extended_ui_ops->base;

      
    std::string s;
    OtrlTLV *tlv = NULL;
    bool add_if_missing = true;
    int addedp = 0;
    ConnContext* smpcontext = otrl_context_find( userstate,
                                                 recipientname, accountname, protocol,
                                                 add_if_missing, &addedp,
                                                 myotr_add_appdata, &ui_ops );
    
    NextExpectedSMP nextMsg = smpcontext->smstate->nextExpected;
    cerr << "      nextMsg:" << nextMsg << endl;
    cerr << "sm_prog_state:" << smpcontext->smstate->sm_prog_state << endl;

    
    if( tlv = otrl_tlv_find(tlvs, OTRL_TLV_SMP1Q) )
    {
        cerr << "smp1q" << endl;
        std::string question = (char *)tlv->data;
		if (nextMsg != OTRL_SMP_EXPECT1)
        {
			cerr << "smp: spurious SMP1 received, aborting" << endl;
			otrl_message_abort_smp( userstate, ui_ops, opdata, smpcontext);
			otrl_sm_state_free(smpcontext->smstate);
		}
        else
        {
            cerr << embold("smp: initiated by client, please provide response") << endl;
            cerr << "Q:" << question << endl;
            getline(cin,s);
			otrl_message_respond_smp( userstate, ui_ops, opdata, smpcontext, (unsigned char *)s.c_str(), s.length());
			/* smp stays in EXPECT1 until user responds */
		}
    }
    if( tlv = otrl_tlv_find(tlvs, OTRL_TLV_SMP1))
    {
        cerr << "smp1" << endl;

		if (nextMsg != OTRL_SMP_EXPECT1)
        {
			cerr << "smp: spurious SMP1 received, aborting" << endl;
			otrl_message_abort_smp( userstate, ui_ops, opdata, smpcontext);
			otrl_sm_state_free(smpcontext->smstate);
		}
        else
        {
            cerr << embold("smp: initiated by client, please provide response") << endl;
            getline(cin,s);
			otrl_message_respond_smp( userstate, ui_ops, opdata, smpcontext, (unsigned char *)s.c_str(), s.length());
			/* smp stays in EXPECT1 until user responds */
		}
    }
	if( tlv = otrl_tlv_find(tlvs, OTRL_TLV_SMP2))
    {
		if (nextMsg != OTRL_SMP_EXPECT2)
        {
			cerr << "smp: spurious SMP2 received, aborting" << endl;
			otrl_message_abort_smp( userstate, ui_ops, opdata, smpcontext);
			otrl_sm_state_free(smpcontext->smstate);
		}
        else
        {
			cerr << embold("SMP2 received, otrl_message_receiving will have sent SMP3") << endl;
			smpcontext->smstate->nextExpected = OTRL_SMP_EXPECT4;
		}
	}
	if( tlv = otrl_tlv_find(tlvs, OTRL_TLV_SMP3))
    {
		if (nextMsg != OTRL_SMP_EXPECT3)
        {
			cerr << "smp: spurious SMP3 received, aborting" << endl;
			otrl_message_abort_smp( userstate, ui_ops, opdata, smpcontext);
			otrl_sm_state_free(smpcontext->smstate);
		}
        else
        {
			cerr << embold("SMP3 received, otrl_message_receiving will have sent SMP4") << endl;
			if(smpcontext->smstate->sm_prog_state == OTRL_SMP_PROG_SUCCEEDED)
            {
                secure = 1;
                ui_ops->new_fingerprint( opdata, userstate,
                                         accountname, protocol, recipientname,
                                         smpcontext->active_fingerprint->fingerprint );
                ui_ops->write_fingerprints( opdata );
                extended_ui_ops->extended_write_fingerprints( opdata, userstate, accountname, protocol, recipientname );
                
				if(smpcontext->smstate->received_question) {
					cerr << color("smp: correct answer, you are trusted") << endl;
				} else {
					cerr << color("smp: secrets proved equal, fingerprint trusted") << endl;
				}
			}
            else
            {
                secure = SMP_BAD;
                cerr << color("smp: wrong answer, you are not trusted") << endl;
			}
			otrl_sm_state_free(smpcontext->smstate);
			/* smp is in back in EXPECT1 */
		}
	}
	tlv = otrl_tlv_find(tlvs, OTRL_TLV_SMP4);
	if (tlv)
    {
		if (nextMsg != OTRL_SMP_EXPECT4)
        {
			cerr << embold("smp: spurious SMP4 received, aborting") << endl;
			otrl_message_abort_smp( userstate, ui_ops, opdata, smpcontext);
			otrl_sm_state_free(smpcontext->smstate);
		}
        else
        {
			/* SMP4 received, otrl_message_receiving will have set fp trust */
			if(smpcontext->smstate->sm_prog_state == OTRL_SMP_PROG_SUCCEEDED)
            {
                secure = 1;
				cerr << color("smp: secrets proved equal, fingerprint trusted") << endl;
                cerr << "fingerprint:" << smpcontext->active_fingerprint << endl;
                if( smpcontext->active_fingerprint && smpcontext->active_fingerprint->fingerprint )
                {
                    otrl_context_set_trust( smpcontext->active_fingerprint, "1" );

                    
                    ui_ops->new_fingerprint( opdata, userstate,
                                             accountname, protocol, recipientname,
                                             smpcontext->active_fingerprint->fingerprint );
                    ui_ops->write_fingerprints( opdata );
                    extended_ui_ops->extended_write_fingerprints( opdata, userstate, accountname, protocol, recipientname );
                }
			}
            else
            {
                secure = SMP_BAD;
				cerr << color("smp: secrets did not match, fingerprint not trusted") << endl;
			}
			otrl_sm_state_free(smpcontext->smstate);
			/* smp is in back in EXPECT1 */
		}
	}
	tlv = otrl_tlv_find(tlvs, OTRL_TLV_SMP_ABORT);
	if (tlv)
    {
	 	cerr << embold("smp: received abort message!") << endl;
		otrl_sm_state_free(smpcontext->smstate);
		/* smp is in back in EXPECT1 */
	}
    
}



void server_session( h_iosockstream streamptr )
{
    iosockstream& stream = *(streamptr.get());
    try
    {
        while( stream )
        {
            gcry_error_t et;
            std::string s;
            void* opdata = &stream;
            OtrlTLV* tlvs = 0;

//            tlvs = otrl_tlv_new( OTRL_TLV_PADDING, 1, (const unsigned char*)"" );
            
            VMSG << "getting more data from the client..." << endl;
            getline( stream, s );
            VMSG << "READ:" << s << endl;
                    
            char *newmessage = NULL;
            int ignore_message = otrl_message_receiving(
                userstate, &ui_ops, opdata,
                accountname, protocol, recipientname,
                s.c_str(),
                &newmessage,
                &tlvs,
                myotr_add_appdata, &ui_ops );

            VMSG << "ignore:" << ignore_message << " newmsg:" << maybenull(newmessage) << endl;
            VMSG << " tlvs:" << tlvs << endl;

            if( tlvs )
            {
                handle_smp( stream, tlvs, userstate, &extended_ui_ops, opdata );
            }
            
            if( newmessage )
                s = newmessage;
            otrl_message_free( newmessage );
            if( ignore_message )
            {
                VMSG << "libotr told us to ignore this message..." << endl;
                continue;
            }
                
            cout << "ignore:" << ignore_message << " server got:" << s << endl;
            cout << "message from client:" << color(s) << endl;

            // do not echo back messages when we are establishing the session
            if( !secure )
                continue;
                
            static int count = 0;
            stringstream zz;
            zz << "back to you:" << count++;
            s = zz.str();
            cout << "writing...s:" << s << endl;
            cerr << "send plaintext:" << colorsend(s) << endl;

            et = otrl_message_sending( userstate, &ui_ops, opdata,
                                       accountname, protocol, recipientname,
                                       s.c_str(), tlvs, &newmessage,
                                       myotr_add_appdata, &ui_ops );
            if( !ok(et) )
            {
                cerr << "OTR message_sending() failed!" << endl;
            }
            if( ok(et) && !newmessage )
            {
                cerr << "There was no error, but an OTR message could not be made." << endl;
                cerr << "perhaps you need to run some key authentication first..." << endl;
            }
            if( newmessage )
            {
                VMSG << "have new OTR message:" << newmessage << endl;
                s = newmessage;
            }
                
            VMSG << "writing otr...s:" << s << endl;
            if( secure )
                stream << s << endl;
        }
        cerr << "done..." << endl;
    }
    catch (std::exception& e)
    {
        std::cerr << "Exception in thread: " << e.what() << "\n";
    }
}



void setupKey( const std::string& filename )
{
    gcry_error_t et;
    
    et = otrl_privkey_read( userstate, filename.c_str() );
    if( !ok(et) )
    {
        cerr << "can't find existing key, generating a new one!" << endl;
        cerr << "this needs a bunch of entropy from your machine... so please" << endl;
        cerr << "move the mouse around and slap some keys mindlessly for a while" << endl;
        cerr << "a message will be printed when keys have been made..." << endl;
        et = otrl_privkey_generate( userstate, filename.c_str(),
                                    accountname, protocol );
        if( !ok(et) )
        {
            cerr << "failed to write new key file at:" << filename << endl;
        }
        cerr << "Have keys!" << endl;
    }
}

std::string client_read_msg_from_server( iosockstream& stream )
{
    void* opdata = &stream;
    OtrlTLV* tlvs = 0;
    std::string s;
    char* newmessage = 0;
    
    s = "junk";
    VMSG << "reading data from server" << endl;
    getline(stream,s);
    VMSG << "READ:" << s << endl;

    int ignore_message = otrl_message_receiving(
        userstate, &ui_ops, opdata,
        accountname, protocol, recipientname,
        s.c_str(),
        &newmessage,
        &tlvs,
        myotr_add_appdata, &ui_ops );

    VMSG << "tlvs:" << tlvs << endl;
    if( tlvs )
    {
        handle_smp( stream, tlvs, userstate, &extended_ui_ops, opdata );
    }

    VMSG << "secure:" << secure << " ignore:" << ignore_message << " newmsg:" << maybenull(newmessage) << endl;
    if( ignore_message )
    {
        VMSG << "libotr told us to ignore this message..." << endl;
        VMSG << "available:" << stream.rdbuf()->available() << endl;
        VMSG << " in_avail:" << stream.rdbuf()->in_avail() << endl;   
        return "";
    }
    if( newmessage )
        s = newmessage;

    return s;
}

void run_smp_client( iosockstream& stream )
{
    void* opdata = &stream;
    OtrlTLV* tlvs = 0;

    stream << "?OTR?v2?" << endl;
    usleep( 200 * 1000 );
    while( !secure && stream.peek() != std::iostream::traits_type::eof() )
        client_read_msg_from_server( stream );

    if( !runSMP )
    {
        return;
    }
    
    VMSG << "Starting the Socialist Millionaires' Protocol " << endl
         << " to work out who the other guy is..." << endl
         << endl;
    VMSG << "please give me a secret that only you and the other guy know..." << endl;
    std::string s;
    getline( cin, s );
    int add_if_missing = true;
    int addedp = 0;
    ConnContext* smpcontext = otrl_context_find( userstate,
                                                 recipientname, accountname, protocol,
                                                 add_if_missing, &addedp,
                                                 myotr_add_appdata, &ui_ops );

    cerr << "addedp:" << addedp << " smpcontext:" << smpcontext << endl;
    if( !smpcontext )
        return;
    otrl_message_initiate_smp( userstate, &ui_ops, opdata, smpcontext,
                               (const unsigned char*)s.c_str(), s.length() );

    secure = 0;
    while( !secure && stream.peek() != std::iostream::traits_type::eof() )
        client_read_msg_from_server( stream );
        
    cerr << "secure:" << secure << endl;
    if( secure == SMP_BAD )
    {
        cerr << "couldn't authenticate server, exiting..." << endl;
        exit(1);
    }
}
        

int main( int argc, const char** argv )
{
    const char* XX= "";
    unsigned long Port    = 10000;
    unsigned long ServerMode = 0;

    struct poptOption optionsTable[] = {

        { "port", 'p', POPT_ARG_INT, &Port, 0,
          "port to connect/listen on", 0 },

        { "verbose", 'v', POPT_ARG_NONE, &Verbose, 0,
          "print verbose messages as things go along", 0 },

        { "server", 's', POPT_ARG_NONE, &ServerMode, 0,
          "run as a server, wait on the given port for a client", 0 },

        { "smp", 'z', POPT_ARG_NONE, &runSMP, 0,
          "run a round of the Socialist Millionaires' Protocol to verify the other end", 0 },
        
        POPT_AUTOHELP
        POPT_TABLEEND
    };
    poptContext optCon;

    optCon = poptGetContext(PROGRAM_NAME.c_str(), argc, argv, optionsTable, 0);
    poptSetOtherOptionHelp(optCon, "[OPTIONS]*  ...");

    if (argc < 1)
    {
        poptPrintUsage(optCon, stderr, 0);
        exit(1);
    }

    /* Now do options processing... */
    int c=-1;
    while ((c = poptGetNextOpt(optCon)) >= 0)
    {
//         switch (c) {
//         }
    }

    int rc;
    VMSG << "otr test client..." << endl;
    OTRL_INIT;
    userstate = otrl_userstate_create();

    keyfile = "client.key";
    accountname = "client";
    recipientname = "server";
    if( ServerMode )
    {
        accountname = "server";
        recipientname = "client";
        keyfile = "server.key";
    }
    setupKey( keyfile );

    std::stringstream fn;
    fn << "fingerprints-" << accountname;
    gcry_error_t e = otrl_privkey_read_fingerprints( userstate, fn.str().c_str(), 0, 0 );
    
    
    
    if( ServerMode )
    {
        VMSG << "server mode..." << endl;

        boost::asio::io_service io_service;
        tcp::acceptor a( io_service, tcp::endpoint( tcp::v4(), Port ));
        for (;;)
        {
            h_iosockstream stream(new iosockstream());
            a.accept( *(stream->rdbuf()) );
            boost::thread t(boost::bind(server_session, stream));
        }
    }
    else
    {
        VMSG << "client mode..." << endl;
        stringstream portss;
        portss << Port;
        iosockstream stream( "127.0.0.1", portss.str() );
        if (!stream)
        {
            cerr << "can't connect to server!" << endl;
            exit(1);
        }

        run_smp_client( stream );
        string s;
        while( true )
        {
            void* opdata = &stream;
            OtrlTLV* tlvs = 0;
            gcry_error_t et;
            char* newmessage;

            cerr << "getting a messsage from you to send to the server..." << endl;
            getline(cin,s);
            cerr << "your raw message:" << s << endl;
            cerr << "send plaintext:" << colorsend(s) << endl;
            
            et = otrl_message_sending( userstate, &ui_ops, opdata,
                                       accountname, protocol, recipientname,
                                       s.c_str(), tlvs, &newmessage,
                                       myotr_add_appdata, &ui_ops );
            cerr << "encoded... ok:" << ok(et) << endl;
            if( !ok(et) )
            {
                cerr << "OTR message_sending() failed!" << endl;
            }
            if( ok(et) && !newmessage )
            {
                cerr << "There was no error, but an OTR message could not be made." << endl;
                cerr << "perhaps you need to run some key authentication first..." << endl;
            }
            if( newmessage )
            {
                VMSG << "have new OTR message:" << newmessage << endl;
                s = newmessage;
            }
            
            cerr << "WRITE:" << s << endl;
            stream << s << endl;
            usleep( 200 * 1000 );

            while( !secure && stream.peek() != std::iostream::traits_type::eof()
                   || secure && stream.rdbuf()->available() )
            {
                s = client_read_msg_from_server( stream );
                if( !s.empty() )
                    cout << color( s ) << endl;
            }
        }
    }
    
    return 0;
}
