/*  xmbot
 **
 ** a xmpp bot running on openwrt router
 **
 ** This code is free software; you can redistribute it and/or
 ** modify it under the terms of GNU Lesser General Public License.
 */

#include <sys/types.h>
#include <stdio.h>

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <unistd.h>

#include <errno.h>
#ifndef errno
extern int errno;
#endif

#include <iksemel.h>

//#define DEBUG

/* stuff we keep per session */
struct session {
    iksparser *prs;
    iksid *acc;
    char *pass;
    int features;
    int authorized;
    int counter;
    int set_roster;
    int job_done;
};

struct command{
    char *word;
    char *command;
};

//char *cfgfile="/home/wgjtyu/xmbotrc";
char *cfgfile="/etc/xmbotrc";

/*
 * need to initate
 */
char *jabber_id;
char *pass;
char *god;

//struct command *cmd_arys=NULL;
struct command cmd_arys[50];
/*{
    {"wifi up","control_wireless.sh up"},
    {"wifi down","control_wireless.sh down"}
};*/

int cmd_arys_l=0;

/* precious roster we'll deal with */
iks *my_roster;

/* out packet filter */
iksfilter *my_filter;

/* connection time outs if nothing comes for this much seconds */
int opt_timeout = 30;

/* connection flags */
int opt_use_tls=1;
int opt_use_sasl=1;
int opt_use_plain=0;

void putlog(const char *func,int line,const char *detail){
#ifdef DEBUG
    printf("(%3d)%s:%s\n",line,func,detail);
#endif
}

int load_config(){
    FILE *fp;
    char tmp[100];
    char *content=NULL;
    int loadcmd=0;
    if((fp=fopen(cfgfile,"r"))==NULL){
        printf("%s doesn't exist..exit!\n",cfgfile);
        return -1;
    }
    while(fgets(tmp,100,fp)!=NULL){
        if(tmp[0]=='#') continue;
        content=strchr(tmp,'=');
        if(loadcmd){
            cmd_arys[cmd_arys_l].word=malloc(content-tmp);
            strncpy(cmd_arys[cmd_arys_l].word,tmp,content-tmp);
            printf("word:%s ",cmd_arys[cmd_arys_l].word);
            cmd_arys[cmd_arys_l].command=malloc(strlen(content));
            strncpy(cmd_arys[cmd_arys_l].command,content+1,strlen(content)-1);
            printf("command:%s\n",cmd_arys[cmd_arys_l].command);
            ++cmd_arys_l;
        }else{
            if(strncmp(tmp,"account",7)==0){
                if(tmp[0]=='#') continue;
                jabber_id=malloc(strlen(content));
                strncpy(jabber_id,content+1,strlen(content)-2);
                printf("jid:%s\n",jabber_id);
            }
            else if(strncmp(tmp,"password",8)==0){
                pass=malloc(strlen(content));
                strncpy(pass,content+1,strlen(content)-2);
                printf("psw:%s\n",pass);
            }
            else if(strncmp(tmp,"god",3)==0){
                god=malloc(strlen(content));
                strncpy(god,content+1,strlen(content)-2);
                printf("god:%s\n",god);
            }
            else if(strncmp(tmp,"command",7)==0){
                loadcmd=1;
            }
            else{
                if(content==NULL) continue; //跳过没有等于号的行
                printf("unknown:%s\n",tmp);
                return -1;
            }
        }
    }
    return 0;
}

void j_error (char *msg)
{
    fprintf (stderr, "xmbot: %s\n", msg);
    exit (2);
}

int on_result (struct session *sess, ikspak *pak)
{
    putlog(__FUNCTION__,__LINE__,"COME IN");
    iks *x;

    if (sess->set_roster == 0) {
        x = iks_make_iq (IKS_TYPE_GET, IKS_NS_ROSTER);
        iks_insert_attrib (x, "id", "roster");
        iks_send (sess->prs, x);
        iks_delete (x);
    } else {
        iks_insert_attrib (my_roster, "type", "set");
        iks_send (sess->prs, my_roster);
    }
    putlog(__FUNCTION__,__LINE__,"COME OUT");
    return IKS_FILTER_EAT;
}

int on_stream (struct session *sess, int type, iks *node)
{
    putlog(__FUNCTION__,__LINE__,"COME IN");
    sess->counter = opt_timeout;

    switch (type) {
        case IKS_NODE_START:
            putlog(__FUNCTION__,__LINE__,"IKS_NODE_START");
            if (opt_use_tls && !iks_is_secure (sess->prs)) {
                putlog(__FUNCTION__,__LINE__,"CALL iks_start_tls");
                iks_start_tls (sess->prs);
                break;
            }
            if (!opt_use_sasl) {
                putlog(__FUNCTION__,__LINE__,"!opt_use_sasl");
                iks *x;
                char *sid = NULL;

                if (!opt_use_plain) sid = iks_find_attrib (node, "id");
                x = iks_make_auth (sess->acc, sess->pass, sid);
                iks_insert_attrib (x, "id", "auth");
                iks_send (sess->prs, x);
                iks_delete (x);
            }
            break;

        case IKS_NODE_NORMAL:
            putlog(__FUNCTION__,__LINE__,"IKS_NODE_NORMAL");
            if (strcmp ("stream:features", iks_name (node)) == 0) {
                sess->features = iks_stream_features (node);
                if (opt_use_sasl) {
                    if (opt_use_tls && !iks_is_secure (sess->prs)) break;
                    if (sess->authorized) {
                        iks *t;
                        if (sess->features & IKS_STREAM_BIND) {
                            t = iks_make_resource_bind (sess->acc);
                            iks_send (sess->prs, t);
                            iks_delete (t);
                        }
                        if (sess->features & IKS_STREAM_SESSION) {
                            t = iks_make_session ();
                            iks_insert_attrib (t, "id", "auth");
                            iks_send (sess->prs, t);
                            iks_delete (t);
                        }
                    } else {
                        if (sess->features & IKS_STREAM_SASL_MD5)
                            iks_start_sasl (sess->prs, IKS_SASL_DIGEST_MD5, sess->acc->user, sess->pass);
                        else if (sess->features & IKS_STREAM_SASL_PLAIN)
                            iks_start_sasl (sess->prs, IKS_SASL_PLAIN, sess->acc->user, sess->pass);
                    }
                }
            } else if (strcmp ("failure", iks_name (node)) == 0) {
                j_error ("sasl authentication failed");
            } else if (strcmp ("success", iks_name (node)) == 0) {
                putlog(__FUNCTION__,__LINE__,"IKS_NODE_NORMAL success");
                sess->authorized = 1;
                iks_send_header (sess->prs, sess->acc->server);
            } else {
                ikspak *pak;

                pak = iks_packet (node);
                //printf("something: %s\n",pak->x->s);
                iks_filter_packet (my_filter, pak);
                if (sess->job_done == 1){
                    putlog(__FUNCTION__,__LINE__,"COME OUT IKS_HOOK");    
                    //return IKS_HOOK;
                }
            }
            break;

        case IKS_NODE_STOP:
            putlog(__FUNCTION__,__LINE__,"IKS_NODE_STOP");
            break;

        case IKS_NODE_ERROR:
            putlog(__FUNCTION__,__LINE__,"IKS_NODE_ERROR");
            break;
    }

    if (node) iks_delete (node);
    putlog(__FUNCTION__,__LINE__,"COME OUT");
    return IKS_OK;
}

int on_error (void *user_data, ikspak *pak)
{
    j_error ("authorization failed");
    return IKS_FILTER_EAT;
}

int on_msg(struct session *sess,ikspak *pak)
{
    char *body=NULL;
    putlog(__FUNCTION__,__LINE__,"COME IN");
    if(strncmp(god,iks_find_attrib(pak->x,"from"),sizeof(god))!=0)
        return -1;
    if((body=iks_find_cdata(pak->x,"body"))!=NULL){
        putlog(__FUNCTION__,__LINE__,body);
        printf("command: %s\n",body);
        int found=0,i;
        for(i=0;i<cmd_arys_l;++i){
            if(strncmp(body,cmd_arys[i].word,strlen(body))==0){
                printf("runcmd: %s\n",cmd_arys[i].command);
                system(cmd_arys[i].command);
                found=1;
                break;
            }
        }
        if(!found){
            printf("unknown command\n");
        }
    }
    putlog(__FUNCTION__,__LINE__,"COME OUT");
    return IKS_OK;
}

int on_roster (struct session *sess, ikspak *pak)
{
    putlog(__FUNCTION__,__LINE__,"COME IN");
    
    iks *x;
    x=iks_make_pres(IKS_SHOW_AVAILABLE,"come on");
    iks_send (sess->prs, x);
    x=iks_make_msg(IKS_TYPE_CHAT,god,"I'm On");
    iks_send (sess->prs, x);
    
    my_roster = pak->x;
    sess->job_done = 1;
    return IKS_FILTER_EAT;
}

void on_log (struct session *sess, const char *data, size_t size, int is_incoming)
{
#ifdef DEBUG
    if (iks_is_secure (sess->prs)) printf ("Sec");
    if (is_incoming) printf("RECV"); else printf("SEND");
    printf ("[%s]\n", data);
#endif
}

void setup_filter (struct session *sess)
{
    if (my_filter) iks_filter_delete (my_filter);
    my_filter = iks_filter_new ();
    iks_filter_add_rule (my_filter, (iksFilterHook *) on_result, sess,
            IKS_RULE_TYPE, IKS_PAK_IQ,
            IKS_RULE_SUBTYPE, IKS_TYPE_RESULT,
            IKS_RULE_ID, "auth",
            IKS_RULE_DONE);
    iks_filter_add_rule (my_filter, on_error, sess,
            IKS_RULE_TYPE, IKS_PAK_IQ,
            IKS_RULE_SUBTYPE, IKS_TYPE_ERROR,
            IKS_RULE_ID, "auth",
            IKS_RULE_DONE);
    iks_filter_add_rule (my_filter, (iksFilterHook *) on_roster, sess,
            IKS_RULE_TYPE, IKS_PAK_IQ,
            IKS_RULE_SUBTYPE, IKS_TYPE_RESULT,
            IKS_RULE_ID, "roster",
            IKS_RULE_DONE);
    iks_filter_add_rule (my_filter, (iksFilterHook *)on_msg, sess,
            IKS_RULE_TYPE, IKS_PAK_MESSAGE,
            IKS_RULE_SUBTYPE, IKS_TYPE_CHAT,
            IKS_RULE_DONE);
}

int main (int argc, char *argv[])
{
    int e;
    int set_roster=0;

    if(0!=load_config()) return -1;

    struct session sess;
    sess.counter=10000;
    sess.authorized=0;

    sess.prs=iks_stream_new(IKS_NS_CLIENT,&sess,(iksStreamHook *)on_stream);
    iks_set_log_hook(sess.prs, (iksLogHook *) on_log);
    sess.acc = iks_id_new (iks_parser_stack (sess.prs), jabber_id);
    if (NULL == sess.acc->resource) {
        /* user gave no resource name, use the default */
        char *tmp;
        tmp = iks_malloc (strlen (sess.acc->user) + strlen (sess.acc->server) + 5 + 3);
        sprintf (tmp, "%s@%s/%s", sess.acc->user, sess.acc->server, "xmbot");
        sess.acc = iks_id_new (iks_parser_stack (sess.prs), tmp);
        iks_free (tmp);
    }
    sess.pass = pass;
    sess.set_roster = set_roster;

    setup_filter (&sess);

    e=iks_connect_via(sess.prs, "talk.google.com", IKS_JABBER_PORT,"gmail.com");
    switch (e) {
        case IKS_OK:
            putlog(__FUNCTION__,__LINE__,"IKS_OK");
            break;
        case IKS_NET_NODNS:
            j_error ("hostname lookup failed");
        case IKS_NET_NOCONN:
            j_error ("connection failed");
        default:
            j_error ("io error");
    }

    sess.counter = opt_timeout;
    while (1) {
        e = iks_recv (sess.prs, 1);
        if (IKS_HOOK == e) break;
        if (IKS_NET_TLSFAIL == e) j_error ("tls handshake failed");
        if (IKS_OK != e) j_error ("io error");
        sess.counter--;
        if (sess.counter == 0) j_error ("network timeout");
    }
    iks_parser_delete (sess.prs);
    putlog(__FUNCTION__,__LINE__,"QUIT");
    return 0;
}
