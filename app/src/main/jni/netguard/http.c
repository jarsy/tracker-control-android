/*
 *  @FileName  http.c
 *
 *  @Brief     Fragments of HTTP filtering functionality.
 */

#include "netguard.h"

// Declare the type for which the Aho-Corasick machines have to be instanciated
ACM_DECLARE (char);
ACM_DEFINE (char);

ACMachine (char)*ahoMachine = NULL;

void ahoMachine_init() {
    if ( ahoMachine == NULL ) {
        ahoMachine = ACM_create(char);
    } else {
        log_android(ANDROID_LOG_DEBUG, "Not expected behaviour! Extra init!");
    }
}

void ahoMachine_deinit() {
    if ( ahoMachine == NULL ) {
        log_android(ANDROID_LOG_DEBUG, "Not expected behaviour! Extra deinit!");
    } else {
        ACM_release (ahoMachine);
        ahoMachine = NULL;
    }
}

JNIEXPORT jboolean JNICALL
Java_eu_faircode_netguard_ServiceSinkhole_jni_1register_1http_1filter_1keyword(JNIEnv *env, jobject instance, jstring keyword) {
    Keyword (char) kw;
    ACM_KEYWORD_SET (kw, (*env)->GetStringUTFChars(env, keyword, 0), (*env)->GetStringUTFLength(env, keyword));
    return ACM_register_keyword (ahoMachine, kw);
}

JNIEXPORT jboolean JNICALL
Java_eu_faircode_netguard_ServiceSinkhole_jni_1deregister_1http_1filter_1keyword(JNIEnv *env, jobject instance, jstring keyword) {
    Keyword (char) kw;
    ACM_KEYWORD_SET (kw, (*env)->GetStringUTFChars(env, keyword, 0), (*env)->GetStringUTFLength(env, keyword));
    return ACM_unregister_keyword(ahoMachine, kw);
}

static jmethodID midHttpPktBlockedReport = NULL;

void http_pkt_blocked_report(const struct arguments *args, const char *blockedKeyword, jobject jpacket) {
#ifdef PROFILE_JNI
    float mselapsed;
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif

    jclass clsService = (*args->env)->GetObjectClass(args->env, args->instance);
    ng_add_alloc(clsService, "clsService");

    const char *signature = "(Ljava/lang/String;Leu/faircode/netguard/Packet;)V";
    if (midHttpPktBlockedReport == NULL)
        midHttpPktBlockedReport = jniGetMethodID(args->env, clsService, "httpPktBlockedReport", signature);

    jstring jblockedKeyword = (*args->env)->NewStringUTF(args->env, blockedKeyword);
    ng_add_alloc(jblockedKeyword, "jblockedKeyword");

    (*args->env)->CallVoidMethod(args->env, args->instance, midHttpPktBlockedReport, jblockedKeyword, jpacket);

    jniCheckException(args->env);

    (*args->env)->DeleteLocalRef(args->env, jpacket);
    (*args->env)->DeleteLocalRef(args->env, clsService);
    (*args->env)->DeleteLocalRef(args->env, jblockedKeyword);
    ng_delete_alloc(jpacket, __FILE__, __LINE__);
    ng_delete_alloc(clsService, __FILE__, __LINE__);
    ng_delete_alloc(jblockedKeyword, __FILE__, __LINE__);

#ifdef PROFILE_JNI
    gettimeofday(&end, NULL);
    mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                (end.tv_usec - start.tv_usec) / 1000.0;
    if (mselapsed > PROFILE_JNI)
        log_android(ANDROID_LOG_WARN, "http_pkt_locked_report %f", mselapsed);
#endif
}

/* Simple HTTP filter
 *
 * @Params
 *
 *  @{in} const struct arguments *args       - Context
 *  @{in} const uint8_t *data                - TCP/UDP payload
 *  @{in} uint16_t datalen                   - TCP/UDP payload length
 *  @{in} jobject jpacket                    - Packet info structure
 *
 *  @{return} true   - process traffic
 *            false  - dismiss traffic
 *
 *  @Brief ...
 */
uint8_t httpFilter(const struct arguments *args, const uint8_t *data, uint16_t datalen, jobject jpacket) {

    char  urlPath[HTTP_URL_LENGTH_MAX+1];
    char  ct[NAME_MAX+1];
    char  httpMethod[10];
    char  blockedKeyword[NAME_MAX+1];

    memset(urlPath,        0x00, sizeof(urlPath));
    memset(ct,             0x00, sizeof(ct));
    memset(blockedKeyword, 0x00, sizeof(blockedKeyword));

    if (datalen < 16 ) //minimum size of http pkt
        return true;

    /* Check for HTTP REQUEST */
        // GET
    if (((data[0] == 'G') && (data[1] == 'E') && (data[2] == 'T')) ||
        // POST
        ((data[0] == 'P') && (data[1] == 'O') && (data[2] == 'S') && (data[3] == 'T')) ||
        // PUT
        ((data[0] == 'P') && (data[1] == 'U') && (data[2] == 'T')) ||
        // DELETE
        ((data[0] == 'D') && (data[1] == 'E') && (data[2] == 'L') && (data[3] == 'E') && (data[4] == 'T') && (data[5] == 'E')) ||
        // HEAD
        ((data[0] == 'H') && (data[1] == 'E') && (data[2] == 'A') && (data[3] == 'D'))) {

        uint16_t urlPathLength      = 0;
        uint16_t indx               = 0;
        uint8_t  *filePresent_ptr   = 0;
        uint8_t  *fileName_ptr      = 0;

        sscanf((const char*)data, "%s %s HTTP/1.1", httpMethod, urlPath);

        urlPathLength = strlen(urlPath);
# if 0 //TODO: Correct in the next drop
        if (urlPathLength > 4) { // /x.x min filename

            for (indx=urlPathLength-2; indx > 0; indx--) {
                if (urlPath[indx] == '.') { //At the point check for files with extention.
                    filePresent_ptr = &urlPath[indx];
                } else if (urlPath[indx] == '/') {
                    fileName_ptr = &urlPath[indx + 1];
                    break;
                }
            }

            if (fileName_ptr < filePresent_ptr) {
                memcpy(ct, fileName_ptr, urlPathLength - indx + 1);
            }
        }
#endif
        // Currently do not parse Host separately, and only have it in the urlPath in case proxy is used.

        if (((urlPathLength > 1) && // Request to domain is blocked separately
             !is_url_path_blocked(args, urlPath, jpacket))  //Check path is allowed
            /*||
            ((strlen(ct) > 0) && !is_content_type_blocked(args, ct, uid))*/) {
            log_android(ANDROID_LOG_DEBUG, "HTTP %s request has been blocked for (%s)!", httpMethod, urlPath);
            return false;
        };

    } else {
        // We are not intrested in :
        //
        //  PATCH
        //  TRACE
        //  OPTIONS
        //  CONNECT
    }

    /*TODO: Check for HTTP RESPONSE */

    /* Check for disallowed keywords */
    if (ahoMachine && ACM_nb_keywords(ahoMachine)) {
        const ACState(char) *state = ACM_reset(ahoMachine);
        MatchHolder (char) match;
        size_t nb_matches = 0;
        void *match_ptr;

        ACM_MATCH_INIT (match);

        for (char *c = data; *c; c++) {
            nb_matches += ACM_match(state, *c);
            if (nb_matches)  // So we get first match
            {
                // 10. If matches were found, retrieve them calling `ACM_get_match ()` for each match.
                //     An optional fourth argument will point to the pointer to the value associated with the matching keyword.
                ACM_get_match (state, 0, &match, &match_ptr);
                size_t kwLenght = ACM_MATCH_LENGTH (match);
                for (size_t indx = 0; (indx < kwLenght) && (indx < sizeof(blockedKeyword)); indx++) {
                     blockedKeyword[indx] = ACM_MATCH_SYMBOLS(match)[indx];
                }
                http_pkt_blocked_report(args, blockedKeyword, jpacket);
                log_android(ANDROID_LOG_DEBUG, "HTTP packet has been blocked! Contains forbidden keywords!");
                return false;
            } //if
        } //for
    } //if

    return true;
}
