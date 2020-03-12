/*
 *  @FileName  http.c
 *
 *  @Brief     Fragments of HTTP filtering functionality.
 */

#include "netguard.h"

// Declare the type for which the Aho-Corasick machines have to be instanciated
ACM_DECLARE (char);
ACM_DEFINE (char);

ACMachine (char)*ahoMachine = NULL;  // block keywords SM
ACMachine (char)*ahoKH = NULL;       // hash keywords SM

void ahoMachine_init() {
    //block keywords SM
    if ( ahoMachine == NULL ) {
        ahoMachine = ACM_create(char);
    } else {
        log_android(ANDROID_LOG_DEBUG, "Not expected behaviour! Extra init!");
    }

    //hasing keywords SM
    if ( ahoKH == NULL ) {
        ahoKH = ACM_create(char);
    } else {
        log_android(ANDROID_LOG_DEBUG, "Not expected behaviour! Extra init!");
    }
}

void ahoMachine_deinit() {
    //block SM
    if ( ahoMachine == NULL ) {
        log_android(ANDROID_LOG_DEBUG, "Not expected behaviour! Extra deinit!");
    } else {
        ACM_release (ahoMachine);
        ahoMachine = NULL;
    }

    //hash SM
    if ( ahoKH == NULL ) {
        log_android(ANDROID_LOG_DEBUG, "Not expected behaviour! Extra deinit!");
    } else {
        ACM_release (ahoKH);
        ahoKH = NULL;
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

void http_pkt_blocked_report(const struct arguments *args, const char *blockedKeyword, jint uid) {
#ifdef PROFILE_JNI
    float mselapsed;
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif

    jclass clsService = (*args->env)->GetObjectClass(args->env, args->instance);
    ng_add_alloc(clsService, "clsService");

    const char *signature = "(Ljava/lang/String;I)V";
    if (midHttpPktBlockedReport == NULL)
        midHttpPktBlockedReport = jniGetMethodID(args->env, clsService, "httpPktBlockedReport", signature);

    jstring jblockedKeyword = (*args->env)->NewStringUTF(args->env, blockedKeyword);
    ng_add_alloc(jblockedKeyword, "jblockedKeyword");

    (*args->env)->CallVoidMethod(args->env, args->instance, midHttpPktBlockedReport, jblockedKeyword, uid);

    jniCheckException(args->env);

    (*args->env)->DeleteLocalRef(args->env, clsService);
    (*args->env)->DeleteLocalRef(args->env, jblockedKeyword);
    ng_delete_alloc(clsService, __FILE__, __LINE__);
    ng_delete_alloc(jblockedKeyword, __FILE__, __LINE__);

#ifdef PROFILE_JNI
    gettimeofday(&end, NULL);
    mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                (end.tv_usec - start.tv_usec) / 1000.0;
    if (mselapsed > PROFILE_JNI)
        log_android(ANDROID_LOG_WARN, "http_pkt_blocked_report %f", mselapsed);
#endif
}

JNIEXPORT jboolean JNICALL
Java_eu_faircode_netguard_ServiceSinkhole_jni_1register_1http_1hashfilter_1keyword(JNIEnv *env, jobject instance, jstring hash_keyword) {
    Keyword (char) kw;
    ACM_KEYWORD_SET (kw, (*env)->GetStringUTFChars(env, hash_keyword, 0), (*env)->GetStringUTFLength(env, hash_keyword));
    return ACM_register_keyword (ahoKH, kw);
}

JNIEXPORT jboolean JNICALL
Java_eu_faircode_netguard_ServiceSinkhole_jni_1deregister_1http_1hashfilter_1keyword(JNIEnv *env, jobject instance, jstring hash_keyword) {
    Keyword (char) kw;
    ACM_KEYWORD_SET (kw, (*env)->GetStringUTFChars(env, hash_keyword, 0), (*env)->GetStringUTFLength(env, hash_keyword));
    return ACM_unregister_keyword(ahoKH, kw);
}

static jmethodID midHttpPktKeywordHashedReport = NULL;

void http_pkt_keyword_hashed_report(const struct arguments *args, const char *hashedKeyword, jint uid) {
#ifdef PROFILE_JNI
    float mselapsed;
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif

    jclass clsService = (*args->env)->GetObjectClass(args->env, args->instance);
    ng_add_alloc(clsService, "clsService");

    const char *signature = "(Ljava/lang/String;I)V";
    if (midHttpPktKeywordHashedReport == NULL)
        midHttpPktKeywordHashedReport = jniGetMethodID(args->env, clsService, "httpPktKeywordHashedReport", signature);

    jstring jhashedKeyword = (*args->env)->NewStringUTF(args->env, hashedKeyword);
    ng_add_alloc(jhashedKeyword, "jhashedKeyword");

    (*args->env)->CallVoidMethod(args->env, args->instance, midHttpPktKeywordHashedReport, jhashedKeyword, uid);

    jniCheckException(args->env);

    (*args->env)->DeleteLocalRef(args->env, clsService);
    (*args->env)->DeleteLocalRef(args->env, jhashedKeyword);
    ng_delete_alloc(clsService, __FILE__, __LINE__);
    ng_delete_alloc(jhashedKeyword, __FILE__, __LINE__);

#ifdef PROFILE_JNI
    gettimeofday(&end, NULL);
    mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                (end.tv_usec - start.tv_usec) / 1000.0;
    if (mselapsed > PROFILE_JNI)
        log_android(ANDROID_LOG_WARN, "http_pkt_keyword_hashed_report %f", mselapsed);
#endif
}

static jmethodID midIsURLPathBlocked = NULL;

jboolean is_url_path_blocked(const struct arguments *args, const char *urlPath, jint uid) {
#ifdef PROFILE_JNI
    float mselapsed;
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif

    jclass clsService = (*args->env)->GetObjectClass(args->env, args->instance);
    ng_add_alloc(clsService, "clsService");

    const char *signature = "(Ljava/lang/String;I)Z";
    if (midIsURLPathBlocked == NULL)
        midIsURLPathBlocked = jniGetMethodID(args->env, clsService, "isURLPathBlocked", signature);

    jstring jurlPath = (*args->env)->NewStringUTF(args->env, urlPath);
    ng_add_alloc(jurlPath, "jurlPath");

    jboolean jallowed = (*args->env)->CallBooleanMethod(
            args->env, args->instance, midIsURLPathBlocked, jurlPath, uid);
    jniCheckException(args->env);

    (*args->env)->DeleteLocalRef(args->env, jurlPath);
    (*args->env)->DeleteLocalRef(args->env, clsService);
    ng_delete_alloc(jurlPath, __FILE__, __LINE__);
    ng_delete_alloc(clsService, __FILE__, __LINE__);

#ifdef PROFILE_JNI
    gettimeofday(&end, NULL);
    mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                (end.tv_usec - start.tv_usec) / 1000.0;
    if (mselapsed > PROFILE_JNI)
        log_android(ANDROID_LOG_WARN, "is_url_path_blocked %f", mselapsed);
#endif

    return jallowed;
}

/* Simple HTTP filter
 *
 * @Params
 *
 *  @{in} const struct arguments *args       - Context
 *  @{in} const uint8_t *data                - TCP/UDP payload
 *  @{in} uint16_t datalen                   - TCP/UDP payload length
 *  @{in} jint uid                           - UID
 *
 *  @{return} true   - process traffic
 *            false  - dismiss traffic
 *
 *  @Brief ...
 */
uint8_t httpFilter(const struct arguments *args, uint8_t *data, uint16_t datalen, jint uid) {

    char  urlPath[HTTP_URL_LENGTH_MAX+1];
    char  ct[NAME_MAX+1];
    char  httpMethod[10];
    char  blockedKeyword[NAME_MAX+1];

    int bk_num = 0;
    int kh_num = 0;

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
        // Currently do not parse Host separately, and only have it in the urlPath in case proxy is used.
        if (((urlPathLength > 1) && // Request to domain is blocked separately
             is_url_path_blocked(args, urlPath, uid))) { //Check path is allowed

            log_android(ANDROID_LOG_DEBUG, "HTTP %s request has been blocked for (%s), UID %d!", httpMethod, urlPath, uid);
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

    /* Parse pkt content */
    bk_num = ACM_nb_keywords(ahoMachine);
    kh_num = ACM_nb_keywords(ahoKH);

    if ((ahoMachine && bk_num) ||   /* Check for disallowed keywords */
          (ahoKH && kh_num)) {        /* Check for hashed keywords */

        // block kw init
        const ACState(char) *state = ACM_reset(ahoMachine);
        MatchHolder (char) match;
        size_t nb_matches = 0;
        void *match_ptr;

        ACM_MATCH_INIT (match);

        // hash kw init
        const ACState(char) *kh_state = ACM_reset(ahoKH);
        MatchHolder (char) kh_match;
        size_t kh_matches = 0;
        void *kh_match_ptr;

        ACM_MATCH_INIT (kh_match);

        // handle packet
        //
        //  If forbidden keyword matched drop the pkt.
        //  If keyword for hashing matches hash it and proceed
        //
        for (char *c = data; *c; c++) {
            // block keywords handling
            if (bk_num) { // There is sence to look up for blocked keywords
                nb_matches += ACM_match(state, *c);
                if (nb_matches)  // So we get first match
                {
                    // 10. If matches were found, retrieve them calling `ACM_get_match ()` for each match.
                    //     An optional fourth argument will point to the pointer to the value associated with the matching keyword.
                    ACM_get_match (state, 0, &match, &match_ptr);
                    size_t kwLenght = ACM_MATCH_LENGTH (match);
                    for (size_t indx = 0;
                         (indx < kwLenght) && (indx < sizeof(blockedKeyword)); indx++) {
                        blockedKeyword[indx] = ACM_MATCH_SYMBOLS(match)[indx];
                    }
                    http_pkt_blocked_report(args, blockedKeyword, uid);
                    log_android(ANDROID_LOG_DEBUG,
                                "HTTP packet has been blocked! Contains forbidden keywords!");
                    return false;
                } //if nb_matches
            }

            if (kh_num) {  // There is sence to look up for hashed keywords
                kh_matches = ACM_match(kh_state, *c);
                if (kh_matches) {
                    int kh_lenght = 0;
                    ACM_get_match (kh_state, 0, &kh_match, &kh_match_ptr);
                    kh_lenght = ACM_MATCH_LENGTH (kh_match);

                    for (int indx = kh_lenght - 1; (indx >= 0) && (indx < sizeof(blockedKeyword)); indx--) {
                        blockedKeyword[indx] = ACM_MATCH_SYMBOLS(kh_match)[indx];
                        *(c - indx) = '*';  // HASH --> It's not random, but much faster... To be discussed...
                    }

                    http_pkt_keyword_hashed_report(args, blockedKeyword, uid);
                    ACM_MATCH_RELEASE(kh_match); // we need to handle few 'same' keywords if matches...
                    kh_matches = 0;
                    memset(blockedKeyword, 0x00, sizeof(blockedKeyword));
                } //if kh_matches
            }
        } //for
    } //if

    return true;
}
