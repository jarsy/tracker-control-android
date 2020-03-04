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

/* Simple HTTP filter
 *
 * @Params
 *
 *  @{in} const struct arguments *args       - Context
 *  @{in} const uint8_t *data                - TCP/UDP payload
 *  @{in} uint16_t datalen                   - TCP/UDP payload length

 *
 *  @{return} true   - process traffic
 *            false  - dismiss traffic
 *
 *  @Brief ...
 */
uint8_t httpFilter(const struct arguments *args, const uint8_t *data, uint16_t datalen, int uid) {

    char  urlPath[HTTP_URL_LENGTH_MAX+1];
    char  ct[NAME_MAX+1];
    char  httpMethod[10];

    memset(urlPath, 0x00, sizeof(urlPath));
    memset(ct,      0x00, sizeof(ct));

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
             !is_url_path_blocked(args, urlPath, uid))  //Check path is allowed
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
        const ACState(char)
        *state = ACM_reset(ahoMachine);

        size_t nb_matches = 0;
        for (char *c = data; *c; c++) {
            nb_matches += ACM_match(state, *c);
        }

        if (nb_matches) {
            log_android(ANDROID_LOG_DEBUG, "HTTP packet has been blocked! Contained do not allowed keywords!");
            return false;
        }
    }

    return true;
}





