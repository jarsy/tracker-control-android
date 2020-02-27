/*
 *  @FileName  http.c
 *
 *  @Brief     Fragments of HTTP filtering functionality.
 */

#include "netguard.h"

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
uint8_t httpFilter(const struct arguments *args, const uint8_t *data, uint16_t datalen) {

    char  urlPath[HTTP_URL_LENGTH_MAX+1];
    char  ct[NAME_MAX+1];
    char  httpMethod[10];

    memset(urlPath, 0x00, sizeof(urlPath));
    memset(ct,      0x00, sizeof(ct));

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

        // Currently do not parse Host separately, and only have it in the urlPath in case proxy is used.

        if (((strlen(urlPath) > 1) && // Request to domain is blocked separately
             !is_url_path_blocked(args, urlPath)) || //Check path is allowed
            ((strlen(ct) > 0) && !is_content_type_blocked(args, ct))) {
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

    return true;
}





