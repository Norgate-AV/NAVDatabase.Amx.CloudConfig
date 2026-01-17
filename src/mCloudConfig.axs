MODULE_NAME='mCloudConfig'  (
                                dev vdvObject,
                                dev dvPort
                            )

(***********************************************************)
#DEFINE USING_NAV_MODULE_BASE_CALLBACKS
#DEFINE USING_NAV_MODULE_BASE_PROPERTY_EVENT_CALLBACK
#DEFINE USING_NAV_HTTP_RESPONSE_HEADERS_CALLBACK
#DEFINE USING_NAV_HTTP_RESPONSE_BODY_CALLBACK
#DEFINE USING_NAV_HTTP_RESPONSE_COMPLETE_CALLBACK
#include 'NAVFoundation.ModuleBase.axi'
#include 'NAVFoundation.ErrorLogUtils.axi'
#include 'NAVFoundation.FileUtils.axi'
#include 'NAVFoundation.PathUtils.axi'
#include 'NAVFoundation.Url.axi'
#include 'NAVFoundation.HttpUtils.axi'
#include 'NAVFoundation.StringUtils.axi'
#include 'NAVFoundation.Cryptography.Sha256.axi'
#include 'NAVFoundation.Encoding.Base64.axi'
#include 'NAVFoundation.SocketUtils.axi'
#include 'NAVFoundation.NetUtils.axi'
#include 'NAVFoundation.TimelineUtils.axi'
#include 'NAVFoundation.Regex.axi'

/*
 _   _                       _          ___     __
| \ | | ___  _ __ __ _  __ _| |_ ___   / \ \   / /
|  \| |/ _ \| '__/ _` |/ _` | __/ _ \ / _ \ \ / /
| |\  | (_) | | | (_| | (_| | ||  __// ___ \ V /
|_| \_|\___/|_|  \__, |\__,_|\__\___/_/   \_\_/
                 |___/

MIT License

Copyright (c) 2010-2026 Norgate AV

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

(***********************************************************)
(*          DEVICE NUMBER DEFINITIONS GO BELOW             *)
(***********************************************************)
DEFINE_DEVICE

(***********************************************************)
(*               CONSTANT DEFINITIONS GO BELOW             *)
(***********************************************************)
DEFINE_CONSTANT

constant char DEFAULT_FILE_PATH[]      = './config.ini'

constant long TL_CONFIG_CHECK = 1
constant long TL_CONFIG_CHECK_INTERVAL = 300000  // 5 minutes


(***********************************************************)
(*              DATA TYPE DEFINITIONS GO BELOW             *)
(***********************************************************)
DEFINE_TYPE

struct _Context {
    char ServerEndpoint[255]
    _NAVCredential ServerCredential
    char FilePath[255]
    char FileName[100]

    char Request[NAV_HTTP_MAX_REQUEST_LENGTH]
    char LastModified[NAV_MAX_CHARS]
    char ETag[NAV_MAX_CHARS]

    char CurrentHash[64]  // SHA-256 hash is 64 chars

    _NAVHttpResponse Response
    _NAVUrl Url  // Parsed URL for socket connection

    char PendingGetRequest  // Flag to trigger GET after HEAD completes
}


(***********************************************************)
(*               VARIABLE DEFINITIONS GO BELOW             *)
(***********************************************************)
DEFINE_VARIABLE

volatile _NAVModule module
volatile _Context context
volatile _NAVHttpResponseBuffer rxBuffer


(***********************************************************)
(*               LATCHING DEFINITIONS GO BELOW             *)
(***********************************************************)
DEFINE_LATCHING

(***********************************************************)
(*       MUTUALLY EXCLUSIVE DEFINITIONS GO BELOW           *)
(***********************************************************)
DEFINE_MUTUALLY_EXCLUSIVE

(***********************************************************)
(*        SUBROUTINE/FUNCTION DEFINITIONS GO BELOW         *)
(***********************************************************)
(* EXAMPLE: DEFINE_FUNCTION <RETURN_TYPE> <NAME> (<PARAMETERS>) *)
(* EXAMPLE: DEFINE_CALL '<NAME>' (<PARAMETERS>) *)

define_function char RequestConfig(char method[]) {
    stack_var _NAVUrl url
    stack_var _NAVHttpRequest request
    stack_var _NAVController controller
    stack_var char hostname[256]

    if (!length_array(context.ServerEndpoint)) {
        NAVErrorLog(NAV_LOG_LEVEL_ERROR,
                    "GetLogPrefix(), 'Server endpoint URL is not configured. Cannot request config.'")
        return false
    }

    if (!length_array(context.FilePath)) {
        NAVErrorLog(NAV_LOG_LEVEL_ERROR,
                    "GetLogPrefix(), 'File path is not configured. Cannot request config.'")
        return false
    }

    if (!length_array(context.FileName)) {
        NAVErrorLog(NAV_LOG_LEVEL_ERROR,
                    "GetLogPrefix(), 'File name is not configured. Cannot request config.'")
        return false
    }

    // Get the hostname of the device
    NAVGetControllerInformation(controller)
    hostname = controller.IP.Hostname

    if (!NAVParseUrl("context.ServerEndpoint, '/', hostname, '/', context.FileName", url)) {
        NAVErrorLog(NAV_LOG_LEVEL_ERROR,
                    "GetLogPrefix(), 'Error parsing config URL'")
        return false
    }

    // Store URL in context for socket connection handling
    context.Url = url

    if (!NAVHttpRequestInit(request, method, url, '')) {
        NAVErrorLog(NAV_LOG_LEVEL_ERROR,
                    "GetLogPrefix(), 'Error initializing HTTP request for config'")
        return false
    }

    // Always close the connection after the request
    NAVHttpRequestAddHeader(request,
                            NAV_HTTP_HEADER_CONNECTION,
                            'close')

    if (length_array(context.ServerCredential.Username) &&
        length_array(context.ServerCredential.Password)) {
        NAVHttpRequestAddHeader(request,
                                NAV_HTTP_HEADER_AUTHORIZATION,
                                "'Basic ', NAVBase64Encode("context.ServerCredential.Username, ':', context.ServerCredential.Password")")
    }

    if (!NAVHttpBuildRequest(request, context.Request)) {
        NAVErrorLog(NAV_LOG_LEVEL_ERROR,
                    "GetLogPrefix(), 'Error building HTTP request for config'")
        return false
    }

    // SendRequest will handle socket opening if needed
    SendRequest(context.Request)

    return true
}


define_function char ParseHeadResponse(char data[], _NAVHttpResponse response) {
    stack_var char lastModified[NAV_MAX_CHARS]
    stack_var char etag[NAV_MAX_CHARS]

    // Initialize response
    NAVHttpResponseInit(response)

    if (!NAVHttpParseResponse(data, response)) {
        NAVErrorLog(NAV_LOG_LEVEL_ERROR,
                    "GetLogPrefix(), 'Error parsing config server response'")
        return false
    }

    if (response.Status.Code != NAV_HTTP_STATUS_CODE_SUCCESS_OK) {
        NAVErrorLog(NAV_LOG_LEVEL_ERROR,
                    "GetLogPrefix(), 'Config server returned error code: ', itoa(response.Status.Code), ' ', NAVHttpGetStatusMessage(response.Status.Code)")
        return false
    }

    return true
}


define_function char ShouldFetchConfig(_NAVHttpResponse response) {
    stack_var char etag[NAV_MAX_CHARS]
    stack_var char lastModified[NAV_MAX_CHARS]

    // Extract cache headers
    if (NAVHttpHeaderKeyExists(response.Headers, NAV_HTTP_HEADER_ETAG)) {
        etag = NAVHttpGetHeaderValue(response.Headers, NAV_HTTP_HEADER_ETAG)
    }

    if (NAVHttpHeaderKeyExists(response.Headers, NAV_HTTP_HEADER_LAST_MODIFIED)) {
        lastModified = NAVHttpGetHeaderValue(response.Headers, NAV_HTTP_HEADER_LAST_MODIFIED)
    }

    // Check if cache is still fresh
    if (etag == context.ETag && lastModified == context.LastModified) {
        NAVErrorLog(NAV_LOG_LEVEL_INFO,
                    "GetLogPrefix(), 'Config has not changed. Cache is fresh.'")
        return false  // Don't fetch
    }

    // Cache has changed - update and return true
    context.ETag = etag
    context.LastModified = lastModified
    NAVErrorLog(NAV_LOG_LEVEL_INFO,
                "GetLogPrefix(), 'Config has changed. Will fetch.'")
    return true  // Should fetch
}


define_function char ParseGetResponse(char data[], _NAVHttpResponse response) {
    // Initialize response
    NAVHttpResponseInit(response)

    if (!NAVHttpParseResponse(data, response)) {
        NAVErrorLog(NAV_LOG_LEVEL_ERROR,
                    "GetLogPrefix(), 'Error parsing config server response'")
        return false
    }

    if (response.Status.Code != NAV_HTTP_STATUS_CODE_SUCCESS_OK) {
        NAVErrorLog(NAV_LOG_LEVEL_ERROR,
                    "GetLogPrefix(), 'Config server returned error code: ', itoa(response.Status.Code), ' ', NAVHttpGetStatusMessage(response.Status.Code)")

        switch (response.Status.Code) {
            case NAV_HTTP_STATUS_CODE_CLIENT_ERROR_UNAUTHORIZED: {
                NAVErrorLog(NAV_LOG_LEVEL_ERROR,
                            "GetLogPrefix(), 'Unauthorized access to config server. Check USERNAME and PASSWORD.'")
            }
        }

        return false
    }

    if (NAVHttpHeaderKeyExists(response.Headers, NAV_HTTP_HEADER_ETAG)) {
        context.ETag = NAVHttpGetHeaderValue(response.Headers, NAV_HTTP_HEADER_ETAG)
    }

    if (NAVHttpHeaderKeyExists(response.Headers, NAV_HTTP_HEADER_LAST_MODIFIED)) {
        context.LastModified = NAVHttpGetHeaderValue(response.Headers, NAV_HTTP_HEADER_LAST_MODIFIED)
    }

    return true
}


define_function char ParseGetResponseBody(char data[], _NAVHttpResponse response) {
    if (!NAVHttpParseResponseBody(data, response)) {
        NAVErrorLog(NAV_LOG_LEVEL_ERROR,
                    "GetLogPrefix(), 'Error parsing config server response body'")
        return false
    }

    if (!length_array(response.Body)) {
        NAVErrorLog(NAV_LOG_LEVEL_WARNING,
                    "GetLogPrefix(), 'Config server response body is empty'")
        return false
    }

    NAVLog("GetLogPrefix(), 'Successfully retrieved config file from server. Size: ', itoa(length_array(response.Body)), ' bytes'")

    return true
}


define_function char[64] CalculateHash(char data[]) {
    stack_var char hash[64]

    hash = NAVHexToString(NAVSha256GetHash(data))

    if (!length_array(hash)) {
        NAVErrorLog(NAV_LOG_LEVEL_ERROR,
                    "GetLogPrefix(), 'Error calculating hash of config body'")
        return ''
    }

    return hash
}


define_function char ConfigHasChanged(char hash[]) {
    if (hash == context.CurrentHash) {
        NAVErrorLog(NAV_LOG_LEVEL_INFO,
                    "GetLogPrefix(), 'Config file has not changed. Skipping save.'")
        return false
    }

    if (length_array(context.CurrentHash)) {
        NAVErrorLog(NAV_LOG_LEVEL_INFO,
                    "GetLogPrefix(), 'Config file has changed.'")
        NAVErrorLog(NAV_LOG_LEVEL_INFO,
                    "GetLogPrefix(), 'Old hash: ', context.CurrentHash")
        NAVErrorLog(NAV_LOG_LEVEL_INFO,
                    "GetLogPrefix(), 'New hash: ', hash")
    }
    else {
        NAVErrorLog(NAV_LOG_LEVEL_INFO,
                    "GetLogPrefix(), 'First time reading config file.'")
        NAVErrorLog(NAV_LOG_LEVEL_INFO,
                    "GetLogPrefix(), 'Hash: ', hash")
    }

    context.CurrentHash = hash
    return true
}


define_function char SaveConfigFile(char content[]) {
    if (!NAVFileWrite(context.FilePath, content)) {
        NAVErrorLog(NAV_LOG_LEVEL_ERROR,
                    "GetLogPrefix(), 'Error saving config file to: ', context.FilePath")
        return false
    }

    NAVLog("GetLogPrefix(), 'Successfully saved config file: ', context.FilePath")
    return true
}


define_function char ProcessConfigBody(char body[]) {
    stack_var char hash[64]

    hash = CalculateHash(body)
    if (!length_array(hash)) {
        return false
    }

    if (!ConfigHasChanged(hash)) {
        return true
    }

    if (!SaveConfigFile(body)) {
        return false
    }

    // Notify other modules/devices of the updated config
    Notify("'CONFIG-UPDATED,', context.FilePath")

    NAVTimelineStart(TL_CONFIG_CHECK,
                     module.Device.SocketConnection.Interval,
                     TIMELINE_ABSOLUTE,
                     TIMELINE_REPEAT)

    return true
}


define_function CleanUp() {
    context.Request = ''  // Clear request for next use
}


#IF_DEFINED USING_NAV_HTTP_RESPONSE_HEADERS_CALLBACK
define_function NAVHttpResponseHeadersCallback(_NAVHttpResponseHeadersResult result) {
    // Handle HEAD vs GET responses using existing parsing functions
    select {
        active (NAVStartsWith(context.Request, NAV_HTTP_METHOD_HEAD)): {
            NAVErrorLog(NAV_LOG_LEVEL_DEBUG,
                        "GetLogPrefix(), 'Processing HEAD response from config server...'")

            if (!ParseHeadResponse(result.Data, context.Response)) {
                NAVErrorLog(NAV_LOG_LEVEL_ERROR,
                            "GetLogPrefix(), 'Failed to parse HEAD response'")
                return
            }

            // Check if config has changed and should be fetched
            if (ShouldFetchConfig(context.Response)) {
                // Can't send GET on same connection - mark for reconnect
                context.PendingGetRequest = true
            }
            // Don't transition to body state - HEAD responses have no body
        }
        active (NAVStartsWith(context.Request, NAV_HTTP_METHOD_GET)): {
            NAVErrorLog(NAV_LOG_LEVEL_DEBUG,
                        "GetLogPrefix(), 'Processing GET response from config server...'")

            if (!ParseGetResponse(result.Data, context.Response)) {
                NAVErrorLog(NAV_LOG_LEVEL_ERROR,
                            "GetLogPrefix(), 'Failed to parse GET response'")
                return
            }

            if (!context.Response.ContentLength) {
                NAVErrorLog(NAV_LOG_LEVEL_ERROR,
                            "GetLogPrefix(), 'GET response has no body to process.'")
                return
            }

            // Transition to body parsing state
            rxBuffer.ContentLength = context.Response.ContentLength
            rxBuffer.State = NAV_HTTP_STATE_PARSING_BODY
        }
    }
}
#END_IF


#IF_DEFINED USING_NAV_HTTP_RESPONSE_BODY_CALLBACK
define_function NAVHttpResponseBodyCallback(_NAVHttpResponseBodyResult result) {
    NAVErrorLog(NAV_LOG_LEVEL_DEBUG,
                "GetLogPrefix(), 'Processing GET response body from config server...'")

    // Parse body using existing function
    if (!ParseGetResponseBody(result.Data, context.Response)) {
        NAVErrorLog(NAV_LOG_LEVEL_ERROR,
                    "GetLogPrefix(), 'Failed to parse response body'")
        return
    }

    // Process the complete response body
    ProcessConfigBody(context.Response.Body)
}
#END_IF


#IF_DEFINED USING_NAV_HTTP_RESPONSE_COMPLETE_CALLBACK
define_function NAVHttpResponseCompleteCallback(_NAVHttpResponseCompleteResult result) {
    // Cleanup after response processing is complete
    CleanUp()
}
#END_IF


define_function NAVModulePropertyEventCallback(_NAVModulePropertyEvent event) {
    switch (event.Name) {
        case 'SERVER_ENDPOINT_URL': {
            // Update the server endpoint URL
            stack_var _NAVUrl url
            stack_var char value[255]

            value = NAVTrimString(event.Args[1])

            if (!NAVParseUrl(value, url)) {
                NAVErrorLog(NAV_LOG_LEVEL_ERROR,
                            "GetLogPrefix(), 'Invalid server endpoint URL provided.'")
                return
            }

            context.ServerEndpoint = value
        }
        case 'USERNAME': {
            // Update the server credential username
            context.ServerCredential.Username = NAVTrimString(event.Args[1])
        }
        case 'PASSWORD': {
            // Update the server credential password
            context.ServerCredential.Password = NAVTrimString(event.Args[1])
        }
        case 'FILE_PATH': {
            // Update the file path
            context.FilePath = NAVTrimString(event.Args[1])

            if (!length_array(context.FileName)) {
                // By default should use NAVPathBaseName to extract the file name from FILE_PATH
                context.FileName = NAVPathBaseName(context.FilePath)
            }
        }
        case 'FILE_NAME': {
            // Update the file name
            // By default should use NAVPathBaseName to extract the file name from FILE_PATH
            context.FileName = NAVTrimString(event.Args[1])
        }
        case 'HASH': {
            // Update the current hash
            HandleHashUpdate(NAVTrimString(event.Args[1]))
        }
    }
}


define_function HandleHashUpdate(char hash[]) {
    if (!NAVRegexTest('/^[a-fA-F0-9]{64}$/', hash)) {
        NAVErrorLog(NAV_LOG_LEVEL_ERROR,
                    "GetLogPrefix(), 'Invalid hash format received.'")
        return
    }

    context.CurrentHash = hash
    NAVErrorLog(NAV_LOG_LEVEL_INFO,
                "GetLogPrefix(), 'Updated current config hash to: ', context.CurrentHash")
}


define_function Notify(char message[]) {
    // Notify other modules/devices of events
    send_string vdvObject, message
}


define_function SendRequest(char request[]) {
    if (!length_array(request)) {
        return
    }

    if (module.Device.SocketConnection.IsConnected) {
        send_string dvPort, request
        return
    }

    // Socket not connected - open it based on URL scheme
    switch (context.Url.Scheme) {
        case NAV_URL_SCHEME_HTTP: {
            NAVClientSocketOpen(module.Device.SocketConnection.Socket,
                                context.Url.Host,
                                context.Url.Port,
                                IP_TCP)
        }
        case NAV_URL_SCHEME_HTTPS: {
            NAVClientTlsSocketOpen(module.Device.SocketConnection.Socket,
                                   context.Url.Host,
                                   context.Url.Port,
                                   0)
        }
        default: {
            NAVErrorLog(NAV_LOG_LEVEL_ERROR,
                        "GetLogPrefix(), 'Unsupported URL scheme for config server: ', context.Url.Scheme")
        }
    }

    // Request will be sent when socket connects via HandleSocketOnline
}


define_function HandleSocketOnline(tdata data) {
    module.Device.SocketConnection.IsConnected = true
    NAVErrorLog(NAV_LOG_LEVEL_DEBUG,
                "GetLogPrefix(), 'Connected to config server'")

    SendRequest(context.Request)
}


define_function HandleSocketOffline(tdata data) {
    module.Device.SocketConnection.IsConnected = false
    NAVErrorLog(NAV_LOG_LEVEL_DEBUG,
                "GetLogPrefix(), 'Disconnected from config server'")

    // If GET is pending after HEAD, trigger reconnect for GET request
    if (context.PendingGetRequest) {
        context.PendingGetRequest = false
        wait 5 {  // Brief delay to ensure socket fully closed
            NAVLog("GetLogPrefix(), 'Requesting config download...'")
            RequestConfig(NAV_HTTP_METHOD_GET)
        }
    }
}


define_function HandleSocketError(tdata data) {
    module.Device.SocketConnection.IsConnected = false
    NAVErrorLog(NAV_LOG_LEVEL_ERROR,
                "GetLogPrefix(), 'Socket error: ', NAVGetSocketError(type_cast(data.number))")
}


define_function char[NAV_MAX_BUFFER] GetLogPrefix() {
    return "'mCloudConfig [', NAVDeviceToString(dvPort), '] => '"
}


(***********************************************************)
(*                STARTUP CODE GOES BELOW                  *)
(***********************************************************)
DEFINE_START {
    NAVModuleInit(module)

    NAVHttpResponseBufferInit(rxBuffer)
    create_buffer dvPort, rxBuffer.Data

    module.Device.SocketConnection.Socket = dvPort.PORT
    module.Device.SocketConnection.Interval[1] = TL_CONFIG_CHECK_INTERVAL

    context.FilePath = DEFAULT_FILE_PATH
    context.FileName = NAVPathBaseName(context.FilePath)
}


(***********************************************************)
(*                THE EVENTS GO BELOW                      *)
(***********************************************************)
DEFINE_EVENT

data_event[dvPort] {
    online: {
        HandleSocketOnline(data)
    }
    offline: {
        HandleSocketOffline(data)
    }
    onerror: {
        HandleSocketError(data)
    }
    string: {
        NAVHttpProcessResponseBuffer(rxBuffer)
    }
}


data_event[vdvObject] {
    command: {
        stack_var _NAVSnapiMessage message

        NAVParseSnapiMessage(data.text, message)

        switch (message.Header) {
            case 'CONFIG': {
                switch (message.Parameter[1]) {
                    case 'CHECK': {
                        // Manually trigger a config check
                        NAVErrorLog(NAV_LOG_LEVEL_INFO,
                                    "GetLogPrefix(), 'Manual trigger: Checking for updated configuration...'")

                        if (!RequestConfig(NAV_HTTP_METHOD_HEAD)) {
                            NAVErrorLog(NAV_LOG_LEVEL_WARNING,
                                        "GetLogPrefix(), 'Failed to check for updated configuration.'")
                        }
                    }
                    case 'GET': {
                        // Manually trigger a config download
                        NAVErrorLog(NAV_LOG_LEVEL_INFO,
                                    "GetLogPrefix(), 'Manual trigger: Downloading configuration...'")

                        if (!RequestConfig(NAV_HTTP_METHOD_GET)) {
                            NAVErrorLog(NAV_LOG_LEVEL_WARNING,
                                        "GetLogPrefix(), 'Failed to download configuration.'")
                        }

                        if (!timeline_active(TL_CONFIG_CHECK)) {
                            NAVTimelineStart(TL_CONFIG_CHECK,
                                             module.Device.SocketConnection.Interval,
                                             TIMELINE_ABSOLUTE,
                                             TIMELINE_REPEAT)
                        }
                    }
                }
            }
            case 'MONITOR': {
                switch (message.Parameter[1]) {
                    case 'START': {
                        if (!timeline_active(TL_CONFIG_CHECK)) {
                            NAVErrorLog(NAV_LOG_LEVEL_INFO,
                                        "GetLogPrefix(), 'Starting periodic config monitoring...'")
                            NAVTimelineStart(TL_CONFIG_CHECK,
                                             module.Device.SocketConnection.Interval,
                                             TIMELINE_ABSOLUTE,
                                             TIMELINE_REPEAT)
                            NAVErrorLog(NAV_LOG_LEVEL_INFO,
                                        "GetLogPrefix(), 'Config monitoring started. Checking every ', itoa(TL_CONFIG_CHECK_INTERVAL / 1000), ' seconds.'")
                        }
                    }
                    case 'STOP': {
                        if (timeline_active(TL_CONFIG_CHECK)) {
                            NAVErrorLog(NAV_LOG_LEVEL_INFO,
                                        "GetLogPrefix(), 'Stopping periodic config monitoring...'")
                            NAVTimelineStop(TL_CONFIG_CHECK)
                            NAVErrorLog(NAV_LOG_LEVEL_INFO,
                                        "GetLogPrefix(), 'Config monitoring stopped.'")
                        }
                    }
                }
            }
        }
    }
}


timeline_event[TL_CONFIG_CHECK] {
    NAVErrorLog(NAV_LOG_LEVEL_INFO,
                "GetLogPrefix(), 'Checking for updated configuration...'")

    if (!RequestConfig(NAV_HTTP_METHOD_HEAD)) {
        NAVErrorLog(NAV_LOG_LEVEL_WARNING,
                    "GetLogPrefix(), 'Failed to check for updated configuration.'")
    }
}


(***********************************************************)
(*                     END OF PROGRAM                      *)
(*        DO NOT PUT ANY CODE BELOW THIS COMMENT           *)
(***********************************************************)
