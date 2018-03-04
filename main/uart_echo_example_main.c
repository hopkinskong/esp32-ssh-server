/* UART Echo Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/uart.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_spi_flash.h"
#include "esp_event_loop.h"
#include <freertos/event_groups.h>
#include "esp_wifi.h"
#include "nvs.h"
#include "nvs_flash.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssh/ssh.h>
#include <wolfssh/test.h>
#include <wolfssh/misc.h>

#include "server-key-rsa.h"

static const char* TAG = "MAIN";

static uint8_t *UARTInData;

/**
 * This is an example which echos any data it receives on UART1 back to the sender,
 * with hardware flow control turned off. It does not use UART driver event queue.
 *
 * - Port: UART1
 * - Receive (Rx) buffer: on
 * - Transmit (Tx) buffer: off
 * - Flow control: off
 * - Event queue: off
 * - Pin assignment: see defines below
 */

#define ECHO_TEST_TXD  (GPIO_NUM_4)
#define ECHO_TEST_RXD  (GPIO_NUM_5)
#define ECHO_TEST_RTS  (UART_PIN_NO_CHANGE)
#define ECHO_TEST_CTS  (UART_PIN_NO_CHANGE)

#define BUF_SIZE (1024)

#define EXAMPLE_BUFFER_SZ 4096

#define SSH_GREETING_MESSAGE (byte*)((char*)"Welcome to ESP32 SSH Server!\r\nYou have now logged in!\r\n\r\n")

THREAD_RETURN WOLFSSH_THREAD echoserver_test(void* args);

static INLINE void c32toa(word32 u32, byte* c)
{
    c[0] = (u32 >> 24) & 0xff;
    c[1] = (u32 >> 16) & 0xff;
    c[2] = (u32 >>  8) & 0xff;
    c[3] =  u32 & 0xff;
}

/* Map user names to passwords */
/* Use arrays for username and p. The password or public key can
 * be hashed and the hash stored here. Then I won't need the type. */
typedef struct PwMap {
    byte type;
    byte username[32];
    word32 usernameSz;
    byte p[SHA256_DIGEST_SIZE];
    struct PwMap* next;
} PwMap;


typedef struct PwMapList {
    PwMap* head;
} PwMapList;


static PwMap* PwMapNew(PwMapList* list, byte type, const byte* username,
                       word32 usernameSz, const byte* p, word32 pSz)
{
    PwMap* map;

    map = (PwMap*)malloc(sizeof(PwMap));
    if (map != NULL) {
        Sha256 sha;
        byte flatSz[4];

        map->type = type;
        if (usernameSz >= sizeof(map->username))
            usernameSz = sizeof(map->username) - 1;
        memcpy(map->username, username, usernameSz + 1);
        map->username[usernameSz] = 0;
        map->usernameSz = usernameSz;

        wc_InitSha256(&sha);
        c32toa(pSz, flatSz);
        wc_Sha256Update(&sha, flatSz, sizeof(flatSz));
        wc_Sha256Update(&sha, p, pSz);
        wc_Sha256Final(&sha, map->p);

        map->next = list->head;
        list->head = map;
    }

    return map;
}


static void PwMapListDelete(PwMapList* list)
{
    if (list != NULL) {
        PwMap* head = list->head;

        while (head != NULL) {
            PwMap* cur = head;
            head = head->next;
            memset(cur, 0, sizeof(PwMap));
            free(cur);
        }
    }
}


static const char samplePasswordBuffer[] =
    "hopkins:hopkinsdev\n";


static int LoadPasswordBuffer(byte* buf, word32 bufSz, PwMapList* list)
{
    char* str = (char*)buf;
    char* delimiter;
    char* username;
    char* password;

    /* Each line of passwd.txt is in the format
     *     username:password\n
     * This function modifies the passed-in buffer. */

    if (list == NULL)
        return -1;

    if (buf == NULL || bufSz == 0)
        return 0;

    while (*str != 0) {
        delimiter = strchr(str, ':');
        username = str;
        *delimiter = 0;
        password = delimiter + 1;
        str = strchr(password, '\n');
        *str = 0;
        str++;
        if (PwMapNew(list, WOLFSSH_USERAUTH_PASSWORD,
                     (byte*)username, (word32)strlen(username),
                     (byte*)password, (word32)strlen(password)) == NULL ) {

            return -1;
        }
    }

    return 0;
}


static int wsUserAuth(byte authType,
                      WS_UserAuthData* authData,
                      void* ctx)
{
    PwMapList* list;
    PwMap* map;
    byte authHash[SHA256_DIGEST_SIZE];

    if (ctx == NULL) {
        fprintf(stderr, "wsUserAuth: ctx not set");
        return WOLFSSH_USERAUTH_FAILURE;
    }

    if (authType != WOLFSSH_USERAUTH_PASSWORD &&
        authType != WOLFSSH_USERAUTH_PUBLICKEY) {

        return WOLFSSH_USERAUTH_FAILURE;
    }

    /* Hash the password or public key with its length. */
    {
        Sha256 sha;
        byte flatSz[4];
        wc_InitSha256(&sha);
        if (authType == WOLFSSH_USERAUTH_PASSWORD) {
            c32toa(authData->sf.password.passwordSz, flatSz);
            wc_Sha256Update(&sha, flatSz, sizeof(flatSz));
            wc_Sha256Update(&sha,
                            authData->sf.password.password,
                            authData->sf.password.passwordSz);
        }
        else if (authType == WOLFSSH_USERAUTH_PUBLICKEY) {
            c32toa(authData->sf.publicKey.publicKeySz, flatSz);
            wc_Sha256Update(&sha, flatSz, sizeof(flatSz));
            wc_Sha256Update(&sha,
                            authData->sf.publicKey.publicKey,
                            authData->sf.publicKey.publicKeySz);
        }
        wc_Sha256Final(&sha, authHash);
    }

    list = (PwMapList*)ctx;
    map = list->head;

    while (map != NULL) {
        if (authData->usernameSz == map->usernameSz &&
            memcmp(authData->username, map->username, map->usernameSz) == 0) {

            if (authData->type == map->type) {
                if (memcmp(map->p, authHash, SHA256_DIGEST_SIZE) == 0) {
                    return WOLFSSH_USERAUTH_SUCCESS;
                }
                else {
                    return (authType == WOLFSSH_USERAUTH_PASSWORD ?
                            WOLFSSH_USERAUTH_INVALID_PASSWORD :
                            WOLFSSH_USERAUTH_INVALID_PUBLICKEY);
                }
            }
            else {
                return WOLFSSH_USERAUTH_INVALID_AUTHTYPE;
            }
        }
        map = map->next;
    }

    return WOLFSSH_USERAUTH_INVALID_USER;
}

static byte find_char(const byte* str, const byte* buf, word32 bufSz)
{
    const byte* cur;

    while (bufSz) {
        cur = str;
        while (*cur != '\0') {
            if (*cur == *buf)
                return *cur;
            cur++;
        }
        buf++;
        bufSz--;
    }

    return 0;
}

typedef struct {
    WOLFSSH* ssh;
    SOCKET_T fd;
    word32 id;
} thread_ctx_t;

static int dump_stats(thread_ctx_t* ctx)
{
    char stats[1024];
    word32 statsSz;
    word32 txCount, rxCount, seq, peerSeq;

    wolfSSH_GetStats(ctx->ssh, &txCount, &rxCount, &seq, &peerSeq);

    WSNPRINTF(stats, sizeof(stats),
            "Statistics for Thread #%u:\r\n"
            "  txCount = %u\r\n  rxCount = %u\r\n"
            "  seq = %u\r\n  peerSeq = %u\r\n",
            ctx->id, txCount, rxCount, seq, peerSeq);
    statsSz = (word32)strlen(stats);

    ESP_LOGI(TAG, "%s", stats);
    return wolfSSH_stream_send(ctx->ssh, (byte*)stats, statsSz);
}

static THREAD_RETURN WOLFSSH_THREAD server_worker(void* vArgs)
{
    thread_ctx_t* threadCtx = (thread_ctx_t*)vArgs;
    ESP_LOGI(TAG, "server_worker: entry");

    int acceptStatus;

    if ((acceptStatus = wolfSSH_accept(threadCtx->ssh)) == WS_SUCCESS) {
    	ESP_LOGW(TAG, "wolfSSH_accept == WS_SUCCESS");
        byte* buf = NULL;
        byte* tmpBuf;
        int bufSz, backlogSz = 0, rxSz, txSz, stop = 0, txSum;

        wolfSSH_stream_send(threadCtx->ssh, SSH_GREETING_MESSAGE, strlen((char *)SSH_GREETING_MESSAGE));
        buf = (byte*)malloc(1024);

        do {
        	rxSz = wolfSSH_stream_read(threadCtx->ssh, buf, 1024);
        	if(rxSz > 0) {
        		uart_write_bytes(UART_NUM_1, (const char *)buf, rxSz);
        	}else if(rxSz == WS_WANT_READ) { // TCP Blocking socket
        		// Use this "free" time to do Tx to ssh
        		int uartLen = uart_read_bytes(UART_NUM_1, UARTInData, BUF_SIZE, portTICK_RATE_MS);
        		wolfSSH_stream_send(threadCtx->ssh, UARTInData, uartLen);
        	}else{
        		stop = 1;
        	}
        } while(!stop);

        /*do {
            bufSz = EXAMPLE_BUFFER_SZ + backlogSz;

            tmpBuf = (byte*)realloc(buf, bufSz);
            if (tmpBuf == NULL)
                stop = 1;
            else
                buf = tmpBuf;


        	ESP_LOGI(TAG, "realloc buf completed, stop=%d", stop);




            if (!stop) {
                rxSz = wolfSSH_stream_read(threadCtx->ssh,
                                           buf + backlogSz,
                                           EXAMPLE_BUFFER_SZ);
                ESP_LOGI(TAG, "wolfSSH_stream_read: %d", rxSz);
                if (rxSz > 0) {
                    backlogSz += rxSz;
                    txSum = 0;
                    txSz = 0;

                    while (backlogSz != txSum && txSz >= 0 && !stop) {
                        txSz = wolfSSH_stream_send(threadCtx->ssh,
                                                   buf + txSum,
                                                   backlogSz - txSum);

                        if (txSz > 0) {
                            byte c;
                            const byte matches[] = { 0x03, 0x05, 0x06, 0x00 };

                            c = find_char(matches, buf + txSum, txSz);
                            switch (c) {
                                case 0x03:
                                    stop = 1;
                                    break;
                                case 0x06:
                                    if (wolfSSH_TriggerKeyExchange(threadCtx->ssh)
                                            != WS_SUCCESS)
                                        stop = 1;
                                    break;
                                case 0x05:
                                    if (dump_stats(threadCtx) <= 0)
                                        stop = 1;
                                    break;
                            }
                            txSum += txSz;
                        }
                        else if (txSz != WS_REKEYING)
                            stop = 1;
                    }

                    if (txSum < backlogSz)
                        memmove(buf, buf + txSum, backlogSz - txSum);
                    backlogSz -= txSum;
                }
                else
                    stop = 1;
            }
        } while (!stop);*/

        free(buf);
    }
    WCLOSESOCKET(threadCtx->fd);
    wolfSSH_free(threadCtx->ssh);
    free(threadCtx);


    ESP_LOGW(TAG, "server_worker: exit; accept status=%d", acceptStatus);

    return 0;
}


THREAD_RETURN WOLFSSH_THREAD echoserver_test(void* args)
{
    WOLFSSH_CTX* ctx = NULL;
    PwMapList pwMapList;
    SOCKET_T listenFd = 0;
    word32 defaultHighwater = 0x3FFF8000;
    word32 threadCount = 0;
    int multipleConnections = 1;
    int useEcc = 0;
    char ch;
    word16 port = wolfSshPort;

    multipleConnections = 1;
    useEcc = 0;
    port = 22;

    ESP_LOGI(TAG, "echoserver_test");
    if (wolfSSH_Init() != WS_SUCCESS) {
        ESP_LOGE(TAG, "Couldn't initialize wolfSSH.");
        exit(EXIT_FAILURE);
    }
    ESP_LOGI(TAG, "wolfSSH_Init OK");

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL) {
    	ESP_LOGE(TAG, "Couldn't allocate SSH CTX data.");
        exit(EXIT_FAILURE);
    }
    ESP_LOGI(TAG, "wolfSSH_CTX_new OK");

    memset(&pwMapList, 0, sizeof(pwMapList));
	wolfSSH_SetUserAuth(ctx, wsUserAuth);
    ESP_LOGI(TAG, "wolfSSH_SetUserAuth OK");
    wolfSSH_CTX_SetBanner(ctx, "ESP32 WolfSSH Server ");
    ESP_LOGI(TAG, "wolfSSH_CTX_SetBanner OK");


    {
		const char* bufName;
		byte buf[1200];
		word32 bufSz;

		memcpy(buf, server_key_rsa_der, server_key_rsa_der_len);
		bufSz = server_key_rsa_der_len;

		if (wolfSSH_CTX_UsePrivateKey_buffer(ctx, buf, bufSz, WOLFSSH_FORMAT_ASN1) < 0) {
	    	ESP_LOGE(TAG, "Couldn't use key buffer.");
			exit(EXIT_FAILURE);
		}
	    ESP_LOGI(TAG, "wolfSSH_CTX_UsePrivateKey_buffer OK");

		bufSz = (word32)strlen(samplePasswordBuffer);
		memcpy(buf, samplePasswordBuffer, bufSz);
		buf[bufSz] = 0;
		LoadPasswordBuffer(buf, bufSz, &pwMapList);
	    ESP_LOGI(TAG, "LoadPasswordBuffer OK");
	}

    // Sig: static INLINE void tcp_listen(SOCKET_T* sockfd, word16* port, int useAnyAddr)
	tcp_listen(&listenFd, &port, 1);

	do {
		SOCKET_T      clientFd = 0;
		SOCKADDR_IN_T clientAddr;
		socklen_t     clientAddrSz = sizeof(clientAddr);
		WOLFSSH*      ssh;
		thread_ctx_t* threadCtx;

		ESP_LOGI(TAG, "Main loop.");

		threadCtx = (thread_ctx_t*)malloc(sizeof(thread_ctx_t));
		if (threadCtx == NULL) {
			ESP_LOGE(TAG, "Couldn't allocate thread context data.");
			exit(EXIT_FAILURE);
		}
		ESP_LOGI(TAG, "threadCtx OK.");

		ssh = wolfSSH_new(ctx);
		ESP_LOGI(TAG, "Available HEAP Size: %d", esp_get_free_heap_size());
		if (ssh == NULL) {
			ESP_LOGE(TAG, "Couldn't allocate SSH data.");
			exit(EXIT_FAILURE);
		}
		ESP_LOGI(TAG, "wolfSSH_new OK.");
		wolfSSH_SetUserAuthCtx(ssh, &pwMapList);
		ESP_LOGI(TAG, "wolfSSH_SetUserAuthCtx OK.");
		/* Use the session object for its own highwater callback ctx */
		if (defaultHighwater > 0) {
			wolfSSH_SetHighwaterCtx(ssh, (void*)ssh);
			ESP_LOGI(TAG, "wolfSSH_SetHighwaterCtx OK.");
			wolfSSH_SetHighwater(ssh, defaultHighwater);
			ESP_LOGI(TAG, "wolfSSH_SetHighwater OK.");
		}

		//SignalTcpReady(NULL, port);

		clientFd = accept(listenFd, (struct sockaddr*)&clientAddr,
																 &clientAddrSz);
		if (clientFd == -1)
			err_sys("tcp accept failed");
		ESP_LOGI(TAG, "accept OK.");
		ESP_LOGW(TAG, "Setting to non-block");
	    fcntl(clientFd,F_SETFL,O_NONBLOCK);

		wolfSSH_set_fd(ssh, (int)clientFd);

		threadCtx->ssh = ssh;
		threadCtx->fd = clientFd;
		threadCtx->id = threadCount++;

		server_worker(threadCtx);

	} while (multipleConnections);

	PwMapListDelete(&pwMapList);
	wolfSSH_CTX_free(ctx);
	if (wolfSSH_Cleanup() != WS_SUCCESS) {
		fprintf(stderr, "Couldn't clean up wolfSSH.\n");
		exit(EXIT_FAILURE);
	}

    return 0;
}

static EventGroupHandle_t wifi_event_group;
const int CONNECTED_BIT = BIT0;
static ip4_addr_t s_ip_addr;

static esp_err_t event_handler(void *ctx, system_event_t *event)
{
    switch (event->event_id) {
        case SYSTEM_EVENT_STA_START:
            esp_wifi_connect();
            break;
        case SYSTEM_EVENT_STA_GOT_IP:
            xEventGroupSetBits(wifi_event_group, CONNECTED_BIT);
            s_ip_addr = event->event_info.got_ip.ip_info.ip;
            break;
        case SYSTEM_EVENT_STA_DISCONNECTED:
            /* This is a workaround as ESP32 WiFi libs don't currently
             auto-reassociate. */
            esp_wifi_connect();
            xEventGroupClearBits(wifi_event_group, CONNECTED_BIT);
            break;
        default:
            break;
    }
    return ESP_OK;
}

void app_main()
{
	esp_err_t err;

	uart_config_t uart_config = {
			.baud_rate = 115200,
			.data_bits = UART_DATA_8_BITS,
			.parity    = UART_PARITY_DISABLE,
			.stop_bits = UART_STOP_BITS_1,
			.flow_ctrl = UART_HW_FLOWCTRL_DISABLE
		};

	ESP_LOGI(TAG, "Initializing ESP32...");
	err = nvs_flash_init();
	if(err == ESP_ERR_NVS_NO_FREE_PAGES) {
		ESP_ERROR_CHECK(nvs_flash_erase());
		err = nvs_flash_init();
	}
	ESP_ERROR_CHECK(err);

	tcpip_adapter_init();
	wifi_event_group = xEventGroupCreate();
	ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));
	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));
	wifi_config_t wifi_config = {
			.sta = {
					.ssid = "wifi_ssid",
					.password = "wifi_password"
			}
	};

	tcpip_adapter_set_hostname(TCPIP_ADAPTER_IF_STA, "bluetrack-sniffer-0");
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
	ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
	ESP_ERROR_CHECK(esp_wifi_start());
	ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
	xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT, false, true, portMAX_DELAY);

	ESP_LOGI(TAG, "Initializing UART...");
	uart_param_config(UART_NUM_1, &uart_config);
	uart_set_pin(UART_NUM_1, ECHO_TEST_TXD, ECHO_TEST_RXD, ECHO_TEST_RTS, ECHO_TEST_CTS);
	uart_driver_install(UART_NUM_1, BUF_SIZE * 2, 0, 0, NULL, 0);

	// Configure a temporary buffer for the incoming data
	UARTInData = (uint8_t *) malloc(BUF_SIZE);

	if(UARTInData == NULL) {
		ESP_LOGE(TAG, "Unable to allocate memory for UART Rx Buffer");
	}

	ESP_LOGI(TAG, "Testing SSH Server...");
	WSTARTTCP();
	wolfSSH_Debugging_ON();
	wolfSSH_Init();
	ChangeToWolfSshRoot();
	echoserver_test(NULL);
	wolfSSH_Cleanup();
	free(UARTInData);

}
