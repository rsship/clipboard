#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

// Platform-specific includes
#ifdef __APPLE__
#include <ApplicationServices/ApplicationServices.h>
#elif defined(_WIN32)
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <X11/Xlib.h>
#include <X11/Xatom.h>
#endif

#define KEY_SIZE 32
#define IV_SIZE 16
#define BUFFER_SIZE 4096
#define PORT 8443
#define MAX_RETRIES 5

// Structure to hold encrypted data
typedef struct {
    unsigned char *data;
    int length;
    unsigned char iv[IV_SIZE];
    unsigned char tag[16];  // GCM authentication tag
} EncryptedData;

// Network transfer protocol structure
typedef struct {
    uint32_t magic;         // Magic number for protocol verification
    uint32_t data_length;   // Length of encrypted data
    unsigned char iv[16];   // Initialization vector
    unsigned char tag[16];  // Authentication tag
    unsigned char data[];   // Variable-length encrypted data
} __attribute__((packed)) TransferProtocol;

#define PROTOCOL_MAGIC 0x5345434C // "SECL" in ASCII

// Error handling function
void handle_error(const char* message) {
    fprintf(stderr, "Error: %s\n", message);
    fprintf(stderr, "System error: %s\n", strerror(errno));
    exit(1);
}

#ifdef __APPLE__
// macOS-specific clipboard function
char* get_macos_clipboard() {
    PasteboardRef pasteboard;
    OSStatus err = PasteboardCreate(kPasteboardClipboard, &pasteboard);
    if (err != noErr) {
        fprintf(stderr, "Error creating pasteboard reference\n");
        return NULL;
    }

    PasteboardSynchronize(pasteboard);
    
    ItemCount itemCount;
    err = PasteboardGetItemCount(pasteboard, &itemCount);
    if (err != noErr || itemCount == 0) {
        CFRelease(pasteboard);
        return NULL;
    }

    PasteboardItemID itemID;
    err = PasteboardGetItemIdentifier(pasteboard, 1, &itemID);
    if (err != noErr) {
        CFRelease(pasteboard);
        return NULL;
    }

    CFDataRef flavorData;
    err = PasteboardCopyItemFlavorData(pasteboard, itemID, CFSTR("public.utf8-plain-text"), &flavorData);
    if (err != noErr) {
        CFRelease(pasteboard);
        return NULL;
    }

    CFIndex length = CFDataGetLength(flavorData);
    char* buffer = malloc(length + 1);
    CFDataGetBytes(flavorData, CFRangeMake(0, length), (UInt8*)buffer);
    buffer[length] = '\0';

    CFRelease(flavorData);
    CFRelease(pasteboard);
    
    return buffer;
}
#endif

// Cross-platform clipboard setter for receiver
void set_clipboard_content(const char* text) {
#ifdef _WIN32
    if (!OpenClipboard(NULL))
        return;
    
    EmptyClipboard();
    HGLOBAL hText = GlobalAlloc(GMEM_MOVEABLE, strlen(text) + 1);
    if (hText == NULL) {
        CloseClipboard();
        return;
    }
    
    char* buffer = (char*)GlobalLock(hText);
    strcpy(buffer, text);
    GlobalUnlock(hText);
    
    SetClipboardData(CF_TEXT, hText);
    CloseClipboard();
#elif defined(__linux__)
    Display *display = XOpenDisplay(NULL);
    if (display == NULL)
        return;
    
    Window window = DefaultRootWindow(display);
    Atom clipboard = XInternAtom(display, "CLIPBOARD", False);
    Atom utf8_string = XInternAtom(display, "UTF8_STRING", False);
    
    XStoreBytes(display, text, strlen(text));
    XSetSelectionOwner(display, clipboard, window, CurrentTime);
    
    XCloseDisplay(display);
#elif defined(__APPLE__)
    PasteboardRef pasteboard;
    if (PasteboardCreate(kPasteboardClipboard, &pasteboard) != noErr)
        return;

    PasteboardClear(pasteboard);
    CFDataRef textData = CFDataCreate(NULL, (UInt8*)text, strlen(text));
    if (textData != NULL) {
        PasteboardPutItemFlavor(pasteboard, (PasteboardItemID)1,
                               CFSTR("public.utf8-plain-text"),
                               textData, 0);
        CFRelease(textData);
    }
    CFRelease(pasteboard);
#endif
}

// Enhanced encryption function with authentication
EncryptedData encrypt_data(const unsigned char *key, const char *plaintext) {
    EncryptedData result = {0};
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen;
    
    // Generate random IV
    if (RAND_bytes(result.iv, IV_SIZE) != 1) {
        handle_error("Error generating IV");
    }
    
    // Initialize encryption context with AES-256-GCM
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        handle_error("Error initializing encryption context");
    }
    
    // Set key length to 256 bits
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        handle_error("Error setting IV length");
    }
    
    // Initialize key and IV
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, result.iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        handle_error("Error setting key and IV");
    }
    
    // Allocate memory for encrypted data
    int plaintext_len = strlen(plaintext);
    result.data = malloc(plaintext_len + EVP_MAX_BLOCK_LENGTH);
    
    // Encrypt the data
    if (EVP_EncryptUpdate(ctx, result.data, &outlen, (unsigned char*)plaintext, plaintext_len) != 1) {
        free(result.data);
        EVP_CIPHER_CTX_free(ctx);
        handle_error("Error encrypting data");
    }
    result.length = outlen;
    
    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, result.data + outlen, &outlen) != 1) {
        free(result.data);
        EVP_CIPHER_CTX_free(ctx);
        handle_error("Error finalizing encryption");
    }
    result.length += outlen;
    
    // Get the tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, result.tag) != 1) {
        free(result.data);
        EVP_CIPHER_CTX_free(ctx);
        handle_error("Error getting authentication tag");
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

// Enhanced decryption function with authentication
char* decrypt_data(const unsigned char *key, const EncryptedData *encrypted_data) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    char *plaintext = malloc(encrypted_data->length + EVP_MAX_BLOCK_LENGTH);
    int outlen;
    
    // Initialize decryption context
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        handle_error("Error initializing decryption context");
    }
    
    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL) != 1) {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        handle_error("Error setting IV length");
    }
    
    // Initialize key and IV
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, encrypted_data->iv) != 1) {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        handle_error("Error setting key and IV");
    }
    
    // Decrypt the data
    if (EVP_DecryptUpdate(ctx, (unsigned char*)plaintext, &outlen, 
                         encrypted_data->data, encrypted_data->length) != 1) {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        handle_error("Error decrypting data");
    }
    
    int plaintext_len = outlen;
    
    // Set expected tag value
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)encrypted_data->tag) != 1) {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        handle_error("Error setting authentication tag");
    }
    
    // Finalize decryption and verify tag
    if (EVP_DecryptFinal_ex(ctx, (unsigned char*)plaintext + outlen, &outlen) != 1) {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        handle_error("Error finalizing decryption: Authentication failed");
    }
    plaintext_len += outlen;
    plaintext[plaintext_len] = '\0';
    
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

// Network functions
int create_server_socket() {
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;
    
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        handle_error("Socket creation failed");
    }
    
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, 
                   &opt, sizeof(opt))) {
        handle_error("Setsockopt failed");
    }
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        handle_error("Bind failed");
    }
    
    if (listen(server_fd, 3) < 0) {
        handle_error("Listen failed");
    }
    
    return server_fd;
}

int create_client_socket(const char* server_ip) {
    int sock = 0;
    struct sockaddr_in serv_addr;
    
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        handle_error("Socket creation failed");
    }
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    
    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        handle_error("Invalid address");
    }
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        handle_error("Connection failed");
    }
    
    return sock;
}

// Send encrypted data over network
void send_encrypted_data(int sock, const EncryptedData *data) {
    size_t total_size = sizeof(TransferProtocol) + data->length;
    TransferProtocol *protocol = malloc(total_size);
    
    protocol->magic = htonl(PROTOCOL_MAGIC);
    protocol->data_length = htonl(data->length);
    memcpy(protocol->iv, data->iv, 16);
    memcpy(protocol->tag, data->tag, 16);
    memcpy(protocol->data, data->data, data->length);
    
    size_t bytes_sent = 0;
    while (bytes_sent < total_size) {
        ssize_t result = send(sock, ((char*)protocol) + bytes_sent, 
                            total_size - bytes_sent, 0);
        if (result < 0) {
            free(protocol);
            handle_error("Send failed");
        }
        bytes_sent += result;
    }
    
    free(protocol);
}

// Receive encrypted data from network
EncryptedData receive_encrypted_data(int sock) {
    EncryptedData result = {0};
    TransferProtocol header;
    
    // Receive header first
    size_t bytes_received = 0;
    while (bytes_received < sizeof(TransferProtocol)) {
        ssize_t res = recv(sock, ((char*)&header) + bytes_received, 
                          sizeof(TransferProtocol) - bytes_received, 0);
        if (res <= 0) {
            handle_error("Receive failed");
        }
        bytes_received += res;
    }
    
    if (ntohl(header.magic) != PROTOCOL_MAGIC) {
        handle_error("Invalid protocol magic number");
    }
    
    // Get the data length and allocate buffer
    result.length = ntohl(header.data_length);
    result.data = malloc(result.length);
    memcpy(result.iv, header.iv, 16);
    memcpy(result.tag, header.tag, 16);
    
    // Receive encrypted data
    bytes_received = 0;
    while (bytes_received < result.length) {
        ssize_t res = recv(sock, result.data + bytes_received, 
                          result.length - bytes_received, 0);
        if (res <= 0) {
            free(result.data);
            handle_error("Receive failed");
        }
        bytes_received += res;
    }
    
    return result;
}

// Signal handler for graceful shutdown
volatile sig_atomic_t keep_running = 1;

void signal_handler(int signum) {
    keep_running = 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage:\n");
        printf("  Sender: %s send <receiver_ip>\n", argv[0]);
        printf("  Receiver: %s receive\n", argv[0]);
        return 1;
    }
    
    // Setup signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Use a fixed key for testing (in production, implement secure key exchange)
    unsigned char key[KEY_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
    if (strcmp(argv[1], "send") == 0) {
        #ifndef __APPLE__
        fprintf(stderr, "Sender must be running on macOS\n");
        return 1;
        #endif
        
        if (argc != 3) {
            fprintf(stderr, "Sender requires receiver IP address\n");
            return 1;
        }
        
        int sock = create_client_socket(argv[2]);
        printf("Connected to receiver at %s\n", argv[2]);
        
        while (keep_running) {
            // Get clipboard content using macOS-specific function
            char *clipboard_text = get_macos_clipboard();
            if (clipboard_text == NULL) {
                fprintf(stderr, "Error getting clipboard content\n");
                sleep(1);
                continue;
            }
            
            // Encrypt the clipboard content
            EncryptedData encrypted = encrypt_data(key, clipboard_text);
            
            // Send encrypted data
            send_encrypted_data(sock, &encrypted);
            printf("Sent encrypted clipboard data\n");
            
            free(clipboard_text);
            free(encrypted.data);
            
            // Wait before checking clipboard again
            sleep(1);
        }
        
        close(sock);
        
    } else if (strcmp(argv[1], "receive") == 0) {
        int server_fd = create_server_socket();
        printf("Receiver listening on port %d...\n", PORT);
        
        struct sockaddr_in address;
        int addrlen = sizeof(address);
        
        while (keep_running) {
            // Accept incoming connection
            int client_sock = accept(server_fd, (struct sockaddr *)&address, 
                                   (socklen_t*)&addrlen);
            if (client_sock < 0) {
                if (!keep_running) break;  // Check if we're shutting down
                handle_error("Accept failed");
            }
            
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &address.sin_addr, client_ip, INET_ADDRSTRLEN);
            printf("Accepted connection from %s\n", client_ip);
            
            while (keep_running) {
                fd_set readfds;
                struct timeval tv;
                FD_ZERO(&readfds);
                FD_SET(client_sock, &readfds);
                tv.tv_sec = 1;
                tv.tv_usec = 0;
                
                int activity = select(client_sock + 1, &readfds, NULL, NULL, &tv);
                
                if (activity < 0) {
                    if (errno == EINTR) continue;  // Interrupted by signal
                    perror("Select error");
                    break;
                }
                
                if (activity == 0) continue;  // Timeout
                
                if (FD_ISSET(client_sock, &readfds)) {
                    // Receive encrypted data with error handling
                    EncryptedData received_data;
                    
                    // Use non-blocking receive with timeout
                    struct timeval sock_timeout;
                    sock_timeout.tv_sec = 5;
                    sock_timeout.tv_usec = 0;
                    setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, 
                              &sock_timeout, sizeof(sock_timeout));
                    
                    // Attempt to receive data
                    if (recv(client_sock, &received_data, sizeof(received_data), MSG_PEEK) <= 0) {
                        if (errno == EWOULDBLOCK || errno == EAGAIN) {
                            // Timeout occurred
                            continue;
                        } else {
                            // Connection closed or error
                            printf("Connection closed by sender\n");
                            break;
                        }
                    }
                    
                    received_data = receive_encrypted_data(client_sock);
                    if (received_data.data == NULL) {
                        printf("Error receiving data\n");
                        continue;
                    }
                    
                    // Decrypt the received data
                    char *decrypted_text = decrypt_data(key, &received_data);
                    if (!decrypted_text) continue;
                    set_clipboard_content(decrypted_text);
                    printf("[LOG] decrypted data %s\n",  decrypted_text);
                   
                    free(decrypted_text);
                    free(received_data.data);
                }
            }
            
            close(client_sock);
            printf("Connection closed\n");
        }
        
        close(server_fd);
    }
    
    printf("\nShutting down...\n");
    return 0;
}
