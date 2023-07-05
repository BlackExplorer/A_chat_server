package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	rand1 "math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

var (
	clients = make(map[net.Conn]struct{})
	//clientsMtx  sync.Mutex
	clientsMtx  sync.RWMutex
	infoLogger  *log.Logger
	errorLogger *log.Logger
)

func init() {
	// 创建日志文件夹
	logDir := "./logs"
	err := os.MkdirAll(logDir, os.ModePerm)
	if err != nil {
		log.Fatalf("无法创建日志文件夹: %s", err)
	}

	// 创建日志文件
	logFile := filepath.Join(logDir, fmt.Sprintf("log_%s.txt", time.Now().Format("20060102_150405")))
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("无法创建日志文件: %s", err)
	}

	// 初始化日志输出
	infoLogger = log.New(file, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	errorLogger = log.New(file, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
}

func main() {
	key := generateKey()
	// 设置随机数种子
	rand1.Seed(time.Now().UnixNano())

	// 生成范围在[10000,20000]的随机数
	randomNumber := rand1.Intn(10001) + 10000

	ln, err := net.Listen("tcp", ":"+strconv.Itoa(randomNumber))
	if err != nil {
		fmt.Println("Error creating server:", err)
		Error(err)
		return
	}
	defer ln.Close()

	fmt.Printf("Server started, listening on port %d\n", randomNumber)

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			Error(err)
			continue
		}
		go handleClient(conn, key)
	}
}

/*func handleClient(conn net.Conn, key []byte) {
clientsMtx.Lock()
clients[conn] = struct{}{}
clientsMtx.Unlock()

defer func() {
	conn.Close()

	clientsMtx.Lock()
	delete(clients, conn)
	clientsMtx.Unlock()
}()
*/

func handleClient(conn net.Conn, key []byte) {
	clientsMtx.Lock()
	clients[conn] = struct{}{}
	clientsMtx.Unlock()

	defer func() {
		conn.Close()

		clientsMtx.Lock()
		delete(clients, conn)
		clientsMtx.Unlock()
	}()

	for {
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			Error(fmt.Errorf("Error reading from connection: %v", err))
			break
		}

		// 使用动态大小的缓冲区来读取客户端数据
		data := make([]byte, n)
		copy(data, buffer[:n])

		cipherText := string(data)
		plainText := uncryp1([]byte(cipherText), key)

		// 发送加密消息
		reply := plainText
		cipherText = cryp1(reply, key)
		broadcast(cipherText)
	}
	/*
		for {
			buffer := make([]byte, 1024)
			n, err := conn.Read(buffer)
			if err != nil {
				Error(errors.New("Connection closed"))
				break
			}

			cipherText := string(buffer[:n])
			plainText := uncryp1([]byte(cipherText), key)

			// 发送加密消息
			reply := plainText
			cipherText = cryp1(reply, key)
			broadcast(cipherText)
		}

	*/
}

func broadcast(msg string) {
	for client := range clients {
		fmt.Fprint(client, msg)
	}
}

// 生成32byte的密钥
func generateKey() []byte {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}
	key16 := hex.EncodeToString(key)
	Info(key16)
	//fmt.Printf("key: %s\n", key16) //Beta version test code!!!
	return key
}

// 加密数据
func encrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	//println(ciphertext)
	return ciphertext, nil
}

// 解密数据
func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	//println(ciphertext)
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func cryp1(data, key []byte) string {
	// 加密数据
	ciphertext, err := encrypt(data, key)
	if err != nil {
		Error(err)
		panic(err)
	}

	// 计算散列值
	//hash := calculateHash(data)
	return string(ciphertext) //, hash
}

func uncryp1(ciphertext, key []byte) []byte {
	// 解密数据
	plaintext, err := decrypt(ciphertext, key)
	if err != nil {
		Error(err)
		panic(err)
	}

	// 验证散列值
	/*if calculateHash(plaintext) == hash {
		Info(string(plaintext))
		return plaintext
	}*/
	Info(string(plaintext))
	return plaintext
}

// Info 打印一条信息日志
func Info(message string) {
	infoLogger.Println(message)
}

// Error 打印一条错误日志
func Error(err error) {
	errorLogger.Println(err)
}
