package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"
)

// Message is the increment counter message
type Message struct {
	Value     int
	Timestamp time.Time
}

func noEncryptor(data []byte) []byte {
	return data
}

func encryptionFunc() (func([]byte) []byte, func([]byte) []byte) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	encrypt := func(data []byte) []byte {
		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			panic(err)
		}
		nonce := make([]byte, gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			panic(err)
		}
		return gcm.Seal(nil, nonce, data, nil)
	}
	decrypt := func(encrypted []byte) []byte {
		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			panic(err)
		}
		nonceSize := gcm.NonceSize()
		decrypted, err := gcm.Open(nil, encrypted[:nonceSize], encrypted[nonceSize:], nil)
		if err != nil {
			panic(err)
		}
		return decrypted
	}
	return encrypt, decrypt

}

func sender(out chan []byte, max int, encryptor func(data []byte) []byte) {
	timestamp := time.Now()
	for i := 0; i < max; i += 1 {
		value := Message{
			Value:     1,
			Timestamp: timestamp,
		}
		payload, err := json.Marshal(value)
		if err != nil {
			panic(err)
		}
		out <- payload
		timestamp.Add(time.Second)
	}
	close(out)
}

func noDuplicate() bool {
	return false
}

func router(fromSender chan []byte, toReceiver chan []byte, duplicate func() bool) {
	for data := range fromSender {
		toReceiver <- data
		if duplicate() {
			toReceiver <- data
		}
	}
	close(toReceiver)
}

func getReceiver(in chan []byte, decryptor func(data []byte) []byte) func() int {
	if decryptor == nil {
		return func() int {
			state := 0
			for data := range in {
				var m Message
				if err := json.Unmarshal(data, &m); err != nil {
					panic(err)
				}
				state += m.Value
			}
			return state
		}
	} else {
		return func() int {
			state := 0
			lastSeenTimestamp := time.Time{}
			for data := range in {
				decrypted := decryptor(data)
				var m Message
				if err := json.Unmarshal(decrypted, &m); err != nil {
					panic(err)
				}
				if m.Timestamp.After(lastSeenTimestamp) {
					state += m.Value
					lastSeenTimestamp = m.Timestamp
				}
			}
			return state
		}
	}
}

func main() {
	maxInt := 1000
	senderToRoute := make(chan []byte, 1024)
	routeToReceiver := make(chan []byte, 1024)
	encrypt, decrypt := encryptionFunc()
	receiver := getReceiver(routeToReceiver, decrypt)
	go router(senderToRoute, routeToReceiver, noDuplicate)
	start := time.Now()
	// The sender, we're going
	go sender(senderToRoute, maxInt, encrypt)
	finalState := receiver()
	end := time.Now()
	duration := end.Sub(start)
	fmt.Printf("%f %d\n", duration.Seconds(), finalState)
}
