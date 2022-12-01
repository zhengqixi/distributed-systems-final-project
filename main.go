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

// noEncryptor is a simple function that does not do any encryption
func noEncryptor(data []byte) []byte {
	return data
}

// Returns 2 function: (encryptor, decryptor)
// encryptor encrypts a slice of bytes
// decryptor decrypts it
// Things like the cipher and nonce are curried in
func encryptionFunc() (func([]byte) []byte, func([]byte) []byte) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
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
	encrypt := func(data []byte) []byte {
		return gcm.Seal(nil, nonce, data, nil)
	}
	decrypt := func(encrypted []byte) []byte {
		decrypted, err := gcm.Open(nil, nonce, encrypted, nil)
		if err != nil {
			panic(err)
		}
		return decrypted
	}
	return encrypt, decrypt

}

// sender is a function that represents the source
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
		encrypted := encryptor(payload)
		out <- encrypted
		timestamp = timestamp.Add(time.Second)
	}
	close(out)
}

// createRandomDuplicate returns a function which randomly returns true
func createRandomDuplicate(prob int) func() bool {
	return func() bool {
		// TODO: Implement some random logic based on passed in probability
		// If 0, should never return true
		return false
	}
}

// router is a function representing the network router
func router(fromSender chan []byte, toReceiver chan []byte, duplicate func() bool) {
	for data := range fromSender {
		toReceiver <- data
		if duplicate() {
			toReceiver <- data
		}
	}
	close(toReceiver)
}

// getReceiver creates a receiver function
// We have a function create a function to account for the control case
// Where we don't check a timestamp at all
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
	// TODO: Take some arguments to vary the
	// test variables
	// maxInt is the state we want to check
	maxInt := 1000
	// senderToRoute represents the network queue between the sender and the router
	senderToRoute := make(chan []byte, 1024)
	// routeToReceiver represents the network queue between the router and the receiver
	routeToReceiver := make(chan []byte, 1024)
	encrypt, decrypt := encryptionFunc()
	receiver := getReceiver(routeToReceiver, decrypt)
	duplicateProb := createRandomDuplicate(0)
	go router(senderToRoute, routeToReceiver, duplicateProb)
	start := time.Now()
	// The sender, we're going
	go sender(senderToRoute, maxInt, encrypt)
	finalState := receiver()
	end := time.Now()
	duration := end.Sub(start)
	fmt.Printf("%f %d\n", duration.Seconds(), finalState)
}
