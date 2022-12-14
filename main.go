package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"
	mathrand "math/rand"
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
func createRandomDuplicate(prob float64) func() bool {
	return func() bool {
		// If 0, should never return true
		if prob <= 0.0 {
			return false
		}
		if prob >= 1.0 {	// always duplicate
			return true
		}

		r := mathrand.Intn(1000)
		if float64(r) < 1000.0*prob {
			return true
		}
		return false
	}
}

// router is a function representing the network router
func router(fromSender chan []byte, toReceiver chan []byte, prob float64) {
	for data := range fromSender {
		toReceiver <- data
		c := 0
		for createRandomDuplicate(prob)() || c < 10 {
			c += 1
			toReceiver <- data
		}
	}
	close(toReceiver)
}

// getReceiver creates a receiver function
// We have a function create a function to account for the control case
// Where we don't check a timestamp at all
func getReceiver(in chan []byte, decryptor func(data []byte) []byte) func() (int, time.Time, int) {
	if decryptor == nil {
		return func() (int, time.Time, int) {
			state := 0
			totalMessagesRcvd := 0
			for data := range in {
				var m Message
				if err := json.Unmarshal(data, &m); err != nil {
					panic(err)
				}
				state += m.Value
				totalMessagesRcvd += 1
			}
			return state, time.Now(), totalMessagesRcvd
		}
	} else {
		return func() (int, time.Time, int) {
			state := 0
			totalMessagesRcvd := 0
			lastSeenTimestamp := time.Time{}
			for data := range in {
				decrypted := decryptor(data)
				var m Message
				if err := json.Unmarshal(decrypted, &m); err != nil {
					panic(err)
				}
				totalMessagesRcvd += 1
				if m.Timestamp.After(lastSeenTimestamp) {
					state += m.Value
					lastSeenTimestamp = m.Timestamp
				}
			}
			return state, time.Now(), totalMessagesRcvd
		}
	}
}

func test(prob float64, maxInt int) {
	// senderToRoute represents the network queue between the sender and the router
	senderToRoute := make(chan []byte, 1024)
	// routeToReceiver represents the network queue between the router and the receiver
	routeToReceiver := make(chan []byte, 1024)
	encrypt, decrypt := encryptionFunc()
	receiver := getReceiver(routeToReceiver, decrypt)
	// duplicateProb := createRandomDuplicate(prob)
	go router(senderToRoute, routeToReceiver, prob)
	start := time.Now()
	// The sender, we're going
	go sender(senderToRoute, maxInt, encrypt)
	finalState, end, totalMessagesRcvd := receiver()
	duration := end.Sub(start)
	// fmt.Printf("Reslts for %d sent messages with approximate %.1f%% messages duplicated at router\n", maxInt, 100.0*prob)
	fmt.Printf("\tMessages sent %d, Messages received %d, Final State %d, Total time(nanoseconds) %d\n", maxInt, totalMessagesRcvd, finalState, duration.Nanoseconds())
}

func main() {
	// Seeding with different values to result in different random sequence on
	// different application/test runs
	seedValue := time.Now().UnixNano()
	mathrand.Seed(seedValue)

	prob := 0.0	// probability value between [0, 1]
	maxInt := 100000 // maxInt is the state we want to check
	for prob < 0.9 {
		test(prob, maxInt)
		prob += 0.1
	}
}
