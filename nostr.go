package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/nfnt/resize"
)

type Tag []string
type Tags []Tag
type NostrEvent struct {
	ID        string    `json:"id"`
	PubKey    string    `json:"pubkey"`
	CreatedAt time.Time `json:"created_at"`
	Kind      int       `json:"kind"`
	Tags      Tags      `json:"tags"`
	Content   string    `json:"content"`
	Sig       string    `json:"sig"`
}

type ProfileMetadata struct {
	Name        string `json:"name,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	About       string `json:"about,omitempty"`
	Website     string `json:"website,omitempty"`
	Picture     string `json:"picture,omitempty"`
	Banner      string `json:"banner,omitempty"`
	NIP05       string `json:"nip05,omitempty"`
	LUD16       string `json:"lud16,omitempty"`
}

func ParseMetadata(event nostr.Event) (*ProfileMetadata, error) {
	if event.Kind != 0 {
		return nil, fmt.Errorf("event %s is kind %d, not 0", event.ID, event.Kind)
	}

	var meta ProfileMetadata
	if err := json.Unmarshal([]byte(event.Content), &meta); err != nil {
		cont := event.Content
		if len(cont) > 100 {
			cont = cont[0:99]
		}
		return nil, fmt.Errorf("failed to parse metadata (%s) from event %s: %w", cont, event.ID, err)
	}

	return &meta, nil
}

var nip57Receipt nostr.Event
var zapEventSerializedStr string
var nip57ReceiptRelays []string

func Nip57DescriptionHash(zapEventSerialized string) string {
	hash := sha256.Sum256([]byte(zapEventSerialized))
	hashString := hex.EncodeToString(hash[:])
	return hashString
}

func DecodeBech32(key string) string {
	if _, v, err := nip19.Decode(key); err == nil {
		return v.(string)
	}
	return key

}

func EncodeBech32Public(key string) string {
	if v, err := nip19.EncodePublicKey(key); err == nil {
		return v
	}
	return key
}

func EncodeBech32Private(key string) string {
	if v, err := nip19.EncodePrivateKey(key); err == nil {
		return v
	}
	return key
}

func EncodeBech32Note(key string) string {
	if v, err := nip19.EncodeNote(key); err == nil {
		return v
	}
	return key
}

func sendMessage(receiverKey string, message string) {

	var relays []string
	var tags nostr.Tags
	reckey := DecodeBech32(receiverKey)
	tags = append(tags, nostr.Tag{"p", reckey})

	//references, err := optSlice(opts, "--reference")
	//if err != nil {
	//	return
	//}
	//for _, ref := range references {
	//tags = append(tags, nostr.Tag{"e", reckey})
	//}

	// parse and encrypt content
	privkeyhex := DecodeBech32(s.NostrPrivateKey)
	pubkey, _ := nostr.GetPublicKey(privkeyhex)

	sharedSecret, err := nip04.ComputeSharedSecret(reckey, privkeyhex)
	if err != nil {
		log.Printf("Error computing shared key: %s. x\n", err.Error())
		return
	}

	encryptedMessage, err := nip04.Encrypt(message, sharedSecret)
	if err != nil {
		log.Printf("Error encrypting message: %s. \n", err.Error())
		return
	}

	event := nostr.Event{
		PubKey:    pubkey,
		CreatedAt: nostr.Now(),
		Kind:      nostr.KindEncryptedDirectMessage,
		Tags:      tags,
		Content:   encryptedMessage,
	}
	event.Sign(privkeyhex)
	publishNostrEvent(event, relays)
	log.Printf("%+v\n", event)
}

func handleNip05(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("name")
	if username == "" {
		http.Error(w, `{"error": "missing 'name' parameter"}`, http.StatusBadRequest)
		return
	}

	domains := getDomains(s.Domain)
	domain := ""

	if len(domains) == 1 {
		domain = domains[0]
	} else {
		hostname := r.URL.Host
		if hostname == "" {
			hostname = r.Host
		}

		for _, one := range domains {
			if strings.Contains(hostname, one) {
				domain = one
				break
			}
		}
		if domain == "" {
			http.Error(w, `{"error": "incorrect domain"}`, http.StatusBadRequest)
			return
		}
	}

	params, err := GetName(username, domain)
	if err != nil {
		log.Error().Err(err).Str("name", username).Str("domain", domain).Msg("failed to get name")
		http.Error(w, fmt.Sprintf(`{"error": "failed to get name %s@%s"}`, username, domain), http.StatusNotFound)
		return
	}

	nostrnpubHex := DecodeBech32(params.Npub)
	response := map[string]interface{}{
		"names": map[string]interface{}{
			username: nostrnpubHex,
		},
	}

	if s.Nip05 {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(response)
	}
}

func GetNostrProfileMetaData(npub string, index int) (ProfileMetadata, error) {
	var metadata *ProfileMetadata
	// Prepend special purpose relay wss://purplepag.es to the list of relays
	var relays = append([]string{"wss://purplepag.es"}, Relays...)

	for index < len(relays) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		rel := relays[index]
		log.Printf("Get Image from: %s", rel)
		url := rel
		relay, err := nostr.RelayConnect(ctx, url)
		if err != nil {
			log.Printf("Could not connect to [%s], trying next relay", url)
			index++
			continue
		}

		var filters nostr.Filters
		if _, v, err := nip19.Decode(npub); err == nil {
			t := make(map[string][]string)
			t["p"] = []string{v.(string)}
			filters = []nostr.Filter{{
				Authors: []string{v.(string)},
				Kinds:   []int{0},
				Limit:   1,
			}}
		} else {
			log.Printf("Could not find Profile, trying next relay")
			index++
			relay.Close()
			continue
		}
		sub, err := relay.Subscribe(ctx, filters)
		evs := make([]nostr.Event, 0)

		endStoredEventsOnce := new(sync.Once)
		go func() {
			endStoredEventsOnce.Do(func() {
				<-sub.EndOfStoredEvents
			})
		}()

		for ev := range sub.Events {
			evs = append(evs, *ev)
		}
		relay.Close()

		if len(evs) > 0 {
			metadata, err = ParseMetadata(evs[0])
			log.Printf("Success getting Nostr Profile")
			break
		} else {
			err = fmt.Errorf("no profile found for npub %s on relay %s", npub, url)
			log.Printf("Could not find Profile, trying next relay")
			index++
		}
	}

	if metadata == nil {
		return ProfileMetadata{}, fmt.Errorf("Couldn't download Profile for given relays")
	}
	return *metadata, nil
}

// Reusable instance of http client
var httpClient = &http.Client{
	Timeout: 5 * time.Second,
}

// addImageToMetaData adds an image to the LNURL metadata
func addImageToProfile(params *Params, imageURL string) (err error) {
	// Download and resize profile picture
	picture, contentType, err := DownloadProfilePicture(imageURL)
	if err != nil {
		log.Debug().Str("Downloading profile picture", err.Error()).Msg("Error")
		return err
	}

	// Determine image format
	var ext string
	switch contentType {
	case "image/jpeg":
		ext = "jpeg"
	case "image/png":
		ext = "png"
	case "image/gif":
		ext = "gif"
	default:
		log.Debug().Str("Detecting image format", "unknown format").Msg("Error")
		return fmt.Errorf("Detecting image format: unknown format")
	}

	// Set image metadata in LNURL metadata
	encodedPicture := base64.StdEncoding.EncodeToString(picture)
	params.Image.Ext = ext
	params.Image.DataURI = "data:" + contentType + ";base64," + encodedPicture
	params.Image.Bytes = picture

	return nil
}

func DownloadProfilePicture(url string) ([]byte, string, error) {
	res, err := httpClient.Get(url)
	if err != nil {
		return nil, "", errors.New("failed to download image: " + err.Error())
	}
	defer res.Body.Close()

	contentType := res.Header.Get("Content-Type")
	if contentType != "image/jpeg" && contentType != "image/png" && contentType != "image/gif" {
		return nil, "", errors.New("unsupported image format")
	}

	var img image.Image
	switch contentType {
	case "image/jpeg":
		img, err = jpeg.Decode(res.Body)
	case "image/png":
		img, err = png.Decode(res.Body)
	case "image/gif":
		img, err = gif.Decode(res.Body)
	}
	if err != nil {
		return nil, "", errors.New("failed to decode image: " + err.Error())
	}

	img = resize.Thumbnail(thumbnailWidth, thumbnailHeight, img, resize.Lanczos3)

	buf := new(bytes.Buffer)

	if err := jpeg.Encode(buf, img, nil); err != nil {
		return nil, "", errors.New("failed to encode image: " + err.Error())
	}
	return buf.Bytes(), contentType, nil
}

func publishNostrEvent(ev nostr.Event, relays []string) {
	// Add more relays, remove trailing slashes, and ensure unique relays
	relays = uniqueSlice(cleanUrls(append(relays, Relays...)))

	ev.Sign(s.NostrPrivateKey)

	var wg sync.WaitGroup
	wg.Add(len(relays))

	// Create a buffered channel to control the number of active goroutines
	concurrencyLimit := 20
	goroutines := make(chan struct{}, concurrencyLimit)

	// Publish the event to relays
	for _, url := range relays {
		goroutines <- struct{}{}
		go func(url string) {
			defer func() {
				<-goroutines
				wg.Done()
			}()

			var err error
			var conn *nostr.Relay
			maxRetries := 3
			retryDelay := 1 * time.Second

			for i := 0; i < maxRetries; i++ {
				// Set a timeout for connecting to the relay
				connCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				conn, err = nostr.RelayConnect(connCtx, url)
				cancel()

				if err != nil {
					log.Printf("Error connecting to relay %s: %v", url, err)
					time.Sleep(retryDelay)
					retryDelay *= 2
					continue
				}
				defer conn.Close()

				// Set a timeout for publishing to the relay
				pubCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				err = conn.Publish(pubCtx, ev)
				cancel()

				if err != nil {
					log.Printf("Error publishing to relay %s: %v", url, err)
					time.Sleep(retryDelay)
					retryDelay *= 2
					continue
				} else {
					log.Printf("[NOSTR] published to %s: %s", url, "sent")
					break
				}
			}
		}(url)
	}

	wg.Wait()
}

func ExtractNostrRelays(zapEvent nostr.Event) []string {
	relaysTag := zapEvent.Tags.GetFirst([]string{"relays"})
	log.Printf("Zap relaysTag: %s", relaysTag)

	if relaysTag == nil || len(*relaysTag) == 0 {
		return []string{}
	}

	// Skip the first element, which is the tag name
	relays := (*relaysTag)[1:]
	log.Printf("Zap relays: %v", relays)

	return relays
}

func CreateNostrReceipt(zapEvent nostr.Event, invoice string) (nostr.Event, error) {
	pub, err := nostr.GetPublicKey(nostrPrivkeyHex)
	if err != nil {
		return nostr.Event{}, err
	}

	zapEventSerialized, err := json.Marshal(zapEvent)
	if err != nil {
		return nostr.Event{}, err
	}

	nip57Receipt := nostr.Event{
		PubKey:    pub,
		CreatedAt: nostr.Now(),
		Kind:      9735,
		Tags: nostr.Tags{
			*zapEvent.Tags.GetFirst([]string{"p"}),
			[]string{"P", zapEvent.PubKey},
			[]string{"bolt11", invoice},
			[]string{"description", string(zapEventSerialized)},
		},
	}

	if eTag := zapEvent.Tags.GetFirst([]string{"e"}); eTag != nil {
		nip57Receipt.Tags = nip57Receipt.Tags.AppendUnique(*eTag)
	}

	if aTags := zapEvent.Tags.GetAll([]string{"a"}); aTags != nil {
		for _, s := range aTags {
			if s.Key() == "a" {
				nip57Receipt.Tags = nip57Receipt.Tags.AppendUnique(s)
			}
		}
	}

	err = nip57Receipt.Sign(nostrPrivkeyHex)
	if err != nil {
		return nostr.Event{}, err
	}

	return nip57Receipt, nil
}

func uniqueSlice(slice []string) []string {
	keys := make(map[string]bool)
	list := make([]string, 0, len(slice))
	for _, entry := range slice {
		if _, exists := keys[entry]; !exists && entry != "" {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func cleanUrls(slice []string) []string {
	list := make([]string, 0, len(slice))
	for _, entry := range slice {
		if strings.HasSuffix(entry, "/") {
			entry = entry[:len(entry)-1]
		}
		list = append(list, entry)
	}
	return list
}
