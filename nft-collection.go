package shuffle

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

// Used to load collections on an interval, e.g. every 30 minutes.
func LoadRelatedCollection(topClient *http.Client, collectionName string) (OpenseaAsset, error) {
	streamUrl := fmt.Sprintf("https://api.opensea.io/api/v1/collection/%s", collectionName)

	resultData := ""
	req, err := http.NewRequest(
		"GET",
		streamUrl,
		bytes.NewBuffer([]byte(resultData)),
	)

	if err != nil {
		log.Printf("[ERROR] Error in NFT collection setup: %s", err)
		return OpenseaAsset{}, err
	}

	newresp, err := topClient.Do(req)
	if err != nil {
		log.Printf("[ERROR] Error in NFT collection client: %s", err)
		return OpenseaAsset{}, err
	}

	body, err := ioutil.ReadAll(newresp.Body)
	if err != nil {
		log.Printf("[ERROR] Failed reading parent body in NFT collection: %s", err)
		return OpenseaAsset{}, err
	}
	//log.Printf("BODY (%d): %s", newresp.StatusCode, string(body))

	var collection OpenseaAsset
	err = json.Unmarshal(body, &collection)
	if err != nil {
		log.Printf("[WARNING] Failed unmarshaling (NFT collection): %s. Value: %#v", err, collection)
		return collection, err
	}

	return collection, err
}

func LoadRelatedAsset(topClient *http.Client, contractId, assetId string) (OpenseaAsset, error) {
	streamUrl := fmt.Sprintf("https://api.opensea.io/api/v1/asset/%s/%s", contractId, assetId)

	resultData := ""
	req, err := http.NewRequest(
		"GET",
		streamUrl,
		bytes.NewBuffer([]byte(resultData)),
	)

	if err != nil {
		log.Printf("[ERROR] Error in NFT collection setup: %s", err)
		return OpenseaAsset{}, err
	}

	newresp, err := topClient.Do(req)
	if err != nil {
		log.Printf("[ERROR] Error in NFT collection client: %s", err)
		return OpenseaAsset{}, err
	}

	body, err := ioutil.ReadAll(newresp.Body)
	if err != nil {
		log.Printf("[ERROR] Failed reading parent body in NFT collection: %s", err)
		return OpenseaAsset{}, err
	}
	//log.Printf("BODY (%d): %s", newresp.StatusCode, string(body))

	var collection OpenseaAsset
	err = json.Unmarshal(body, &collection)
	if err != nil {
		//log.Printf("[WARNING] Failed unmarshaling (NFT collection): %s. Value: %#v", err, collection)
		return collection, err
	}

	return collection, err
}

var assets = []string{
	"0x495f947276749ce646f68ac8c248420045cb7b5e/58026500867055606734922553788423170575605578418013816366565612099986385797121",
}

func runLoadCollections(ctx context.Context, topClient *http.Client) {
	for _, assetString := range assets {
		assetSplit := strings.Split(assetString, "/")
		if len(assetSplit) != 2 {
			log.Printf("[ERROR] Couldn't split value %s", assetString)
			continue
		}

		asset, assetErr := LoadRelatedAsset(topClient, assetSplit[0], assetSplit[1])
		if assetErr != nil {
			log.Printf("[ERROR] Failed to get asset: %s", assetErr)
			continue
		}

		id := Md5sum([]byte(assetString))
		err = SetOpenseaAsset(ctx, asset, id)
		if err != nil {
			log.Printf("[ERROR] Failed setting NFT asset in DB %s: %s", assetString, err)
			continue
		}

		log.Printf("[DEBUG] Reloaded asset %s in collection %s. Err: %#v", assetString, asset.Collection, assetErr)
	}
}

func LoadCollections(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Just here to verify that the user is logged in
	_, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed load collections: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	topClient := &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
		},
	}

	httpProxy := os.Getenv("HTTP_PROXY")
	httpsProxy := os.Getenv("HTTPS_PROXY")
	if len(httpProxy) > 0 || len(httpsProxy) > 0 {
		topClient = &http.Client{}
	} else {
		if len(httpProxy) > 0 {
			log.Printf("Running with HTTP proxy %s (env: HTTP_PROXY)", httpProxy)
		}
		if len(httpsProxy) > 0 {
			log.Printf("Running with HTTPS proxy %s (env: HTTPS_PROXY)", httpsProxy)
		}
	}

	ctx := getContext(request)
	runLoadCollections(ctx, topClient)

	/*
		collectionNames := []string{"shuffle-workflows", "untitled-collection-103712081"}
		for _, collectionName := range collectionNames {
			collection, collectionerr := LoadRelatedCollection(topClient, collectionName)
			if collectionerr != nil {
				if !strings.Contains(fmt.Sprintf("%s", collectionerr), "into Go struct field") {
					log.Printf("[ERROR] Failed loading NFT collection %s: %s", collectionName, err)
					continue
				}
			}

			err = SetOpenseaAsset(ctx, collection, collectionName)
			if err != nil {
				log.Printf("[ERROR] Failed setting NFT collection in DB %s: %s", collectionName, err)
				continue
			}

			log.Printf("[DEBUG] Reloaded collection %s. Err: %#v", collectionName, collectionerr)
		}
	*/

	resp.WriteHeader(200)
	resp.Write([]byte(fmt.Sprintf(`{"success": true, "reason": "Successfully loaded %d assets"}`, len(assets))))
}

func HandleGetCollection(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Just here to verify that the user is logged in
	user, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed in get collection: %s", err)
		//resp.WriteHeader(401)
		//resp.Write([]byte(`{"success": false}`))
		//return
	}

	var fileId string
	location := strings.Split(request.URL.String(), "/")
	if location[1] == "api" {
		if len(location) <= 5 {
			log.Printf("Path too short: %d", len(location))
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false}`))
			return
		}

		fileId = location[5]
	}

	collectionName := fileId
	log.Printf("[DEBUG] Getting collection %s for user %s (%s)", collectionName, user.Username, user.Id)

	ctx := getContext(request)
	returnAssets, err := GetOpenseaAssets(ctx, collectionName)
	if err != nil {
		log.Printf("[WARNING] Failed getting collection %s: %s", collectionName, err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed to get the collection key. Does it exist?"}`))
		return
	}

	// Force load if they're not there
	if len(returnAssets) == 0 {
		topClient := &http.Client{
			Transport: &http.Transport{
				Proxy: nil,
			},
		}

		httpProxy := os.Getenv("HTTP_PROXY")
		httpsProxy := os.Getenv("HTTPS_PROXY")
		if len(httpProxy) > 0 || len(httpsProxy) > 0 {
			topClient = &http.Client{}
		} else {
			if len(httpProxy) > 0 {
				log.Printf("Running with HTTP proxy %s (env: HTTP_PROXY)", httpProxy)
			}
			if len(httpsProxy) > 0 {
				log.Printf("Running with HTTPS proxy %s (env: HTTPS_PROXY)", httpsProxy)
			}
		}

		log.Printf("[DEBUG] Running grab of assets due to them not existing")
		runLoadCollections(ctx, topClient)

		returnAssets, err = GetOpenseaAssets(ctx, collectionName)
		if err != nil {
			log.Printf("[WARNING] Failed getting collection %s (2): %s", collectionName, err)
			resp.WriteHeader(401)
			resp.Write([]byte(`{"success": false, "reason": "Failed to get collection key (2). Does it exist?"}`))
			return
		}
	}

	//for _, asset := range assets {
	//	log.Printf("Got assets: %#v", asset)
	//}

	//log.Printf("[DEBUG] Assets: %d", len(returnAssets))
	b, err := json.Marshal(returnAssets)
	if err != nil {
		log.Printf("[WARNING] Failed to GET collection %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false, "reason": "Failed to parse value. Try again."}`))
		return
	}

	resp.WriteHeader(200)
	resp.Write(b)
}

func ValidateOwnership(resp http.ResponseWriter, request *http.Request) {
	cors := HandleCors(resp, request)
	if cors {
		return
	}

	// Just here to verify that the user is logged in
	_, err := HandleApiAuthentication(resp, request)
	if err != nil {
		log.Printf("[WARNING] Api authentication failed load collections: %s", err)
		resp.WriteHeader(401)
		resp.Write([]byte(`{"success": false}`))
		return
	}

	// Check owner based on address?
}
