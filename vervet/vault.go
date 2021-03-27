package vervet

import (
	"fmt"
	"net/url"

	"github.com/hashicorp/vault/api"
)

// connect to Vault server and execute unseal operation
func vaultUnseal(vaultAddr string, unsealKey string) error {
	vaultURL, err := url.Parse(vaultAddr)
	if err != nil {
		return err
	}

	config := &api.Config{
		Address: vaultAddr,
	}
	client, err := api.NewClient(config)
	if err != nil {
		return err
	}

	sealStatusRsp, err := client.Sys().Unseal(unsealKey)
	if err != nil {
		return err
	}

	fmt.Printf("Vault server: %s\n", vaultURL.Host)
	vaultPrintSealStatus(sealStatusRsp)

	return nil
}

// connect to Vault server and execute unseal operation
func vaultGenerateRoot(vaultAddr string, unsealKey string, nonce string) error {
	vaultURL, err := url.Parse(vaultAddr)
	if err != nil {
		return err
	}

	config := &api.Config{
		Address: vaultAddr,
	}
	client, err := api.NewClient(config)
	if err != nil {
		return err
	}

	genRootStatusRsp, err := client.Sys().GenerateRootUpdate(unsealKey, nonce)
	if err != nil {
		return err
	}

	fmt.Printf("Vault server: %s\n", vaultURL.Host)
	vaultPrintGenRootStatus(genRootStatusRsp)

	return nil
}

func vaultPrintSealStatus(resp *api.SealStatusResponse) {
	status := "unsealed"
	if resp.Sealed {
		status = "sealed"
	} else {
		fmt.Printf("Cluster name: %s\n", resp.ClusterName)
		fmt.Printf("Cluster ID: %s\n", resp.ClusterID)
	}

	if resp.Initialized {
		fmt.Printf("Seal status: %s\n", status)
		fmt.Printf("Key threshold/shares: %d/%d\n", resp.T, resp.N)
		fmt.Printf("Progress: %d/%d\n", resp.Progress, resp.T)
		fmt.Printf("Version: %s\n", resp.Version)

	} else {
		fmt.Println("Vault server is not initialized.")
	}
}

func vaultPrintGenRootStatus(resp *api.GenerateRootStatusResponse) {
	status := "not started"
	if resp.Started {
		status = "started"

		if resp.Complete {
			status = "complete"
		}
	}

	fmt.Printf("Root generation: %s\n", status)
	fmt.Printf("Nonce: %s\n", resp.Nonce)
	fmt.Printf("Progress: %d/%d\n", resp.Progress, resp.Required)
	fmt.Printf("PGP fingerprint: %s\n", resp.PGPFingerprint)

	if resp.EncodedRootToken != "" {
		fmt.Printf("Encoded root token: %s\n", resp.EncodedRootToken)
	}
}
