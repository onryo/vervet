package vervet

import (
	"fmt"
	"net/url"

	"github.com/hashicorp/vault/api"
)

type vaultClient struct {
	apiClient *api.Client
	host      string
	tls       bool
}

func newVaultClient(addr string) (*vaultClient, error) {
	vault := new(vaultClient)

	config := &api.Config{
		Address: addr,
	}

	api, err := api.NewClient(config)
	if err != nil {
		return vault, err
	}

	url, err := url.Parse(addr)
	if err != nil {
		return vault, err
	}

	vault.apiClient = api
	vault.host = url.Host

	vault.tls = true
	if url.Scheme == "http" {
		vault.tls = false
	}

	return vault, nil
}

// connect to Vault server and execute unseal operation
func (vault *vaultClient) unseal(unsealKey string) (*api.SealStatusResponse, error) {
	resp, err := vault.apiClient.Sys().SealStatus()
	if err != nil {
		return nil, err
	}

	if !resp.Sealed {
		msg := fmt.Sprintf("%s - already unsealed, skipping unseal operation", vault.host)
		PrintSuccess(msg)
		return resp, nil
	}

	resp, err = vault.apiClient.Sys().Unseal(unsealKey)
	if err != nil {
		return nil, err
	}

	msg := fmt.Sprintf("%s - successfully provided unseal key share, remaining: %d of %d",
		vault.host, resp.Progress, resp.T)
	PrintSuccess(msg)

	return resp, nil
}

// connect to Vault server and execute unseal operation
func (vault *vaultClient) generateRoot(unsealKey string, nonce string) error {
	_, err := vault.apiClient.Sys().GenerateRootUpdate(unsealKey, nonce)
	if err != nil {
		return err
	}

	fmt.Printf("Vault server: %s\n", vault.host)
	vault.printGenRootStatus()

	return nil
}

func (vault *vaultClient) printSealStatus() {
	resp, err := vault.apiClient.Sys().SealStatus()
	if err == nil {
		fmt.Printf("\n===== Vault cluster details =====\n")

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
}

func (vault *vaultClient) printGenRootStatus() {
	resp, err := vault.apiClient.Sys().GenerateRootStatus()
	if err == nil {
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
}
