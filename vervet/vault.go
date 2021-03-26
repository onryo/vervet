package vervet

import (
	"fmt"
	"net/url"

	"github.com/hashicorp/vault/api"
)

// connect to Vault server and execute unseal operation
func UnsealVault(vaultAddr string, unsealKey string) error {
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

	PrintSealStatus(vaultURL, sealStatusRsp)

	return nil
}

func PrintSealStatus(url *url.URL, resp *api.SealStatusResponse) {
	fmt.Printf("Vault server: %s\n", url.Host)

	status := "unsealed"
	if resp.Sealed {
		status = "sealed"
	} else {
		fmt.Printf("Cluster name: %s\n", resp.ClusterName)
		fmt.Printf("Cluster ID: %s\n", resp.ClusterID)
	}

	if resp.Initialized {
		fmt.Printf("Seal Status: %s\n", status)
		fmt.Printf("Key Threshold/Shares: %d/%d\n", resp.T, resp.N)
		fmt.Printf("Progress: %d/%d\n", resp.Progress, resp.T)
		fmt.Printf("Version: %s\n", resp.Version)

	} else {
		fmt.Println("Vault server is not initialized.")
	}
}
