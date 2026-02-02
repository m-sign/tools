package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/m-sign/msign"
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:          "verify [list of files]",
	Short:        "Verify files' signatures",
	SilenceUsage: true,
	Long:         ``,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("requires at least one file")
		}

		if publicFile == "" && os.Getenv(msign_Env_Public) == "" {
			return fmt.Errorf("MSIGN_PUBLIC environment variable or --public option is required")
		}

		if publicFile != "" {
			if _, err := os.Stat(publicFile); os.IsNotExist(err) {
				return fmt.Errorf("file %s does not exist", publicFile)
			}
		}

		for _, arg := range args {
			if _, err := os.Stat(arg); os.IsNotExist(err) {
				return fmt.Errorf("file %s does not exist", arg)
			}

			if _, err := os.Stat(arg + ".msign"); os.IsNotExist(err) {
				return fmt.Errorf("file %s.msign does not exist", arg)
			}
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		var pkReader io.Reader

		if publicFile != "" {
			prFile, err := os.Open(publicFile)
			if err != nil {
				return err
			}
			pkReader = prFile
			defer prFile.Close()
		} else {
			pubKey := os.Getenv(msign_Env_Public)
			pubKey += "\n"
			pkReader = strings.NewReader(pubKey)
		}

		pub, err := msign.ImportPublicKey(pkReader)
		if err != nil {
			return err
		}

		cmd.SilenceUsage = true

		var returnErr error

		for _, arg := range args {
			verified, err := verifyFile(pub, arg)
			if err != nil {
				return err
			}
			if !verified {
				returnErr = fmt.Errorf("verification failed for one or more files")
			}
		}

		return returnErr
	},
}

func init() {
	verifyCmd.Flags().StringVarP(&publicFile, "public", "", "", "read public key from file (default: get public key from environment variable MSIGN_PUBLIC)")
	rootCmd.AddCommand(verifyCmd)
}

func verifyFile(pub msign.PublicKey, arg string) (bool, error) {
	fmt.Print("Verifying ", arg, " : ")

	sigFile, err := os.Open(arg + ".msign")
	if err != nil {
		return false, err
	}
	defer sigFile.Close()

	sign, err := msign.ImportSignature(sigFile)
	if err != nil {
		return false, err
	}

	inFile, err := os.Open(arg)
	if err != nil {
		return false, err
	}
	defer inFile.Close()

	verified, err := pub.Verify(inFile, sign)
	if err != nil {
		return false, err
	}

	if verified {
		fmt.Println("OK")
	} else {
		fmt.Println("FAILED")
	}
	return verified, nil
}
