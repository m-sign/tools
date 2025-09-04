package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/m-sign/msign"
	"github.com/spf13/cobra"
)

var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "Key operations",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Usage()
	},
}

var keyNewCmd = &cobra.Command{
	Use:          "generate",
	Short:        "Generate new key pair",
	Long:         ``,
	SilenceUsage: true,
	Args: func(cmd *cobra.Command, args []string) error {
		if privateFile != "" && publicFile != "" {
			if privateFile == publicFile {
				return errors.New("private and public key files must be different")
			}
		}
		if privateFile != "" {
			_, err := os.Stat(privateFile)
			if err == nil {
				return errors.New(privateFile + " already exists - use another file name or remove the existing file.")
			}
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return err // unexpected error
			}
		}
		if publicFile != "" {
			_, err := os.Stat(publicFile)
			if err == nil {
				return errors.New(publicFile + " already exists - use another file name or remove the existing file.")
			}
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return err // unexpected error
			}
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Generating new key pair")

		outputPrivate := os.Stdout
		outputPublic := os.Stdout

		if privateFile != "" {
			prFile, err := os.OpenFile(privateFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
			if err != nil {
				return err
			}
			outputPrivate = prFile
			fmt.Println("Private key file:", privateFile)
		}

		if publicFile != "" {
			prFile, err := os.OpenFile(publicFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
			if err != nil {
				return err
			}
			outputPublic = prFile
			fmt.Println("Public key file:", publicFile)
		}

		priv, pub, err := msign.NewPrivateKey()

		if err == nil {
			fmt.Println("KeyId:", priv.Id())
			if err = msign.Export(outputPrivate, priv); err != nil {
				os.Remove(privateFile)
				os.Remove(publicFile)
				return err
			}
			if err = msign.Export(outputPublic, pub); err != nil {
				os.Remove(privateFile)
				os.Remove(publicFile)
				return err
			}
		}

		if outputPrivate != os.Stdout {
			outputPrivate.Close()
			if err == nil {
				fmt.Println("Private key saved to file:", privateFile)
			}
		}

		if outputPublic != os.Stdout {
			outputPublic.Close()
			if err == nil {
				fmt.Println("Public key saved to file:", publicFile)
			}
		}

		return err
	},
}

var keyPublicCmd = &cobra.Command{
	Use:          "public",
	Short:        "Get public key from private key",
	Long:         ``,
	SilenceUsage: true,
    Args: func(cmd *cobra.Command, args []string) error {
        if privateFile == "" && os.Getenv(msign_Env_Private) == "" {
            return fmt.Errorf("MSIGN_PRIVATE environment variable or --private option is required")
        }

		if len(args) > 0 {
			return fmt.Errorf("no arguments are allowed")
		}

		if privateFile != "" {
			if _, err := os.Stat(privateFile); os.IsNotExist(err) {
				return fmt.Errorf("file %s does not exist", privateFile)
			}
		}

		if publicFile != "" {
			_, err := os.Stat(publicFile)
			if err == nil {
				err := errors.New(publicFile + " already exists - use another file name or remove the existing file.")
				return err
			}
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return err // unexpected error
			}
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		var pkReader io.Reader
		outputPublic := os.Stdout

		if privateFile != "" {
			prFile, err := os.Open(privateFile)
			if err != nil {
				return err
			}
			pkReader = prFile
			defer prFile.Close()
		} else {
			privKey := os.Getenv(msign_Env_Private)
			privKey += "\n"
			pkReader = strings.NewReader(privKey)
		}

		priv, err := msign.ImportPrivateKey(pkReader)

		if err != nil {
			return err
		}

		pub := priv.Public()

		if publicFile != "" {
			prFile, err := os.OpenFile(publicFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
			if err != nil {
				return err
			}
			outputPublic = prFile
		}

		err = msign.Export(outputPublic, pub)

		if outputPublic != os.Stdout {
			outputPublic.Close()
			if err == nil {
				fmt.Println("Public key saved to file:", publicFile)
			}
		}

		return err
	},
}

var keyIdCmd = &cobra.Command{
	Use:          "id",
	Short:        "Show key ID",
	Long:         ``,
	SilenceUsage: true,
    Args: func(cmd *cobra.Command, args []string) error {
        if privateFile == "" && os.Getenv(msign_Env_Private) == "" && publicFile == "" && os.Getenv(msign_Env_Public) == "" {
            return fmt.Errorf("MSIGN_PRIVATE or MSIGN_PUBLIC environment variable or --private or --public option is required")
        }

		if len(args) > 0 {
			return fmt.Errorf("no arguments are allowed")
		}

		if privateFile != "" {
			if _, err := os.Stat(privateFile); os.IsNotExist(err) {
				return fmt.Errorf("file %s does not exist", privateFile)
			}
		}

        if publicFile != "" {
            if _, err := os.Stat(publicFile); os.IsNotExist(err) {
                return fmt.Errorf("file %s does not exist", publicFile)
            }
        }

		return nil
	},

	RunE: func(cmd *cobra.Command, args []string) error {
		var privReader, pubReader io.Reader

		if privateFile != "" {
			prFile, err := os.Open(privateFile)
			if err != nil {
				return err
			}
			privReader = prFile
			defer prFile.Close()
		} else {
			privKey := os.Getenv(msign_Env_Private)
			if privKey != "" {
				privKey += "\n"
				privReader = strings.NewReader(privKey)
			}
		}

		if publicFile != "" {
			pbFile, err := os.Open(publicFile)
			if err != nil {
				return err
			}
			pubReader = pbFile
			defer pbFile.Close()
		} else {
			pubKey := os.Getenv(msign_Env_Public)
			if pubKey != "" {
				pubKey += "\n"
				pubReader = strings.NewReader(pubKey)
			}
		}

		if privReader != nil {
			priv, err := msign.ImportPrivateKey(privReader)
			if err != nil {
				return err
			}
			fmt.Println("KeyId from private key:", priv.Id())
		}

		if pubReader != nil {
			pub, err := msign.ImportPublicKey(pubReader)
			if err != nil {
				return err
			}
			fmt.Println("KeyId from public key:", pub.Id())
		}
		return nil
	},
}

var (
	keyFile string
)

func init() {
	keyNewCmd.Flags().StringVarP(&privateFile, "private", "", "", "save private key to file (default: print to stdout)")
	keyNewCmd.Flags().StringVarP(&publicFile, "public", "", "", "save public key to file (default: print to stdout)")
    keyIdCmd.Flags().StringVarP(&privateFile, "private", "", "", "get private key from file (default: environment variable MSIGN_PRIVATE)")
    keyIdCmd.Flags().StringVarP(&publicFile, "public", "", "", "get public key from file (default: environment variable MSIGN_PUBLIC)")
    keyPublicCmd.Flags().StringVarP(&privateFile, "private", "", "", "get private key from file (default: environment variable MSIGN_PRIVATE)")
    keyPublicCmd.Flags().StringVarP(&publicFile, "public", "", "", "save public key to file (default: print to stdout)")

	keyCmd.AddCommand(keyNewCmd)
	keyCmd.AddCommand(keyPublicCmd)
	keyCmd.AddCommand(keyIdCmd)
	rootCmd.AddCommand(keyCmd)
}
