package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/m-sign/msign"
	"github.com/spf13/cobra"
)

var signCmd = &cobra.Command{
	Use:          "sign [list of files]",
	Short:        "Sign file(s)",
	SilenceUsage: true,
	Long:         ``,
    Args: func(cmd *cobra.Command, args []string) error {
        if len(args) < 1 {
            return fmt.Errorf("requires at least one file")
        }

        if privateFile == "" && os.Getenv(msign_Env_Private) == "" {
            return fmt.Errorf("MSIGN_PRIVATE environment variable or --private option is required")
        }

		if privateFile != "" {
			if _, err := os.Stat(privateFile); os.IsNotExist(err) {
				return fmt.Errorf("file %s does not exist", privateFile)
			}
		}

        for _, arg := range args {
            if _, err := os.Stat(arg); os.IsNotExist(err) {
                return fmt.Errorf("file %s does not exist", arg)
            }

			if signToFile && !forceOverwrite {
				if _, err := os.Stat(arg + ".msign"); err == nil {
					return fmt.Errorf("file %s.msign already exists", arg)
				}
			}
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		var pkReader io.Reader

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

        for _, arg := range args {
            inFile, err := os.Open(arg)
            if err != nil {
                return err
            }
            defer inFile.Close()

			sign, err := priv.Sign(inFile)
			if err != nil {
				return err
			}

            output := os.Stdout
            if signToFile {
                outFile, err := os.Create(arg + ".msign")
                if err != nil {
                    return err
                }
                defer outFile.Close()
                output = outFile
            }

            if !signToFile {
                fmt.Print("Signature for ", arg, ": ")
            }
            err = msign.Export(output, sign)
            if err != nil {
                return err
            }
            if output != os.Stdout {
                fmt.Println("saved to", arg+".msign")
            }
        }
        return err
    },
}

func init() {
	signCmd.Flags().StringVarP(&privateFile, "private", "", "", "read private key from file (default: get private key from environment variable MSIGN_PRIVATE)")
	signCmd.Flags().BoolVarP(&signToFile, "to-file", "f", false, "save signature to file (default: print message with signature to console)")
	signCmd.Flags().BoolVarP(&forceOverwrite, "force", "", false, "force overwrite signature file (default: msign will not overwrite existing signature file)")
	rootCmd.AddCommand(signCmd)
}
