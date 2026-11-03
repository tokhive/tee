// tee-policy-info reads the exact canonical policy bytes shipped in a bundle.
// Its hash is computed by the same policy implementation used in receipts.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/tokhive/tee/internal/canonical"
	"github.com/tokhive/tee/policy"
)

type policyInfo struct {
	Hash       string `json:"policy_hash"`
	FileSHA256 string `json:"policy_file_sha256"`
}

func inspect(raw []byte) (policyInfo, error) {
	var p policy.Policy
	if err := canonical.Unmarshal(raw, &p); err != nil {
		return policyInfo{}, err
	}
	if err := p.Validate(); err != nil {
		return policyInfo{}, err
	}
	hash, err := p.Hash()
	if err != nil {
		return policyInfo{}, err
	}
	fileHash := sha256.Sum256(raw)
	return policyInfo{hex.EncodeToString(hash[:]), hex.EncodeToString(fileHash[:])}, nil
}

func run(args []string, in io.Reader, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("tee-policy-info", flag.ContinueOnError)
	flags.SetOutput(errOut)
	emit := flags.Bool("emit-default", false, "write the default canonical-CBOR policy to stdout")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *emit && flags.NArg() == 0 {
		p, err := policy.Default()
		if err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
		raw, err := p.EncodeCanonical()
		if err == nil {
			_, err = out.Write(raw)
		}
		if err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
		return 0
	}
	if *emit || flags.NArg() != 1 {
		fmt.Fprintln(errOut, "usage: tee-policy-info POLICY.cbor | - | --emit-default")
		return 2
	}
	if flags.Arg(0) != "-" {
		file, err := os.Open(flags.Arg(0))
		if err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
		defer file.Close()
		in = file
	}
	raw, err := io.ReadAll(io.LimitReader(in, (2<<20)+1))
	if err == nil && len(raw) > 2<<20 {
		err = fmt.Errorf("policy exceeds the 2 MiB limit")
	}
	var info policyInfo
	if err == nil {
		info, err = inspect(raw)
	}
	if err == nil {
		err = json.NewEncoder(out).Encode(info)
	}
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	return 0
}

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }
