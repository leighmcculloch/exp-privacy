package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

type Circuit struct {
	X frontend.Variable `gnark:"x,public"`
	Y frontend.Variable `gnark:"y"`
	Z frontend.Variable `gnark:"z,public"`
}

func (c *Circuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	cs.AssertIsLessOrEqual(c.X, c.Y)
	cs.AssertIsLessOrEqual(c.Y, c.Z)
	return nil
}

func main() {
	err := root(os.Args[1:])
	if err != nil {
		fmt.Println("error:", err)
	}
}

func root(args []string) error {
	f := flag.NewFlagSet("zkp", flag.ContinueOnError)
	f.Bool("h", false, "")
	err := f.Parse(args)
	if err != nil {
		return err
	}
	args = f.Args()
	if len(args) == 0 {
		f.Usage()
		return nil
	}

	cmd := args[0]
	cmdArgs := args[1:]
	switch {
	case strings.HasPrefix("prove", cmd):
		err = prove(cmdArgs)
	case strings.HasPrefix("verify", cmd):
		err = verify(cmdArgs)
	}
	return err
}

func prove(args []string) error {
	f := flag.NewFlagSet("zkp prove", flag.ContinueOnError)
	f.Bool("h", false, "")
	var x, y, z int
	f.IntVar(&x, "x", 0, "x")
	f.IntVar(&y, "y", 0, "y")
	f.IntVar(&z, "z", 0, "z")
	err := f.Parse(args)
	if err != nil {
		return err
	}

	var c Circuit
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &c)
	if err != nil {
		return err
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		return err
	}

	fmt.Print("VK: ")
	vkOut := base64.NewEncoder(base64.StdEncoding, os.Stdout)
	vk.WriteTo(vkOut)
	vkOut.Close()
	fmt.Println()

	var solution Circuit
	solution.X.Assign(x)
	solution.Y.Assign(y)
	solution.Z.Assign(z)

	proof, err := groth16.Prove(r1cs, pk, &solution)
	if err != nil {
		return err
	}
	fmt.Print("Proof: ")
	proofOut := base64.NewEncoder(base64.StdEncoding, os.Stdout)
	proof.WriteTo(proofOut)
	proofOut.Close()
	fmt.Println()

	return nil
}

func verify(args []string) error {
	f := flag.NewFlagSet("zkp verify", flag.ContinueOnError)
	f.Bool("h", false, "")
	var proofStr, vkStr string
	var x, y, z int
	f.IntVar(&x, "x", 0, "x")
	f.IntVar(&y, "y", 0, "y")
	f.IntVar(&z, "z", 0, "z")
	f.StringVar(&proofStr, "proof", "", "")
	f.StringVar(&vkStr, "vk", "", "")
	err := f.Parse(args)
	if err != nil {
		return err
	}
	if proofStr == "" || vkStr == "" {
		f.Usage()
		return nil
	}

	proof := groth16.NewProof(ecc.BN254)
	_, err = proof.ReadFrom(base64.NewDecoder(base64.StdEncoding, strings.NewReader(proofStr)))
	if err != nil {
		return fmt.Errorf("reading proof: %w", err)
	}

	vk := groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(base64.NewDecoder(base64.StdEncoding, strings.NewReader(vkStr)))
	if err != nil {
		return fmt.Errorf("reading verification key: %w", err)
	}

	var solution Circuit
	solution.X.Assign(x)
	if y != 0 {
		solution.Y.Assign(y)
	}
	solution.Z.Assign(z)

	err = groth16.Verify(proof, vk, &solution)
	if err != nil {
		return fmt.Errorf("verifying: %w", err)
	}
	fmt.Println("Verified")

	return nil
}
