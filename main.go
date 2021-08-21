package main

import (
	"fmt"
	"log"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

type Circuit struct {
	X frontend.Variable `gnark:"x"`
	Z frontend.Variable `gnark:"z"`
	Y frontend.Variable `gnark:",public"`
}

func (c *Circuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	// x**2 + x + 5 == y
	// x3 := cs.Mul(c.X, c.X)
	z := cs.Mul(c.X, c.Z)
	y := cs.Mul(z, 5)
	cs.AssertIsEqual(c.Y, y)
	return nil
}

func main() {
	var c Circuit

	// compiles our circuit into a R1CS
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &c)
	if err != nil {
		log.Fatal(err)
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("PK:", pk)
	fmt.Println("VK:", vk)

	var solution Circuit
	solution.X.Assign(3)
	solution.Z.Assign(2)
	solution.Y.Assign(30)

	proof, err := groth16.Prove(r1cs, pk, &solution)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Proof:", proof)

	err = groth16.Verify(proof, vk, &solution)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Verified")
}
