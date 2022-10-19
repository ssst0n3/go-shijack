package main

import "github.com/ssst0n3/gohijack"

func main() {
	gohijack.Run("169.254.169.254:80", "0.0.0.0:0", 0, 0, false)
}
